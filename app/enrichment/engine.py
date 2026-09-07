"""Enrichment engine: runs applicable enrichers for an indicator and merges.

Also derives :class:`~app.scoring.engine.ScoreSignals` from the enrichment plus
the indicator's own metadata, so scoring is driven by real, structured inputs.
"""

from __future__ import annotations

import functools

from app.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.ssrf import SSRFGuard
from app.enrichment.enrichers import DNSEnricher, GeoIPEnricher, ReputationEnricher
from app.ioc.indicators import extract_host
from app.ioc.types import HASH_TYPES, IOCType
from app.scoring.engine import (
    ScoreSignals,
    detection_ratio,
    geo_risk_score,
    port_risk_score,
    source_reputation_score,
)

# Feeds treated as independently reputable for corroboration scoring.
_REPUTABLE_SOURCES = frozenset(
    {"abuseipdb", "urlhaus", "malwarebazaar", "otx", "cisa_kev", "virustotal"}
)

log = get_logger(__name__)


class EnrichmentEngine:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._geoip = GeoIPEnricher(self._settings)
        self._dns = DNSEnricher(self._settings)
        self._reputation = ReputationEnricher(self._settings)
        self._ssrf = SSRFGuard(self._settings.outbound_allowed_hosts)

    async def enrich(self, *, ioc_type: IOCType, value: str) -> dict:
        """Return a merged enrichment payload for an indicator."""
        result: dict = {}
        host = extract_host(value, ioc_type)
        if host is None and ioc_type in HASH_TYPES:
            # Hashes have no network facet; reputation only.
            result.update(await self._reputation.enrich(value))
            return result
        if host is None:
            return result
        # The host comes from a submitted indicator, so an operator who has
        # narrowed OUTBOUND_ALLOWED_HOSTS must have that honoured here too, not
        # only on webhook delivery. Offline facets stay available either way.
        enrichers: tuple = (self._geoip, self._reputation)
        if self._ssrf.host_allowed(host):
            enrichers = (self._geoip, self._dns, self._reputation)
        else:
            log.info("enrichment_host_not_allowed", host=host)
            result["dns"] = {"resolved": [], "source": "live", "blocked": True}
        for enricher in enrichers:
            result.update(await enricher.enrich(host))
        return result

    def signals_from(
        self,
        *,
        enrichment: dict,
        source: str,
        sightings: int = 1,
        age_days: float = 0.0,
        open_ports: list[int] | None = None,
        confidence: float = 0.5,
        blacklisted: bool = False,
    ) -> ScoreSignals:
        """Build scoring signals from enrichment + IOC metadata."""
        rep = enrichment.get("reputation", {})
        geo = enrichment.get("geoip", {})
        det_ratio = (
            detection_ratio(int(rep.get("detected", 0)), int(rep.get("total", 0))) if rep else 0.0
        )
        reputable = 1 + (1 if source in _REPUTABLE_SOURCES else 0)
        from app.scoring.engine import frequency_score, recency_score

        return ScoreSignals(
            source_reputation=source_reputation_score(reputable),
            detection_ratio=det_ratio,
            blacklist_presence=1.0 if blacklisted else 0.0,
            confidence=confidence,
            recency=recency_score(age_days),
            frequency=frequency_score(sightings),
            geo_risk=geo_risk_score(geo.get("country")),
            port_risk=port_risk_score(open_ports),
            historical_activity=min(1.0, sightings / 50),
        )


@functools.lru_cache(maxsize=1)
def get_enrichment_engine() -> EnrichmentEngine:
    return EnrichmentEngine()
