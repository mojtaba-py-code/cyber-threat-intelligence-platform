"""Individual enrichers.

Each enricher augments an indicator with one facet (geo/ASN, DNS, reputation).
They are **offline-first**: without live collection enabled they return
deterministic, clearly-labelled heuristic data (``source: "offline-heuristic"``)
so the platform is fully demonstrable and testable without network or secrets.
Live implementations activate when the operator enables collectors.
"""

from __future__ import annotations

import hashlib
import ipaddress
from abc import ABC, abstractmethod

from app.config import Settings
from app.core.logging import get_logger
from app.core.ssrf import SSRFGuard

log = get_logger(__name__)

# A small, fixed table used purely to derive a *deterministic* demo geolocation
# offline. It is a heuristic, not real geolocation data.
_DEMO_GEOS = ("US", "RU", "CN", "DE", "NL", "IR", "BR", "IN", "KP", "GB")


class Enricher(ABC):
    name: str

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def live_enabled(self) -> bool:
        return self._settings.enable_live_collectors

    @abstractmethod
    async def enrich(self, host: str) -> dict:
        """Return a normalised enrichment fragment for ``host``."""


class GeoIPEnricher(Enricher):
    name = "geoip"

    async def enrich(self, host: str) -> dict:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return {}
        # Deterministic offline geolocation derived from the address bytes.
        digest = hashlib.sha256(ip.packed).digest()
        country = _DEMO_GEOS[digest[0] % len(_DEMO_GEOS)]
        asn = 64512 + (digest[1] << 8 | digest[2]) % 1000  # private ASN range
        return {
            "geoip": {
                "country": country,
                "asn": asn,
                "org": f"AS{asn} Demo Network",
                "source": "offline-heuristic",
            }
        }


class DNSEnricher(Enricher):
    """Resolves a host to its A records, live, through the SSRF guard.

    Resolution is the one enrichment facet that leaves the machine, so it is
    the one that has to respect ``OUTBOUND_ALLOWED_HOSTS`` and refuse to report
    private answers. The guard does both.
    """

    name = "dns"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._ssrf = SSRFGuard(settings.outbound_allowed_hosts)

    async def enrich(self, host: str) -> dict:
        # Offline: no resolution at all — nothing leaves the machine.
        if not self.live_enabled:
            return {"dns": {"resolved": [], "source": "offline-heuristic"}}
        # A policy refusal and a name that simply does not resolve are different
        # facts about the indicator, so they are reported as different fields.
        if not self._ssrf.host_allowed(host):
            log.info("dns_enrich_blocked", host=host)
            return {"dns": {"resolved": [], "source": "live", "blocked": True}}
        try:
            resolved = await self._ssrf.resolve_public(host)
        except Exception as exc:  # noqa: BLE001 - resolution failures are non-fatal
            log.info("dns_enrich_failed", host=host, error=str(exc))
            return {"dns": {"resolved": [], "source": "live", "error": True}}
        return {"dns": {"resolved": list(resolved), "source": "live"}}


class ReputationEnricher(Enricher):
    name = "reputation"

    async def enrich(self, host: str) -> dict:
        # A deterministic pseudo-reputation from the host, for offline demos.
        digest = hashlib.sha256(host.encode()).digest()
        detected = digest[0] % 70
        total = 70
        return {
            "reputation": {
                "detected": detected,
                "total": total,
                "ratio": round(detected / total, 3),
                "source": "offline-heuristic",
            }
        }
