"""IOC lifecycle: classify → enrich → score → store → correlate."""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from app.collectors.base import CollectedIndicator
from app.core.logging import get_logger
from app.correlation.graph import make_ref
from app.enrichment.engine import EnrichmentEngine
from app.ioc.extract import extract_indicators
from app.ioc.indicators import classify_indicator, defang, extract_host
from app.ioc.types import Confidence, IOCType, Severity
from app.models.ioc import IOC
from app.repositories.audit_repository import AuditRepository
from app.repositories.correlation_repository import CorrelationRepository
from app.repositories.enrichment_repository import EnrichmentRepository
from app.repositories.ioc_repository import IOCRepository
from app.scoring.engine import compute_threat_score

if TYPE_CHECKING:
    from app.services.alert_service import AlertService

log = get_logger(__name__)

_CONFIDENCE_FLOAT = {
    Confidence.unknown: 0.2,
    Confidence.low: 0.4,
    Confidence.medium: 0.6,
    Confidence.high: 0.8,
    Confidence.confirmed: 1.0,
}
_REPUTABLE = frozenset({"abuseipdb", "urlhaus", "malwarebazaar", "otx", "cisa_kev", "virustotal"})


def _ref_type_for_host(host: str) -> str:
    """Return the IOCType value for a host string (IPv4/IPv6/domain)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return IOCType.domain.value
    return IOCType.ipv6.value if ip.version == 6 else IOCType.ipv4.value


class IOCService:
    def __init__(
        self,
        *,
        iocs: IOCRepository,
        enrichments: EnrichmentRepository,
        engine: EnrichmentEngine,
        audit: AuditRepository,
        correlation: CorrelationRepository,
        alerts: AlertService | None = None,
    ) -> None:
        self._iocs = iocs
        self._enrichments = enrichments
        self._engine = engine
        self._audit = audit
        self._correlation = correlation
        self._alerts = alerts

    async def upsert(
        self,
        *,
        raw_value: str,
        source: str = "manual",
        confidence: Confidence = Confidence.medium,
        severity: Severity = Severity.medium,
        tags: list[str] | None = None,
        references: list[str] | None = None,
        description: str | None = None,
        do_enrich: bool = True,
        user_id: str | None = None,
    ) -> IOC:
        parsed = classify_indicator(raw_value)  # raises on unknown indicator
        enrichment = (
            await self._engine.enrich(ioc_type=parsed.type, value=parsed.value) if do_enrich else {}
        )
        now = datetime.now(UTC)

        # Fetch first so age/sightings feed the recency & frequency signals.
        ioc = await self._iocs.get_by_type_value(parsed.type.value, parsed.value)
        sightings = (ioc.sightings + 1) if ioc is not None else 1
        age_days = 0.0
        if ioc is not None and ioc.first_seen is not None:
            first_seen = ioc.first_seen
            # SQLite returns naive datetimes; treat stored timestamps as UTC.
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=UTC)
            age_days = max(0.0, (now - first_seen).total_seconds() / 86400)
        signals = self._engine.signals_from(
            enrichment=enrichment,
            source=source,
            confidence=_CONFIDENCE_FLOAT.get(confidence, 0.6),
            blacklisted=source in _REPUTABLE,
            sightings=sightings,
            age_days=age_days,
        )
        score = compute_threat_score(signals)

        if ioc is None:
            ioc = IOC(
                type=parsed.type.value,
                value=parsed.value,
                defanged_value=defang(parsed.value),
                source=source,
                confidence=confidence.value,
                severity=severity.value,
                threat_score=score.score,
                threat_level=score.level.value,
                sightings=sightings,
                tags=sorted(set(tags or [])),
                references=list(references or []),
                description=description,
                first_seen=now,
                last_seen=now,
            )
            await self._iocs.add(ioc)
            action = "ioc.create"
        else:
            ioc.threat_score = score.score
            ioc.threat_level = score.level.value
            ioc.sightings = sightings
            ioc.last_seen = now
            ioc.tags = sorted(set(ioc.tags) | set(tags or []))
            if description and not ioc.description:
                ioc.description = description
            if references:
                ioc.references = sorted(set(ioc.references) | set(references))
            action = "ioc.update"

        # Always persist the engine record so the score is explainable via API.
        engine_payload = dict(enrichment)
        engine_payload["score"] = {
            "score": score.score,
            "level": score.level.value,
            "contributions": score.contributions,
        }
        await self._enrichments.upsert(ioc.id, "engine", engine_payload)
        await self._auto_correlate(parsed.type, parsed.value, enrichment, source)
        await self._audit.record(
            action=action,
            user_id=user_id,
            detail={"type": parsed.type.value, "score": score.score, "source": source},
        )
        # Evaluate alert rules against the freshly scored indicator.
        if self._alerts is not None:
            await self._alerts.evaluate_ioc(ioc)
        return ioc

    async def _auto_correlate(
        self, ioc_type: IOCType, value: str, enrichment: dict, source: str
    ) -> None:
        """Derive obvious relationships from a new indicator."""
        self_ref = make_ref(ioc_type.value, value)
        if ioc_type is IOCType.url:
            host = extract_host(value, ioc_type)
            if host:
                # A URL host may be a domain or a literal IP — classify it so the
                # edge points at the same node an IP/domain IOC would create.
                target_type = _ref_type_for_host(host)
                await self._correlation.upsert_edge(
                    source_ref=self_ref,
                    target_ref=make_ref(target_type, host),
                    relationship="communicates-with",
                    confidence=0.9,
                    source=source,
                )
        resolved = (enrichment.get("dns") or {}).get("resolved") or []
        for ip in resolved:
            await self._correlation.upsert_edge(
                source_ref=self_ref,
                target_ref=make_ref(_ref_type_for_host(ip), ip),
                relationship="resolves-to",
                confidence=0.8,
                source="dns",
            )

    async def ingest_from_collector(
        self, indicators: list[CollectedIndicator], *, do_enrich: bool = True
    ) -> dict:
        """Upsert a batch of collected indicators; return a small summary.

        Each indicator runs inside a SAVEPOINT so that a single failing row (e.g.
        a race on the unique constraint) rolls back only itself, leaving the
        session usable for the rest of the batch.
        """
        created = 0
        skipped = 0
        session = self._iocs.session
        for ind in indicators:
            try:
                async with session.begin_nested():
                    await self.upsert(
                        raw_value=ind.value,
                        source=ind.source,
                        confidence=ind.confidence,
                        severity=ind.severity,
                        tags=list(ind.tags),
                        references=list(ind.references),
                        description=ind.description,
                        do_enrich=do_enrich,
                    )
                created += 1
            except Exception as exc:  # noqa: BLE001 - one bad indicator must not abort the batch
                log.info("ingest_skip", value=ind.value, error=str(exc))
                skipped += 1
        return {"ingested": created, "skipped": skipped}

    async def bulk_import(
        self,
        *,
        content: str,
        fmt: str = "auto",
        source: str = "import",
        confidence: Confidence = Confidence.low,
        severity: Severity = Severity.medium,
        tags: list[str] | None = None,
        do_enrich: bool = False,
        limit: int = 1000,
        user_id: str | None = None,
    ) -> dict:
        """Extract every indicator in a document and upsert them.

        Like :meth:`ingest_from_collector`, each indicator is wrapped in a
        SAVEPOINT so one bad row cannot poison the whole submission, and the
        per-item outcome is reported back to the analyst.
        """
        # Scanning a document is pure CPU work; keep it off the event loop or a
        # large submission stalls every other request served by this worker.
        values = await asyncio.to_thread(extract_indicators, content, fmt=fmt, limit=limit)
        session = self._iocs.session
        items: list[dict] = []
        imported = 0
        for value in values:
            try:
                async with session.begin_nested():
                    ioc = await self.upsert(
                        raw_value=value,
                        source=source,
                        confidence=confidence,
                        severity=severity,
                        tags=list(tags or []),
                        do_enrich=do_enrich,
                        user_id=user_id,
                    )
                items.append(
                    {
                        "value": ioc.defanged_value,
                        "type": ioc.type,
                        "status": "imported",
                        "threat_score": ioc.threat_score,
                    }
                )
                imported += 1
            except Exception as exc:  # noqa: BLE001 - report the row, keep going
                log.info("bulk_import_skip", value=value, error=str(exc))
                items.append({"value": value, "status": "failed", "error": str(exc)})
        return {
            "extracted": len(values),
            "imported": imported,
            "failed": len(values) - imported,
            "items": items,
        }

    @staticmethod
    async def preview_extraction(content: str, *, fmt: str = "auto") -> list[dict]:
        """Parse a document without storing anything (dry run)."""
        values = await asyncio.to_thread(extract_indicators, content, fmt=fmt)
        out: list[dict] = []
        for value in values:
            parsed = classify_indicator(value)
            out.append(
                {
                    "value": parsed.value,
                    "defanged_value": defang(parsed.value),
                    "type": parsed.type.value,
                }
            )
        return out

    async def get(self, ioc_id: str) -> IOC | None:
        return await self._iocs.get(ioc_id)

    async def enrichments_for(self, ioc_id: str) -> list:
        return await self._enrichments.list_for_ioc(ioc_id)

    async def explain(self, ioc_id: str) -> dict | None:
        """Return the stored score breakdown (contributions) for an IOC."""
        record = await self._enrichments.get(ioc_id, "engine")
        if record is None:
            return None
        return record.data.get("score")

    async def rerun_enrichment(self, ioc: IOC, *, user_id: str | None = None) -> IOC:
        """Re-run enrichment and rescoring for an existing indicator."""
        return await self.upsert(
            raw_value=ioc.value,
            source=ioc.source,
            confidence=Confidence(ioc.confidence),
            severity=Severity(ioc.severity),
            do_enrich=True,
            user_id=user_id,
        )

    async def lookup(self, raw_value: str) -> IOC | None:
        parsed = classify_indicator(raw_value)
        return await self._iocs.get_by_type_value(parsed.type.value, parsed.value)

    async def search(self, **kwargs) -> tuple[list[IOC], int]:
        page = kwargs.pop("page", 1)
        page_size = kwargs.pop("page_size", 50)
        offset = (page - 1) * page_size
        items = await self._iocs.search(limit=page_size, offset=offset, **kwargs)
        total = await self._iocs.count(**kwargs)
        return items, total

    async def list_for_report(
        self,
        *,
        ioc_type: str | None = None,
        threat_level: str | None = None,
        source: str | None = None,
        min_score: int | None = None,
        query: str | None = None,
        limit: int = 500,
    ) -> list[IOC]:
        """Fetch indicators for export, honouring the same filters as search."""
        return await self._iocs.search(
            ioc_type=ioc_type,
            threat_level=threat_level,
            source=source,
            min_score=min_score,
            status=None,
            query=query,
            limit=limit,
            offset=0,
        )
