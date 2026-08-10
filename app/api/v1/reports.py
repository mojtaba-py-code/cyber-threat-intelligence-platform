"""Report and sharing export endpoints (JSON / CSV / Markdown / STIX 2.1 / MISP)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from app.api.deps import get_ioc_service, require
from app.core.exceptions import ValidationError
from app.ioc.types import IOCType, ThreatLevel
from app.security.rbac import Permission
from app.services.ioc_service import IOCService
from app.services.report_service import ReportService

router = APIRouter()

IOCDep = Annotated[IOCService, Depends(get_ioc_service)]


@router.get(
    "/iocs.{fmt}",
    dependencies=[Depends(require(Permission.report_generate))],
    response_class=PlainTextResponse,
    summary="Export indicators as json | csv | md | stix | misp (same filters as search)",
)
async def export_iocs(
    fmt: str,
    service: IOCDep,
    ioc_type: IOCType | None = None,
    threat_level: ThreatLevel | None = None,
    source: str | None = None,
    min_score: int | None = Query(default=None, ge=0, le=100),
    q: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=500, ge=1, le=5000),
) -> PlainTextResponse:
    iocs = await service.list_for_report(
        ioc_type=ioc_type.value if ioc_type else None,
        threat_level=threat_level.value if threat_level else None,
        source=source,
        min_score=min_score,
        query=q,
        limit=limit,
    )
    if fmt == "json":
        return PlainTextResponse(ReportService.to_json(iocs), media_type="application/json")
    if fmt == "csv":
        return PlainTextResponse(
            ReportService.to_csv(iocs),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=iocs.csv"},
        )
    if fmt in ("md", "markdown"):
        return PlainTextResponse(ReportService.to_markdown(iocs), media_type="text/markdown")
    if fmt == "stix":
        return PlainTextResponse(
            ReportService.to_stix(iocs),
            # The media type registered for STIX 2.1 content.
            media_type="application/stix+json;version=2.1",
            headers={"Content-Disposition": "attachment; filename=bundle.stix.json"},
        )
    if fmt == "misp":
        return PlainTextResponse(
            ReportService.to_misp(iocs),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=misp-event.json"},
        )
    raise ValidationError(f"Unsupported report format: {fmt}")
