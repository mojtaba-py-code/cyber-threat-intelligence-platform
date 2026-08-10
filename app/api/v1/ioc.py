"""IOC management endpoints: create, lookup, get, search, score explain."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentPrincipalDep, get_ioc_service, require
from app.core.exceptions import NotFoundError
from app.ioc.types import IOCType, ThreatLevel
from app.schemas.common import Page, PageMeta
from app.schemas.ioc import (
    BulkImportItem,
    BulkImportRequest,
    BulkImportResult,
    EnrichmentOut,
    ExtractedIndicator,
    ExtractRequest,
    ExtractResult,
    IOCCreate,
    IOCDetailOut,
    IOCOut,
    LookupRequest,
    ScoreExplainOut,
)
from app.security.rbac import Permission
from app.services.ioc_service import IOCService

router = APIRouter()

IOCDep = Annotated[IOCService, Depends(get_ioc_service)]


@router.post(
    "",
    response_model=IOCDetailOut,
    dependencies=[Depends(require(Permission.ioc_write))],
    summary="Submit an indicator (classified, enriched, scored, stored)",
)
async def create_ioc(
    payload: IOCCreate, principal: CurrentPrincipalDep, service: IOCDep
) -> IOCDetailOut:
    ioc = await service.upsert(
        raw_value=payload.value,
        source=payload.source,
        confidence=payload.confidence,
        severity=payload.severity,
        tags=payload.tags,
        references=payload.references,
        description=payload.description,
        do_enrich=payload.enrich,
        user_id=principal.id,
    )
    return await _to_detail(service, ioc)


@router.post(
    "/extract",
    response_model=ExtractResult,
    dependencies=[Depends(require(Permission.ioc_read))],
    summary="Pull indicators out of a report, CSV or STIX bundle without storing them",
)
async def extract_indicators_endpoint(payload: ExtractRequest, service: IOCDep) -> ExtractResult:
    found = await service.preview_extraction(payload.content, fmt=payload.format)
    return ExtractResult(
        count=len(found), indicators=[ExtractedIndicator(**item) for item in found]
    )


@router.post(
    "/bulk",
    response_model=BulkImportResult,
    dependencies=[Depends(require(Permission.ioc_write))],
    summary="Import every indicator found in a report, CSV export or STIX bundle",
)
async def bulk_import(
    payload: BulkImportRequest, principal: CurrentPrincipalDep, service: IOCDep
) -> BulkImportResult:
    result = await service.bulk_import(
        content=payload.content,
        fmt=payload.format,
        source=payload.source,
        confidence=payload.confidence,
        severity=payload.severity,
        tags=payload.tags,
        do_enrich=payload.enrich,
        limit=payload.limit,
        user_id=principal.id,
    )
    return BulkImportResult(
        extracted=result["extracted"],
        imported=result["imported"],
        failed=result["failed"],
        items=[BulkImportItem(**item) for item in result["items"]],
    )


@router.post(
    "/lookup",
    response_model=IOCDetailOut | None,
    dependencies=[Depends(require(Permission.ioc_read))],
    summary="Look up a stored indicator by value (defanged input accepted)",
)
async def lookup_ioc(payload: LookupRequest, service: IOCDep) -> IOCDetailOut | None:
    ioc = await service.lookup(payload.value)
    return await _to_detail(service, ioc) if ioc else None


@router.get(
    "",
    response_model=Page[IOCOut],
    dependencies=[Depends(require(Permission.ioc_read))],
)
async def search_iocs(
    service: IOCDep,
    ioc_type: IOCType | None = None,
    threat_level: ThreatLevel | None = None,
    source: str | None = None,
    min_score: int | None = Query(default=None, ge=0, le=100),
    q: str | None = Query(default=None, max_length=256),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Page[IOCOut]:
    items, total = await service.search(
        ioc_type=ioc_type.value if ioc_type else None,
        threat_level=threat_level.value if threat_level else None,
        source=source,
        min_score=min_score,
        query=q,
        page=page,
        page_size=page_size,
    )
    return Page[IOCOut](
        items=[IOCOut.model_validate(i) for i in items],
        meta=PageMeta(page=page, page_size=page_size, total=total),
    )


@router.get(
    "/{ioc_id}",
    response_model=IOCDetailOut,
    dependencies=[Depends(require(Permission.ioc_read))],
)
async def get_ioc(ioc_id: str, service: IOCDep) -> IOCDetailOut:
    ioc = await service.get(ioc_id)
    if ioc is None:
        raise NotFoundError("IOC not found.")
    return await _to_detail(service, ioc)


@router.get(
    "/{ioc_id}/explain",
    response_model=ScoreExplainOut,
    dependencies=[Depends(require(Permission.ioc_read))],
    summary="Per-signal breakdown of how an indicator's threat score was computed",
)
async def explain_ioc(ioc_id: str, service: IOCDep) -> ScoreExplainOut:
    ioc = await service.get(ioc_id)
    if ioc is None:
        raise NotFoundError("IOC not found.")
    breakdown = await service.explain(ioc_id)
    if breakdown is None:
        raise NotFoundError("No score breakdown available for this IOC.")
    return ScoreExplainOut(
        score=breakdown["score"],
        level=breakdown["level"],
        contributions=breakdown["contributions"],
    )


@router.post(
    "/{ioc_id}/enrich",
    response_model=IOCDetailOut,
    dependencies=[Depends(require(Permission.enrich_run))],
    summary="Re-run enrichment and rescoring for an existing indicator",
)
async def enrich_ioc(ioc_id: str, principal: CurrentPrincipalDep, service: IOCDep) -> IOCDetailOut:
    ioc = await service.get(ioc_id)
    if ioc is None:
        raise NotFoundError("IOC not found.")
    updated = await service.rerun_enrichment(ioc, user_id=principal.id)
    return await _to_detail(service, updated)


async def _to_detail(service: IOCService, ioc) -> IOCDetailOut:
    # Fetch enrichments explicitly (awaited) rather than via the lazy ORM
    # relationship, which cannot be loaded during Pydantic serialisation.
    records = await service.enrichments_for(ioc.id)
    base = IOCOut.model_validate(ioc)
    return IOCDetailOut(
        **base.model_dump(),
        enrichments=[EnrichmentOut(provider=e.provider, data=e.data) for e in records],
    )
