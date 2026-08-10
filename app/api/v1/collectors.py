"""Collector endpoints: run a source and ingest its indicators."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentPrincipalDep, get_ioc_service, require
from app.collectors.factory import get_collector_factory
from app.security.rbac import Permission
from app.services.ioc_service import IOCService

router = APIRouter()

IOCDep = Annotated[IOCService, Depends(get_ioc_service)]


@router.post(
    "/{name}/run",
    dependencies=[Depends(require(Permission.collector_run))],
    summary="Run a collector and ingest results (samples when offline)",
)
async def run_collector(
    name: str,
    principal: CurrentPrincipalDep,
    service: IOCDep,
    limit: int = Query(default=50, ge=1, le=500),
    enrich: bool = True,
) -> dict:
    factory = get_collector_factory()
    collector = factory.build(name)  # raises ValidationError for unknown names
    indicators = await collector.collect(limit=limit)
    summary = await service.ingest_from_collector(indicators, do_enrich=enrich)
    return {
        "collector": name,
        "live": collector.is_live,
        "collected": len(indicators),
        **summary,
    }
