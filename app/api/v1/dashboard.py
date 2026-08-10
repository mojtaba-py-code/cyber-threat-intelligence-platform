"""Dashboard statistics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import SessionDep, get_current_principal
from app.repositories.ioc_repository import IOCRepository
from app.schemas.ioc import IOCOut

router = APIRouter(dependencies=[Depends(get_current_principal)])


@router.get("/stats", summary="Aggregate threat statistics for the dashboard")
async def stats(session: SessionDep) -> dict:
    repo = IOCRepository(session)
    return {
        "total": await repo.total(),
        "by_level": await repo.count_by_level(),
        "by_type": await repo.count_by_type(),
        "by_source": await repo.count_by_source(),
    }


@router.get("/top", response_model=list[IOCOut], summary="Highest-scoring indicators")
async def top(session: SessionDep, limit: int = 10) -> list[IOCOut]:
    repo = IOCRepository(session)
    items = await repo.top(min(limit, 50))
    return [IOCOut.model_validate(i) for i in items]
