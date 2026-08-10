"""Correlation graph endpoints: relate, pivot, neighbours, attack chain."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.api.deps import CurrentPrincipalDep, get_correlation_service, require
from app.ioc.types import IOCType
from app.security.rbac import Permission
from app.services.correlation_service import CorrelationService

router = APIRouter()

CorrDep = Annotated[CorrelationService, Depends(get_correlation_service)]

# A STIX-like reference: ``<type>:<value>`` (e.g. ``ipv4-addr:198.51.100.23``).
_REF_PATTERN = r"^[a-z0-9-]{1,32}:.+$"

Relationship = Literal[
    "resolves-to",
    "communicates-with",
    "drops",
    "exploits",
    "attributed-to",
    "uses",
    "related-to",
]


class RelationshipCreate(BaseModel):
    source_ref: str = Field(
        examples=["domain-name:evil.example"], max_length=2100, pattern=_REF_PATTERN
    )
    target_ref: str = Field(
        examples=["ipv4-addr:198.51.100.23"], max_length=2100, pattern=_REF_PATTERN
    )
    relationship: Relationship = "related-to"
    confidence: float = Field(default=0.5, ge=0, le=1)


@router.post(
    "/relationships",
    status_code=201,
    dependencies=[Depends(require(Permission.ioc_write))],
)
async def add_relationship(
    payload: RelationshipCreate, principal: CurrentPrincipalDep, service: CorrDep
) -> dict:
    await service.add_relationship(
        source_ref=payload.source_ref,
        target_ref=payload.target_ref,
        relationship=payload.relationship,
        confidence=payload.confidence,
        user_id=principal.id,
    )
    return {"status": "created", "relationship": payload.relationship}


@router.get(
    "/neighbors",
    dependencies=[Depends(require(Permission.ioc_read))],
    summary="Direct neighbours (in + out edges) of a reference",
)
async def neighbors(
    service: CorrDep, ref: str = Query(max_length=2100, pattern=_REF_PATTERN)
) -> dict:
    return {"ref": ref, "neighbors": await service.neighbors(ref)}


@router.get(
    "/attack-chain",
    dependencies=[Depends(require(Permission.ioc_read))],
    summary="Shortest directed path (attack chain) between two references",
)
async def attack_chain(
    service: CorrDep,
    source_ref: str = Query(max_length=2100, pattern=_REF_PATTERN),
    target_ref: str = Query(max_length=2100, pattern=_REF_PATTERN),
) -> dict:
    chain = await service.attack_chain(source_ref, target_ref)
    return {"source_ref": source_ref, "target_ref": target_ref, "chain": chain}


@router.get(
    "/pivot",
    dependencies=[Depends(require(Permission.ioc_read))],
    summary="Pivot around an indicator to a related subgraph",
)
async def pivot(
    service: CorrDep,
    ioc_type: IOCType,
    value: str = Query(max_length=2048),
    depth: int = Query(default=2, ge=1, le=4),
) -> dict:
    return await service.pivot(ioc_type=ioc_type.value, value=value, depth=depth)


@router.get(
    "/graph",
    dependencies=[Depends(require(Permission.ioc_read))],
    summary="Export the full correlation graph (nodes + edges)",
)
async def graph(service: CorrDep) -> dict:
    return await service.full_graph()
