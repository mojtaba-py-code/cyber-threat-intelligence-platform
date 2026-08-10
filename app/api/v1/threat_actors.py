"""Threat-actor profile endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import CurrentPrincipalDep, SessionDep, require
from app.schemas.threat_actor import ThreatActorCreate, ThreatActorOut
from app.security.rbac import Permission
from app.services.threat_actor_service import ThreatActorService

router = APIRouter()


def get_actor_service(session: SessionDep) -> ThreatActorService:
    return ThreatActorService(session)


ActorDep = Annotated[ThreatActorService, Depends(get_actor_service)]


@router.post(
    "",
    response_model=ThreatActorOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.ioc_write))],
)
async def create_actor(
    payload: ThreatActorCreate, principal: CurrentPrincipalDep, service: ActorDep
) -> ThreatActorOut:
    actor = await service.create(data=payload.model_dump(), user_id=principal.id)
    return ThreatActorOut.model_validate(actor)


@router.get(
    "",
    response_model=list[ThreatActorOut],
    dependencies=[Depends(require(Permission.ioc_read))],
)
async def list_actors(service: ActorDep) -> list[ThreatActorOut]:
    actors = await service.list()
    return [ThreatActorOut.model_validate(a) for a in actors]


@router.get(
    "/{actor_id}",
    response_model=ThreatActorOut,
    dependencies=[Depends(require(Permission.ioc_read))],
)
async def get_actor(actor_id: str, service: ActorDep) -> ThreatActorOut:
    return ThreatActorOut.model_validate(await service.get(actor_id))


@router.delete(
    "/{actor_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.ioc_write))],
)
async def delete_actor(actor_id: str, principal: CurrentPrincipalDep, service: ActorDep) -> None:
    await service.delete(actor_id, user_id=principal.id)
