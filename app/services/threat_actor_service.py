"""Threat-actor profile management."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, NotFoundError
from app.models.threat_actor import ThreatActor
from app.repositories.audit_repository import AuditRepository


class ThreatActorService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._audit = AuditRepository(session)

    async def create(self, *, data: dict, user_id: str | None = None) -> ThreatActor:
        name = data["name"]
        existing = await self._session.execute(select(ThreatActor).where(ThreatActor.name == name))
        if existing.scalar_one_or_none() is not None:
            raise ConflictError(f"Threat actor '{name}' already exists.")
        actor = ThreatActor(**data)
        self._session.add(actor)
        await self._session.flush()
        await self._audit.record(action="actor.create", user_id=user_id, detail={"name": name})
        return actor

    async def list(self) -> list[ThreatActor]:
        result = await self._session.execute(select(ThreatActor).order_by(ThreatActor.name))
        return list(result.scalars().all())

    async def get(self, actor_id: str) -> ThreatActor:
        actor = await self._session.get(ThreatActor, actor_id)
        if actor is None:
            raise NotFoundError("Threat actor not found.")
        return actor

    async def delete(self, actor_id: str, *, user_id: str | None = None) -> None:
        actor = await self.get(actor_id)
        await self._session.delete(actor)
        await self._session.flush()
        await self._audit.record(action="actor.delete", user_id=user_id, detail={"id": actor_id})
