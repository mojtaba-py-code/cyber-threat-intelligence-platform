from __future__ import annotations

from sqlalchemy import select

from app.models.enrichment import EnrichmentRecord
from app.repositories.base import BaseRepository


class EnrichmentRepository(BaseRepository[EnrichmentRecord]):
    model = EnrichmentRecord

    async def get(self, ioc_id: str, provider: str) -> EnrichmentRecord | None:  # type: ignore[override]
        result = await self.session.execute(
            select(EnrichmentRecord).where(
                EnrichmentRecord.ioc_id == ioc_id, EnrichmentRecord.provider == provider
            )
        )
        return result.scalar_one_or_none()

    async def upsert(self, ioc_id: str, provider: str, data: dict) -> EnrichmentRecord:
        existing = await self.get(ioc_id, provider)
        if existing is None:
            record = EnrichmentRecord(ioc_id=ioc_id, provider=provider, data=data)
            return await self.add(record)
        existing.data = data
        await self.session.flush()
        return existing

    async def list_for_ioc(self, ioc_id: str) -> list[EnrichmentRecord]:
        result = await self.session.execute(
            select(EnrichmentRecord).where(EnrichmentRecord.ioc_id == ioc_id)
        )
        return list(result.scalars().all())
