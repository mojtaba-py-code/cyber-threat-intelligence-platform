from __future__ import annotations

from sqlalchemy import func, or_, select

from app.models.ioc import IOC
from app.repositories.base import BaseRepository


class IOCRepository(BaseRepository[IOC]):
    model = IOC

    async def get_by_type_value(self, ioc_type: str, value: str) -> IOC | None:
        result = await self.session.execute(
            select(IOC).where(IOC.type == ioc_type, IOC.value == value)
        )
        return result.scalar_one_or_none()

    def _filtered(
        self,
        *,
        ioc_type: str | None,
        min_score: int | None,
        threat_level: str | None,
        source: str | None,
        status: str | None,
        query: str | None,
    ):
        stmt = select(IOC)
        if ioc_type:
            stmt = stmt.where(IOC.type == ioc_type)
        if min_score is not None:
            stmt = stmt.where(IOC.threat_score >= min_score)
        if threat_level:
            stmt = stmt.where(IOC.threat_level == threat_level)
        if source:
            stmt = stmt.where(IOC.source == source)
        if status:
            stmt = stmt.where(IOC.status == status)
        if query:
            like = f"%{query}%"
            stmt = stmt.where(or_(IOC.value.ilike(like), IOC.description.ilike(like)))
        return stmt

    async def search(
        self,
        *,
        ioc_type: str | None = None,
        min_score: int | None = None,
        threat_level: str | None = None,
        source: str | None = None,
        status: str | None = None,
        query: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[IOC]:
        stmt = self._filtered(
            ioc_type=ioc_type,
            min_score=min_score,
            threat_level=threat_level,
            source=source,
            status=status,
            query=query,
        )
        stmt = stmt.order_by(IOC.threat_score.desc(), IOC.updated_at.desc())
        stmt = stmt.limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count(
        self,
        *,
        ioc_type: str | None = None,
        min_score: int | None = None,
        threat_level: str | None = None,
        source: str | None = None,
        status: str | None = None,
        query: str | None = None,
    ) -> int:
        base = self._filtered(
            ioc_type=ioc_type,
            min_score=min_score,
            threat_level=threat_level,
            source=source,
            status=status,
            query=query,
        ).subquery()
        result = await self.session.execute(select(func.count()).select_from(base))
        return int(result.scalar_one())

    async def count_by_level(self) -> dict[str, int]:
        result = await self.session.execute(
            select(IOC.threat_level, func.count(IOC.id)).group_by(IOC.threat_level)
        )
        return dict(result.tuples().all())

    async def count_by_type(self) -> dict[str, int]:
        result = await self.session.execute(select(IOC.type, func.count(IOC.id)).group_by(IOC.type))
        return dict(result.tuples().all())

    async def count_by_source(self) -> dict[str, int]:
        result = await self.session.execute(
            select(IOC.source, func.count(IOC.id)).group_by(IOC.source)
        )
        return dict(result.tuples().all())

    async def total(self) -> int:
        result = await self.session.execute(select(func.count(IOC.id)))
        return int(result.scalar_one())

    async def top(self, limit: int = 10) -> list[IOC]:
        result = await self.session.execute(
            select(IOC).order_by(IOC.threat_score.desc()).limit(limit)
        )
        return list(result.scalars().all())
