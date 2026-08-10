from __future__ import annotations

from sqlalchemy import or_, select

from app.correlation.graph import Edge
from app.models.correlation import CorrelationEdge
from app.repositories.base import BaseRepository


class CorrelationRepository(BaseRepository[CorrelationEdge]):
    model = CorrelationEdge

    async def upsert_edge(
        self,
        *,
        source_ref: str,
        target_ref: str,
        relationship: str = "related-to",
        confidence: float = 0.5,
        source: str = "manual",
    ) -> CorrelationEdge:
        result = await self.session.execute(
            select(CorrelationEdge).where(
                CorrelationEdge.source_ref == source_ref,
                CorrelationEdge.target_ref == target_ref,
                CorrelationEdge.relationship == relationship,
            )
        )
        edge = result.scalar_one_or_none()
        if edge is None:
            edge = CorrelationEdge(
                source_ref=source_ref,
                target_ref=target_ref,
                relationship=relationship,
                confidence=confidence,
                source=source,
            )
            return await self.add(edge)
        edge.confidence = confidence
        await self.session.flush()
        return edge

    async def all_edges(self) -> list[Edge]:
        result = await self.session.execute(select(CorrelationEdge))
        return [
            Edge(
                source_ref=e.source_ref,
                target_ref=e.target_ref,
                relationship=e.relationship,
                confidence=e.confidence,
                source=e.source,
            )
            for e in result.scalars().all()
        ]

    async def edges_touching(self, ref: str) -> list[Edge]:
        result = await self.session.execute(
            select(CorrelationEdge).where(
                or_(CorrelationEdge.source_ref == ref, CorrelationEdge.target_ref == ref)
            )
        )
        return [
            Edge(
                source_ref=e.source_ref,
                target_ref=e.target_ref,
                relationship=e.relationship,
                confidence=e.confidence,
                source=e.source,
            )
            for e in result.scalars().all()
        ]
