"""Correlation service: materialise and query the threat graph."""

from __future__ import annotations

from app.correlation.graph import ThreatGraph, make_ref
from app.repositories.audit_repository import AuditRepository
from app.repositories.correlation_repository import CorrelationRepository


class CorrelationService:
    def __init__(self, *, correlation: CorrelationRepository, audit: AuditRepository) -> None:
        self._correlation = correlation
        self._audit = audit

    async def add_relationship(
        self,
        *,
        source_ref: str,
        target_ref: str,
        relationship: str = "related-to",
        confidence: float = 0.5,
        user_id: str | None = None,
    ) -> None:
        await self._correlation.upsert_edge(
            source_ref=source_ref,
            target_ref=target_ref,
            relationship=relationship,
            confidence=confidence,
            source="manual",
        )
        await self._audit.record(
            action="correlation.add",
            user_id=user_id,
            detail={"src": source_ref, "dst": target_ref, "rel": relationship},
        )

    async def _graph(self) -> ThreatGraph:
        return ThreatGraph(await self._correlation.all_edges())

    async def neighbors(self, ref: str) -> list[dict]:
        graph = ThreatGraph(await self._correlation.edges_touching(ref))
        return graph.neighbors(ref)

    async def pivot(self, *, ioc_type: str, value: str, depth: int = 2) -> dict:
        graph = await self._graph()
        return graph.export(ref=make_ref(ioc_type, value), depth=depth)

    async def attack_chain(self, source_ref: str, target_ref: str) -> list[str]:
        graph = await self._graph()
        return graph.attack_chain(source_ref, target_ref)

    async def full_graph(self) -> dict:
        graph = await self._graph()
        return graph.export()
