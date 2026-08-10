"""In-process threat correlation graph, built on :mod:`networkx`.

Entities are referenced STIX-style as ``"<type>:<value>"`` (e.g.
``"domain-name:evil.com"``). Edges are directed and typed
(``resolves-to``, ``communicates-with``, ``drops``, ``exploits``,
``attributed-to``, ``uses``, ``related-to``). The graph is materialised from the
``correlation_edges`` table for traversal, pivoting and attack-chain discovery.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx


@dataclass(frozen=True, slots=True)
class Edge:
    source_ref: str
    target_ref: str
    relationship: str = "related-to"
    confidence: float = 0.5
    source: str = "manual"


def make_ref(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{value}"


def parse_ref(ref: str) -> tuple[str, str]:
    ioc_type, _, value = ref.partition(":")
    return ioc_type, value


class ThreatGraph:
    """A queryable wrapper around a directed multigraph of threat entities."""

    def __init__(self, edges: list[Edge] | None = None) -> None:
        self._g = nx.MultiDiGraph()
        for edge in edges or []:
            self.add_edge(edge)

    def add_edge(self, edge: Edge) -> None:
        self._g.add_edge(
            edge.source_ref,
            edge.target_ref,
            key=edge.relationship,
            relationship=edge.relationship,
            confidence=edge.confidence,
            source=edge.source,
        )

    @property
    def node_count(self) -> int:
        return self._g.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._g.number_of_edges()

    def neighbors(self, ref: str) -> list[dict]:
        """Directly related entities (both directions) with edge metadata."""
        if ref not in self._g:
            return []
        out: list[dict] = []
        for _, dst, data in self._g.out_edges(ref, data=True):
            out.append({"ref": dst, "direction": "out", **_edge_meta(data)})
        for src, _, data in self._g.in_edges(ref, data=True):
            out.append({"ref": src, "direction": "in", **_edge_meta(data)})
        return out

    def related_within(self, ref: str, depth: int = 2) -> set[str]:
        """All entities reachable within ``depth`` hops (undirected)."""
        if ref not in self._g:
            return set()
        undirected = self._g.to_undirected(as_view=True)
        lengths = nx.single_source_shortest_path_length(undirected, ref, cutoff=depth)
        return {node for node in lengths if node != ref}

    def attack_chain(self, source_ref: str, target_ref: str) -> list[str]:
        """Shortest directed path between two entities, or ``[]`` if none."""
        if source_ref not in self._g or target_ref not in self._g:
            return []
        try:
            return nx.shortest_path(self._g, source_ref, target_ref)
        except nx.NetworkXNoPath:
            return []

    def subgraph_refs(self, ref: str, depth: int = 2) -> set[str]:
        related = self.related_within(ref, depth)
        related.add(ref)
        return related

    def export(self, ref: str | None = None, depth: int = 2) -> dict:
        """Cytoscape-style ``{nodes, edges}`` for the whole graph or a pivot."""
        g = self._g
        if ref is not None:
            g = self._g.subgraph(self.subgraph_refs(ref, depth))
        nodes = [{"id": n, "type": parse_ref(n)[0]} for n in g.nodes]
        edges = [
            {
                "source": u,
                "target": v,
                "relationship": data.get("relationship", "related-to"),
                "confidence": data.get("confidence", 0.5),
            }
            for u, v, data in g.edges(data=True)
        ]
        return {"nodes": nodes, "edges": edges}


def _edge_meta(data: dict) -> dict:
    return {
        "relationship": data.get("relationship", "related-to"),
        "confidence": data.get("confidence", 0.5),
        "source": data.get("source", "manual"),
    }
