"""Tests for the in-process correlation graph."""

from __future__ import annotations

from app.correlation.graph import Edge, ThreatGraph, make_ref, parse_ref


def _graph() -> ThreatGraph:
    return ThreatGraph(
        [
            Edge("url:http://bad.example/x", "domain-name:bad.example", "communicates-with"),
            Edge("domain-name:bad.example", "ipv4-addr:198.51.100.5", "resolves-to"),
            Edge("ipv4-addr:198.51.100.5", "threat-actor:APT-Demo", "attributed-to"),
        ]
    )


def test_ref_helpers():
    assert make_ref("ipv4-addr", "1.2.3.4") == "ipv4-addr:1.2.3.4"
    assert parse_ref("ipv4-addr:1.2.3.4") == ("ipv4-addr", "1.2.3.4")


def test_counts():
    g = _graph()
    assert g.node_count == 4
    assert g.edge_count == 3


def test_neighbors():
    g = _graph()
    neigh = g.neighbors("domain-name:bad.example")
    refs = {n["ref"] for n in neigh}
    assert "ipv4-addr:198.51.100.5" in refs
    assert "url:http://bad.example/x" in refs


def test_related_within_depth():
    g = _graph()
    related = g.related_within("url:http://bad.example/x", depth=2)
    assert "ipv4-addr:198.51.100.5" in related
    assert "threat-actor:APT-Demo" not in related  # 3 hops away


def test_attack_chain():
    g = _graph()
    chain = g.attack_chain("url:http://bad.example/x", "threat-actor:APT-Demo")
    assert chain[0] == "url:http://bad.example/x"
    assert chain[-1] == "threat-actor:APT-Demo"
    assert len(chain) == 4


def test_export_shape():
    g = _graph()
    exported = g.export()
    assert {"nodes", "edges"} <= exported.keys()
    assert len(exported["edges"]) == 3
