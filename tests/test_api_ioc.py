"""Integration tests for the IOC, collector, correlation and report APIs."""

from __future__ import annotations

import pytest
import pytest_asyncio


async def _login(client, payload) -> dict:
    await client.post("/api/v1/auth/register", json=payload)
    r = await client.post(
        "/api/v1/auth/login", json={"email": payload["email"], "password": payload["password"]}
    )
    return r.json()


@pytest_asyncio.fixture
async def headers(client, register_payload) -> dict:
    tokens = await _login(client, register_payload)
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.mark.asyncio
async def test_create_ioc_classifies_and_scores(client, headers):
    r = await client.post(
        "/api/v1/iocs",
        headers=headers,
        json={"value": "hxxp://malware-drop[.]example/x.bin", "source": "abuseipdb"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "url"
    assert body["value"] == "http://malware-drop.example/x.bin"  # refanged
    assert body["defanged_value"].startswith("hxxp")
    assert 0 <= body["threat_score"] <= 100
    assert body["enrichments"]  # enrichment attached


@pytest.mark.asyncio
async def test_lookup_defanged(client, headers):
    await client.post(
        "/api/v1/iocs", headers=headers, json={"value": "198.51.100.23", "source": "manual"}
    )
    r = await client.post(
        "/api/v1/iocs/lookup", headers=headers, json={"value": "198[.]51[.]100[.]23"}
    )
    assert r.status_code == 200
    assert r.json()["value"] == "198.51.100.23"


@pytest.mark.asyncio
async def test_invalid_indicator_422(client, headers):
    r = await client.post(
        "/api/v1/iocs", headers=headers, json={"value": "not an indicator!!", "source": "manual"}
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_search_and_filter(client, headers):
    for val in ["1.1.1.1", "2.2.2.2", "evil.example.com"]:
        await client.post("/api/v1/iocs", headers=headers, json={"value": val})
    r = await client.get("/api/v1/iocs?ioc_type=ipv4-addr&page_size=10", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["total"] == 2
    assert all(i["type"] == "ipv4-addr" for i in body["items"])


@pytest.mark.asyncio
async def test_run_collector_offline_ingests(client, headers):
    r = await client.post("/api/v1/collectors/urlhaus/run?limit=10", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["live"] is False
    assert body["ingested"] >= 1
    # Ingested indicators now appear in search.
    listing = await client.get("/api/v1/iocs?source=urlhaus", headers=headers)
    assert listing.json()["meta"]["total"] >= 1


@pytest.mark.asyncio
async def test_auto_correlation_from_url(client, headers):
    await client.post("/api/v1/iocs", headers=headers, json={"value": "http://bad.example/evil"})
    r = await client.get(
        "/api/v1/correlation/pivot?ioc_type=url&value=http://bad.example/evil&depth=2",
        headers=headers,
    )
    assert r.status_code == 200
    refs = {n["id"] for n in r.json()["nodes"]}
    assert "domain-name:bad.example" in refs  # auto-derived edge


@pytest.mark.asyncio
async def test_manual_relationship_and_graph(client, headers):
    await client.post(
        "/api/v1/correlation/relationships",
        headers=headers,
        json={
            "source_ref": "domain-name:evil.example",
            "target_ref": "ipv4-addr:198.51.100.5",
            "relationship": "resolves-to",
            "confidence": 0.9,
        },
    )
    g = await client.get("/api/v1/correlation/graph", headers=headers)
    assert g.status_code == 200
    assert len(g.json()["edges"]) >= 1


@pytest.mark.asyncio
async def test_dashboard_stats(client, headers):
    await client.post("/api/v1/iocs", headers=headers, json={"value": "9.9.9.9"})
    r = await client.get("/api/v1/dashboard/stats", headers=headers)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.asyncio
async def test_report_export_csv_and_md(client, headers):
    await client.post("/api/v1/iocs", headers=headers, json={"value": "5.5.5.5"})
    csv_resp = await client.get("/api/v1/reports/iocs.csv", headers=headers)
    assert csv_resp.status_code == 200
    assert "type,value,threat_score" in csv_resp.text
    md_resp = await client.get("/api/v1/reports/iocs.md", headers=headers)
    assert md_resp.status_code == 200
    assert md_resp.text.startswith("# Threat Intelligence Report")


@pytest.mark.asyncio
async def test_viewer_cannot_write(client, viewer_headers):
    r = await client.post("/api/v1/iocs", headers=viewer_headers, json={"value": "1.2.3.4"})
    assert r.status_code == 403
