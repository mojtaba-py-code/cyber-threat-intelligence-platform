"""Integration tests for bulk import, sharing exports and the live alert stream."""

from __future__ import annotations

import asyncio
import json

import pytest
import pytest_asyncio
from app.api.v1.stream import stream_alerts
from app.core.events import EventBus, get_event_bus

REPORT = """
Incident 42: the loader beaconed to hxxp://c2[.]example/gate.php and
198[.]51[.]100[.]77, dropping payload.exe (do not extract from evidence.zip).
Related: CVE-2024-21412, technique T1071.001.
"""


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


# --- extraction preview -----------------------------------------------------


@pytest.mark.asyncio
async def test_extract_previews_without_storing(client, headers):
    r = await client.post("/api/v1/iocs/extract", headers=headers, json={"content": REPORT})
    assert r.status_code == 200, r.text
    body = r.json()
    values = {i["value"] for i in body["indicators"]}
    assert "http://c2.example/gate.php" in values
    assert "198.51.100.77" in values
    assert "payload.exe" not in values
    assert body["count"] == len(body["indicators"])
    # Nothing was persisted by a preview.
    assert (await client.get("/api/v1/iocs", headers=headers)).json()["meta"]["total"] == 0


# --- bulk import ------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_import_stores_every_indicator_in_a_report(client, headers):
    r = await client.post(
        "/api/v1/iocs/bulk",
        headers=headers,
        json={"content": REPORT, "source": "incident42", "tags": ["ir"]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["extracted"] >= 4
    assert body["imported"] == body["extracted"]
    assert body["failed"] == 0
    assert all(item["status"] == "imported" for item in body["items"])

    stored = await client.get("/api/v1/iocs?source=incident42", headers=headers)
    assert stored.json()["meta"]["total"] == body["imported"]


@pytest.mark.asyncio
async def test_bulk_import_accepts_a_stix_bundle(client, headers):
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.55']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'stix-in.example']"},
        ],
    }
    r = await client.post(
        "/api/v1/iocs/bulk",
        headers=headers,
        json={"content": json.dumps(bundle), "format": "stix", "source": "partner"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["imported"] == 2


@pytest.mark.asyncio
async def test_bulk_import_respects_the_limit(client, headers):
    text = " ".join(f"10.1.0.{i}" for i in range(1, 12))
    r = await client.post("/api/v1/iocs/bulk", headers=headers, json={"content": text, "limit": 4})
    assert r.json()["imported"] == 4


@pytest.mark.asyncio
async def test_bulk_import_of_a_document_with_no_indicators(client, headers):
    r = await client.post(
        "/api/v1/iocs/bulk", headers=headers, json={"content": "nothing of interest here"}
    )
    assert r.status_code == 200
    assert r.json() == {"extracted": 0, "imported": 0, "failed": 0, "items": []}


@pytest.mark.asyncio
async def test_bulk_import_rejects_malformed_stix(client, headers):
    r = await client.post(
        "/api/v1/iocs/bulk", headers=headers, json={"content": "{oops", "format": "stix"}
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_viewer_may_extract_but_not_bulk_import(client, viewer_headers):
    headers = viewer_headers
    assert (
        await client.post("/api/v1/iocs/extract", headers=headers, json={"content": REPORT})
    ).status_code == 200
    assert (
        await client.post("/api/v1/iocs/bulk", headers=headers, json={"content": REPORT})
    ).status_code == 403


# --- sharing exports --------------------------------------------------------


@pytest.mark.asyncio
async def test_stix_export_is_a_valid_bundle(client, headers):
    await client.post("/api/v1/iocs", headers=headers, json={"value": "198.51.100.60"})
    r = await client.get("/api/v1/reports/iocs.stix", headers=headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/stix+json")
    bundle = json.loads(r.text)
    assert bundle["type"] == "bundle"
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert "[ipv4-addr:value = '198.51.100.60']" in patterns


@pytest.mark.asyncio
async def test_misp_export_is_a_valid_event(client, headers):
    await client.post("/api/v1/iocs", headers=headers, json={"value": "misp-out.example"})
    r = await client.get("/api/v1/reports/iocs.misp", headers=headers)
    assert r.status_code == 200
    event = json.loads(r.text)["Event"]
    assert [a["value"] for a in event["Attribute"]] == ["misp-out.example"]


@pytest.mark.asyncio
async def test_exports_honour_search_filters(client, headers):
    await client.post("/api/v1/iocs", headers=headers, json={"value": "203.0.113.80"})
    await client.post("/api/v1/iocs", headers=headers, json={"value": "filtered.example"})
    r = await client.get("/api/v1/reports/iocs.stix?ioc_type=domain-name", headers=headers)
    bundle = json.loads(r.text)
    assert [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"] == [
        "[domain-name:value = 'filtered.example']"
    ]


@pytest.mark.asyncio
async def test_unsupported_export_format_is_rejected(client, headers):
    assert (await client.get("/api/v1/reports/iocs.xlsx", headers=headers)).status_code == 422


# --- live stream ------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_requires_authentication(client):
    async with client.stream("GET", "/api/v1/stream/alerts") as r:
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_alerts_reach_live_subscribers_end_to_end(client, headers):
    """Creating an indicator that matches a rule must reach a live subscriber."""
    rule = await client.post(
        "/api/v1/alerts/rules",
        headers=headers,
        json={
            "name": "everything",
            "metric": "new_ioc",
            "operator": "gte",
            "threshold": 0,
            "channel": "log",
        },
    )
    assert rule.status_code == 201, rule.text

    # Subscribe to the same process-wide bus the SSE endpoint streams from.
    async with get_event_bus().subscribe() as queue:
        posted = await client.post("/api/v1/iocs", headers=headers, json={"value": "198.51.100.99"})
        assert posted.status_code == 200, posted.text
        event = await asyncio.wait_for(queue.get(), timeout=5)

    assert event.type == "alert"
    assert event.data["ioc"].startswith("198")
    assert event.data["title"].startswith("everything:")
    assert event.data["threat_level"] == posted.json()["threat_level"]


@pytest.mark.asyncio
async def test_stream_endpoint_emits_sse_frames_and_releases_its_session():
    """The endpoint is exercised directly: httpx's ASGI transport buffers whole
    responses, so an endless stream cannot be consumed through the test client."""
    bus = EventBus()
    session = _FakeSession()
    response = await stream_alerts(bus=bus, session=session, heartbeat=30)

    assert response.media_type == "text/event-stream"
    assert response.headers["x-accel-buffering"] == "no"
    # The pooled connection is handed back before the long-lived stream starts.
    assert session.closed and session.committed

    frames = response.body_iterator
    assert await asyncio.wait_for(anext(frames), timeout=5) == ": connected\n\n"
    await bus.publish("alert", {"title": "boom"})
    frame = await asyncio.wait_for(anext(frames), timeout=5)
    assert json.loads(frame.split("data: ", 1)[1])["title"] == "boom"
    await frames.aclose()


class _FakeSession:
    """Just enough of AsyncSession for the endpoint's release-the-connection step."""

    def __init__(self) -> None:
        self.committed = False
        self.closed = False

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:
        self.closed = True
