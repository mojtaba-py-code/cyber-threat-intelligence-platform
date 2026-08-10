"""Regression tests for defects found in the professional audit."""

from __future__ import annotations

import pytest
import pytest_asyncio
from app.ioc.indicators import defang, refang


async def _login(client, payload) -> dict:
    await client.post("/api/v1/auth/register", json=payload)
    r = await client.post(
        "/api/v1/auth/login", json={"email": payload["email"], "password": payload["password"]}
    )
    return r.json()


@pytest_asyncio.fixture
async def tokens(client, register_payload) -> dict:
    return await _login(client, register_payload)


@pytest_asyncio.fixture
async def headers(tokens) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# --- Alerting wired end-to-end (arch #1, the headline) ----------------------
@pytest.mark.asyncio
async def test_alert_fires_on_matching_ioc(client, headers):
    # Create a rule that fires for any new indicator.
    rule = await client.post(
        "/api/v1/alerts/rules",
        headers=headers,
        json={"name": "any-new-ioc", "metric": "new_ioc", "channel": "log"},
    )
    assert rule.status_code == 201, rule.text

    # Submitting an IOC must generate an alert.
    await client.post(
        "/api/v1/iocs",
        headers=headers,
        json={"value": "203.0.113.10", "source": "abuseipdb"},
    )
    alerts = await client.get("/api/v1/alerts", headers=headers)
    assert alerts.status_code == 200
    assert len(alerts.json()) >= 1
    assert alerts.json()[0]["delivered"] is True  # log channel delivers


@pytest.mark.asyncio
async def test_threat_score_rule_only_fires_above_threshold(client, headers):
    await client.post(
        "/api/v1/alerts/rules",
        headers=headers,
        json={"name": "high", "metric": "threat_score", "operator": "gte", "threshold": 100},
    )
    await client.post(
        "/api/v1/iocs", headers=headers, json={"value": "198.51.100.7", "source": "manual"}
    )
    alerts = await client.get("/api/v1/alerts", headers=headers)
    assert alerts.json() == []  # nothing scores 100


# --- Score explainability (arch: ScoreExplainOut was orphaned) --------------
@pytest.mark.asyncio
async def test_score_explain_endpoint(client, headers):
    created = await client.post(
        "/api/v1/iocs", headers=headers, json={"value": "evil.example", "source": "otx"}
    )
    ioc_id = created.json()["id"]
    explain = await client.get(f"/api/v1/iocs/{ioc_id}/explain", headers=headers)
    assert explain.status_code == 200, explain.text
    body = explain.json()
    assert body["score"] == created.json()["threat_score"]
    assert set(body["contributions"]) >= {"source_reputation", "confidence"}


# --- Enrichment re-run (enrich_run permission was orphaned) ------------------
@pytest.mark.asyncio
async def test_enrich_rerun_endpoint(client, headers):
    created = await client.post(
        "/api/v1/iocs", headers=headers, json={"value": "8.8.8.8", "source": "manual"}
    )
    ioc_id = created.json()["id"]
    rerun = await client.post(f"/api/v1/iocs/{ioc_id}/enrich", headers=headers)
    assert rerun.status_code == 200, rerun.text
    assert rerun.json()["id"] == ioc_id


# --- Correlation neighbors + attack-chain (methods were unrouted) -----------
@pytest.mark.asyncio
async def test_correlation_neighbors_and_attack_chain(client, headers):
    await client.post(
        "/api/v1/correlation/relationships",
        headers=headers,
        json={
            "source_ref": "domain-name:evil.example",
            "target_ref": "ipv4-addr:203.0.113.9",
            "relationship": "resolves-to",
        },
    )
    nb = await client.get(
        "/api/v1/correlation/neighbors",
        headers=headers,
        params={"ref": "domain-name:evil.example"},
    )
    assert nb.status_code == 200
    assert any("203.0.113.9" in n.get("ref", "") for n in nb.json()["neighbors"])

    chain = await client.get(
        "/api/v1/correlation/attack-chain",
        headers=headers,
        params={
            "source_ref": "domain-name:evil.example",
            "target_ref": "ipv4-addr:203.0.113.9",
        },
    )
    assert chain.status_code == 200
    assert chain.json()["chain"][0] == "domain-name:evil.example"


@pytest.mark.asyncio
async def test_bad_correlation_ref_rejected(client, headers):
    r = await client.post(
        "/api/v1/correlation/relationships",
        headers=headers,
        json={"source_ref": "no-colon-here", "target_ref": "ipv4-addr:1.2.3.4"},
    )
    assert r.status_code == 422


# --- URL-with-IP host correlates to the ipv4 node (correctness #1) ----------
@pytest.mark.asyncio
async def test_url_with_ip_host_links_to_ipv4_node(client, headers):
    await client.post(
        "/api/v1/iocs",
        headers=headers,
        json={"value": "http://1.2.3.4/payload.bin", "source": "urlhaus"},
    )
    nb = await client.get(
        "/api/v1/correlation/neighbors",
        headers=headers,
        params={"ref": "url:http://1.2.3.4/payload.bin"},
    )
    refs = [n["ref"] for n in nb.json()["neighbors"]]
    assert "ipv4-addr:1.2.3.4" in refs  # not domain-name:1.2.3.4


# --- Threat-actor endpoints (model was unused) ------------------------------
@pytest.mark.asyncio
async def test_threat_actor_crud(client, headers):
    created = await client.post(
        "/api/v1/threat-actors",
        headers=headers,
        json={"name": "APT-Test", "actor_type": "apt", "country": "RU", "aliases": ["TestBear"]},
    )
    assert created.status_code == 201, created.text
    actor_id = created.json()["id"]
    got = await client.get(f"/api/v1/threat-actors/{actor_id}", headers=headers)
    assert got.json()["name"] == "APT-Test"
    listed = await client.get("/api/v1/threat-actors", headers=headers)
    assert len(listed.json()) == 1


# --- Report filter parity (arch #2) -----------------------------------------
@pytest.mark.asyncio
async def test_report_export_honours_ioc_type_filter(client, headers):
    await client.post("/api/v1/iocs", headers=headers, json={"value": "9.9.9.9", "source": "m"})
    await client.post("/api/v1/iocs", headers=headers, json={"value": "bad.example", "source": "m"})
    csv = await client.get("/api/v1/reports/iocs.csv?ioc_type=domain-name", headers=headers)
    assert csv.status_code == 200
    assert "bad[.]example" in csv.text  # defanged domain present
    assert "9.9.9.9" not in csv.text  # ipv4 filtered out by ioc_type


# --- API-key get by id (was missing) ----------------------------------------
@pytest.mark.asyncio
async def test_get_api_key_by_id(client, headers):
    created = await client.post("/api/v1/auth/api-keys", headers=headers, json={"name": "k1"})
    key_id = created.json()["id"]
    got = await client.get(f"/api/v1/auth/api-keys/{key_id}", headers=headers)
    assert got.status_code == 200
    assert got.json()["id"] == key_id
    assert "api_key" not in got.json()  # raw secret never re-exposed


# --- Access-token revoked on logout (security M1) ---------------------------
@pytest.mark.asyncio
async def test_logout_revokes_access_token(client, tokens):
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    # Token works before logout.
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
    await client.post(
        "/api/v1/auth/logout",
        headers=headers,
        json={"refresh_token": tokens["refresh_token"]},
    )
    # Same access token is now rejected.
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401


# --- defang no longer double-mangles (correctness minor) --------------------
def test_defang_refang_roundtrip_https():
    url = "https://evil.example/path"
    assert refang(defang(url)) == url
    assert "hxxpxs" not in defang(url)
