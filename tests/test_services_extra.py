"""Extra service-level tests: alerts, reports, correlation, auth flows."""

from __future__ import annotations

import pytest
import pytest_asyncio
from app.models.alert import AlertRule
from app.models.ioc import IOC
from app.services.alert_service import AlertService
from app.services.report_service import ReportService


# --- Alert service ----------------------------------------------------------
@pytest.mark.asyncio
async def test_alert_rule_matches_and_delivers(session):
    rule = AlertRule(
        name="High score", metric="threat_score", operator="gte", threshold=50, channel="log"
    )
    session.add(rule)
    ioc = IOC(
        type="ipv4-addr",
        value="198.51.100.9",
        defanged_value="198[.]51[.]100[.]9",
        threat_score=80,
        threat_level="high",
        severity="high",
        source="abuseipdb",
    )
    session.add(ioc)
    await session.flush()

    service = AlertService(session)
    alerts = await service.evaluate_ioc(ioc)
    assert len(alerts) == 1
    assert alerts[0].delivered is True  # log channel delivers immediately


@pytest.mark.asyncio
async def test_alert_rule_below_threshold_no_alert(session):
    session.add(
        AlertRule(name="r", metric="threat_score", operator="gte", threshold=90, channel="log")
    )
    ioc = IOC(
        type="ipv4-addr",
        value="1.2.3.4",
        defanged_value="1[.]2[.]3[.]4",
        threat_score=10,
        threat_level="low",
    )
    session.add(ioc)
    await session.flush()
    alerts = await AlertService(session).evaluate_ioc(ioc)
    assert alerts == []


@pytest.mark.asyncio
async def test_alert_webhook_offline_not_delivered(session):
    session.add(
        AlertRule(
            name="wh",
            metric="new_ioc",
            channel="webhook",
            channel_config={"url": "http://hook.example/x"},
        )
    )
    ioc = IOC(type="domain-name", value="x.example", defanged_value="x[.]example", threat_score=60)
    session.add(ioc)
    await session.flush()
    alerts = await AlertService(session).evaluate_ioc(ioc)
    # Offline policy: alert recorded but not delivered (no outbound call).
    assert alerts[0].delivered is False


# --- Report service ---------------------------------------------------------
def _ioc(value="9.9.9.9", score=70):
    return IOC(
        type="ipv4-addr",
        value=value,
        defanged_value=value.replace(".", "[.]"),
        threat_score=score,
        threat_level="high",
        severity="high",
        source="manual",
        tags=["c2"],
    )


def test_report_formats():
    iocs = [_ioc(), _ioc("8.8.8.8", 20)]
    assert "type,value,threat_score" in ReportService.to_csv(iocs)
    assert '"threat_score": 70' in ReportService.to_json(iocs)
    md = ReportService.to_markdown(iocs)
    assert md.startswith("# Threat Intelligence Report")
    summary = ReportService.executive_summary({"total": 2, "by_level": {"high": 2}})
    assert "Executive Threat Summary" in summary


# --- gen_keys script --------------------------------------------------------
def test_gen_keys_outputs(capsys):
    from app.scripts.gen_keys import main

    main()
    out = capsys.readouterr().out
    assert "MASTER_ENCRYPTION_KEY=" in out
    assert "JWT_SECRET_KEY=" in out


# --- Auth API extra flows ---------------------------------------------------
async def _login(client, payload):
    await client.post("/api/v1/auth/register", json=payload)
    r = await client.post(
        "/api/v1/auth/login", json={"email": payload["email"], "password": payload["password"]}
    )
    return r.json()


@pytest_asyncio.fixture
async def headers(client, register_payload):
    tokens = await _login(client, register_payload)
    return {"Authorization": f"Bearer {tokens['access_token']}"}, tokens


@pytest.mark.asyncio
async def test_logout_revokes_refresh(client, register_payload):
    tokens = await _login(client, register_payload)
    lo = await client.post("/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert lo.status_code == 204
    after = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert after.status_code == 401


@pytest.mark.asyncio
async def test_api_key_revoke(client, headers):
    h, _ = headers
    created = await client.post("/api/v1/auth/api-keys", headers=h, json={"name": "k"})
    key_id = created.json()["id"]
    raw = created.json()["api_key"]
    revoke = await client.delete(f"/api/v1/auth/api-keys/{key_id}", headers=h)
    assert revoke.status_code == 204
    # Revoked key no longer authenticates.
    r = await client.get("/api/v1/auth/me", headers={"X-API-Key": raw})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_correlation_neighbors_and_chain(client, headers):
    h, _ = headers
    for src, dst, rel in [
        ("domain-name:evil.example", "ipv4-addr:198.51.100.5", "resolves-to"),
        ("ipv4-addr:198.51.100.5", "threat-actor:APT-Demo", "attributed-to"),
    ]:
        await client.post(
            "/api/v1/correlation/relationships",
            headers=h,
            json={"source_ref": src, "target_ref": dst, "relationship": rel},
        )
    g = await client.get("/api/v1/correlation/graph", headers=h)
    assert len(g.json()["edges"]) == 2


@pytest.mark.asyncio
async def test_ioc_get_by_id_and_404(client, headers):
    h, _ = headers
    created = await client.post("/api/v1/iocs", headers=h, json={"value": "3.3.3.3"})
    ioc_id = created.json()["id"]
    got = await client.get(f"/api/v1/iocs/{ioc_id}", headers=h)
    assert got.status_code == 200
    missing = await client.get("/api/v1/iocs/nope", headers=h)
    assert missing.status_code == 404
