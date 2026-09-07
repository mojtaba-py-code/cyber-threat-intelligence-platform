"""Regression tests for defects found in the professional audit."""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from app.config.settings import Settings
from app.ioc.indicators import defang, refang

REPO_ROOT = Path(__file__).resolve().parents[1]


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


# --- Production refuses open registration into a writable role --------------
def _production_settings(**overrides) -> Settings:
    """A settings object that passes every other production guard."""
    base: dict = {
        "app_env": "production",
        "app_debug": False,
        "master_encryption_key": "k" * 44,
        "jwt_secret_key": "s" * 40,
        "cors_origins": ["https://tip.example"],
    }
    return Settings(**{**base, **overrides})


def test_production_rejects_open_registration_into_a_writable_role():
    settings = _production_settings(
        allow_open_registration=True, registration_default_role="analyst"
    )
    with pytest.raises(RuntimeError, match="REGISTRATION_DEFAULT_ROLE"):
        settings.validate_runtime()


def test_production_allows_open_registration_only_for_viewers():
    _production_settings(
        allow_open_registration=True, registration_default_role="viewer"
    ).validate_runtime()


def test_production_allows_a_writable_default_role_when_registration_is_closed():
    _production_settings(
        allow_open_registration=False, registration_default_role="analyst"
    ).validate_runtime()


def test_non_production_keeps_the_open_analyst_demo():
    Settings(
        app_env="development", allow_open_registration=True, registration_default_role="analyst"
    ).validate_runtime()


# --- Comma-separated list settings load from the environment ----------------
# `.env.example` ships `CORS_ORIGINS=a,b` and an empty `OUTBOUND_ALLOWED_HOSTS=`,
# and the docs tell operators to write exactly that. pydantic-settings treats a
# list field as complex and JSON-decodes it at the source, before any validator
# runs, so those values aborted start-up with a SettingsError: the documented
# quick start and `docker compose up` both died on a fresh checkout. The fields
# are annotated NoDecode to hand the raw string to `_split_csv` instead.
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", []),
        ("a.example", ["a.example"]),
        ("a.example,b.example", ["a.example", "b.example"]),
        ("  a.example , b.example  ", ["a.example", "b.example"]),
        ('["a.example","b.example"]', ["a.example", "b.example"]),  # JSON still accepted
    ],
)
def test_csv_list_setting_parses_env_string(monkeypatch, raw, expected):
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", raw)
    assert Settings(_env_file=None).outbound_allowed_hosts == expected


def test_all_three_list_settings_read_plain_env_strings(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example,https://b.example")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "172.16.0.0/12,10.0.0.0/8")
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "feed.example")
    settings = Settings(_env_file=None)
    assert settings.cors_origins == ["https://a.example", "https://b.example"]
    assert settings.trusted_proxy_cidrs == ["172.16.0.0/12", "10.0.0.0/8"]
    assert settings.outbound_allowed_hosts == ["feed.example"]


def test_list_settings_keep_their_defaults_when_unset(monkeypatch):
    for var in ("CORS_ORIGINS", "TRUSTED_PROXY_CIDRS", "OUTBOUND_ALLOWED_HOSTS"):
        monkeypatch.delenv(var, raising=False)
    settings = Settings(_env_file=None)
    assert settings.cors_origins == ["http://localhost:3000"]
    assert settings.trusted_proxy_cidrs == []
    assert settings.outbound_allowed_hosts == []


# --- The shipped .env.example is loadable as-is -----------------------------
# The quick start is `cp .env.example .env`, so the file has to parse into a
# Settings object. This reads the real file, not a copy of its contents.
def test_shipped_env_example_loads(monkeypatch):
    for var in ("CORS_ORIGINS", "TRUSTED_PROXY_CIDRS", "OUTBOUND_ALLOWED_HOSTS", "APP_ENV"):
        monkeypatch.delenv(var, raising=False)
    settings = Settings(_env_file=REPO_ROOT / ".env.example")
    assert settings.cors_origins == ["http://localhost:3000", "http://localhost:8000"]
    assert settings.outbound_allowed_hosts == []
    assert settings.trusted_proxy_cidrs == []
    # The quick start points readers at /docs, so the sample env must serve it.
    assert settings.docs_enabled is True
