"""Regression tests for the hardening pass.

Each test here pins a defect that was live in a released commit, so the name of
the test is the defect it prevents coming back.
"""

from __future__ import annotations

import pytest
from app.core.ssrf import SSRFGuard, ip_is_public
from app.enrichment.enrichers import DNSEnricher
from app.services.report_service import ReportService
from tests.conftest import make_user

# --- CSV formula injection --------------------------------------------------
# A tag is attacker-supplied (it rides in on an imported report) and the CSV
# export exists to be opened in Excel, so a cell beginning "=" was a live DDE
# payload on the analyst's machine.


class _FakeIOC:
    """The handful of attributes the report layer reads off an IOC."""

    def __init__(self, **kw) -> None:
        defaults = {
            "type": "ipv4-addr",
            "defanged_value": "203[.]0[.]113[.]5",
            "threat_score": 10,
            "threat_level": "low",
            "severity": "medium",
            "source": "manual",
            "tags": [],
            "first_seen": None,
            "last_seen": None,
        }
        self.__dict__.update({**defaults, **kw})


@pytest.mark.parametrize("payload", ["=cmd|'/c calc'!A1", "+1+1", "-1+1", "@SUM(1)", "\tx", "\rx"])
def test_csv_export_neutralises_formula_cells(payload):
    csv = ReportService.to_csv([_FakeIOC(tags=[payload])])
    body = csv.splitlines()[1]
    # The payload survives as readable text, but never as a leading formula
    # character that a spreadsheet would evaluate.
    assert payload.lstrip() in csv or payload in csv
    for cell in body.split(","):
        assert not cell.strip('"').startswith(("=", "+", "-", "@", "\t", "\r"))


def test_csv_export_leaves_ordinary_values_alone():
    csv = ReportService.to_csv([_FakeIOC(tags=["bruteforce", "ssh"])])
    assert "'" not in csv
    assert "203[.]0[.]113[.]5" in csv


def test_markdown_export_escapes_table_pipes():
    md = ReportService.to_markdown([_FakeIOC(defanged_value="a|b")])
    assert "a\\|b" in md


@pytest.mark.asyncio
async def test_api_rejects_a_tag_that_would_be_a_formula(client, register_payload):
    await client.post("/api/v1/auth/register", json=register_payload)
    tokens = await client.post("/api/v1/auth/login", json=register_payload)
    headers = {"Authorization": f"Bearer {tokens.json()['access_token']}"}
    hostile = await client.post(
        "/api/v1/iocs",
        headers=headers,
        json={"value": "203.0.113.55", "tags": ["=cmd|'/c calc'!A1"]},
    )
    assert hostile.status_code == 422
    ok = await client.post(
        "/api/v1/iocs",
        headers=headers,
        json={"value": "203.0.113.55", "tags": ["bruteforce", "T1059.001", "cve-2024-21412"]},
    )
    assert ok.status_code == 200, ok.text
    too_many = await client.post(
        "/api/v1/iocs",
        headers=headers,
        json={"value": "198.51.100.9", "tags": [f"t{i}" for i in range(33)]},
    )
    assert too_many.status_code == 422


# --- SSRF guard: shared address space ---------------------------------------
# 100.64.0.0/10 is neither "private" nor "loopback" to Python, so a guard built
# only from those flags let it through — and it is exactly where cloud
# platforms put internal services.


@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",  # RFC 6598 carrier-grade NAT
        "100.127.255.254",
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",  # cloud metadata
        "192.168.1.1",
        "::1",
        "fd00::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "64:ff9b::7f00:1",  # NAT64-embedded loopback
    ],
)
def test_ssrf_guard_refuses_non_routable_space(address):
    assert ip_is_public(address) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
def test_ssrf_guard_still_allows_public_addresses(address):
    assert ip_is_public(address) is True


# --- Enrichment honours the allow-list --------------------------------------
# The engine built an SSRFGuard and never called it, while the README promised
# enrichment ran behind that guard.


@pytest.mark.asyncio
async def test_dns_enrichment_refuses_a_host_outside_the_allow_list(settings_factory):
    enricher = DNSEnricher(
        settings_factory(enable_live_collectors=True, outbound_allowed_hosts=["feeds.example"])
    )
    assert (await enricher.enrich("evil.example"))["dns"]["blocked"] is True


@pytest.mark.asyncio
async def test_dns_enrichment_makes_no_call_at_all_when_offline(settings_factory):
    enricher = DNSEnricher(settings_factory(enable_live_collectors=False))
    assert (await enricher.enrich("evil.example"))["dns"]["source"] == "offline-heuristic"


@pytest.mark.asyncio
async def test_enrichment_engine_consults_the_guard(settings_factory):
    from app.enrichment.engine import EnrichmentEngine
    from app.ioc.types import IOCType

    engine = EnrichmentEngine(
        settings_factory(enable_live_collectors=True, outbound_allowed_hosts=["feeds.example"])
    )
    result = await engine.enrich(ioc_type=IOCType.domain, value="evil.example")
    assert result["dns"]["blocked"] is True


def test_guard_allow_list_matches_host_and_subdomains():
    guard = SSRFGuard(["feeds.example"])
    assert guard.host_allowed("feeds.example") is True
    assert guard.host_allowed("sub.feeds.example") is True
    assert guard.host_allowed("evil.example") is False
    assert guard.host_allowed("notfeeds.example") is False
    # An empty allow-list means "any public host", not "none".
    assert SSRFGuard([]).host_allowed("anything.example") is True


# --- Administration ---------------------------------------------------------
# `admin:manage` gated nothing and no code path ever produced an admin, so the
# advertised role could not exist.


@pytest.mark.asyncio
async def test_admin_endpoints_require_the_admin_permission(client, viewer_headers):
    assert (await client.get("/api/v1/admin/users", headers=viewer_headers)).status_code == 403


@pytest.mark.asyncio
async def test_admin_can_list_and_change_roles(client, admin_headers):
    target = await make_user(client, email="target@example.com", password="target-strong-pw")
    listing = await client.get("/api/v1/admin/users", headers=admin_headers)
    assert listing.status_code == 200
    ids = {u["email"]: u["id"] for u in listing.json()}
    assert "target@example.com" in ids

    promoted = await client.patch(
        f"/api/v1/admin/users/{ids['target@example.com']}/role",
        headers=admin_headers,
        json={"role": "admin"},
    )
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "admin"
    assert target  # headers were issued for a real account


@pytest.mark.asyncio
async def test_an_admin_cannot_strand_the_deployment(client, admin_headers):
    listing = await client.get("/api/v1/admin/users", headers=admin_headers)
    me = next(u for u in listing.json() if u["email"] == "admin@example.com")
    demote = await client.patch(
        f"/api/v1/admin/users/{me['id']}/role", headers=admin_headers, json={"role": "viewer"}
    )
    assert demote.status_code == 422
    disable = await client.patch(
        f"/api/v1/admin/users/{me['id']}/active",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert disable.status_code == 422


@pytest.mark.asyncio
async def test_a_demotion_takes_effect_on_an_already_issued_token(client, admin_headers):
    """The role is read from the account, not from the bearer token's claim."""
    headers = await make_user(client, email="writer@example.com", password="writer-strong-pw")
    created = await client.post("/api/v1/iocs", headers=headers, json={"value": "203.0.113.7"})
    assert created.status_code == 200

    listing = await client.get("/api/v1/admin/users", headers=admin_headers)
    writer = next(u for u in listing.json() if u["email"] == "writer@example.com")
    await client.patch(
        f"/api/v1/admin/users/{writer['id']}/role", headers=admin_headers, json={"role": "viewer"}
    )
    # Same token, new role.
    denied = await client.post("/api/v1/iocs", headers=headers, json={"value": "203.0.113.8"})
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_deactivating_an_account_ends_its_session_immediately(client, admin_headers):
    headers = await make_user(client, email="gone@example.com", password="gone-strong-pw")
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200

    listing = await client.get("/api/v1/admin/users", headers=admin_headers)
    gone = next(u for u in listing.json() if u["email"] == "gone@example.com")
    await client.patch(
        f"/api/v1/admin/users/{gone['id']}/active",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401


# --- Tokens -----------------------------------------------------------------


def test_a_token_without_a_role_claim_is_rejected():
    import jwt as pyjwt
    from app.core.exceptions import InvalidTokenError
    from app.security.tokens import get_token_service

    service = get_token_service()
    forged = pyjwt.encode(
        {"sub": "u1", "type": "access", "jti": "j1", "exp": 2**31 - 1},
        service._secret,
        algorithm="HS256",
    )
    with pytest.raises(InvalidTokenError):
        service.decode(forged, expected_type="access")


# --- Dependency manifests must not drift ------------------------------------
# The image installs requirements.txt (kept for Docker layer caching) while CI
# installs pyproject.toml. Nothing enforced that they agreed, so production
# could have run a different resolution than the one the tests passed against.


def test_requirements_txt_matches_pyproject_dependencies():
    import re
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {d.strip() for d in pyproject["project"]["dependencies"]}
    pinned = {
        line.strip()
        for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert pinned == declared, (
        "requirements.txt and pyproject.toml have drifted.\n"
        f"  only in requirements.txt: {sorted(pinned - declared)}\n"
        f"  only in pyproject.toml:   {sorted(declared - pinned)}"
    )
    # Guard the regex-free assumption above: no environment markers or extras
    # syntax that would make a plain set comparison misleading.
    assert all(re.match(r"^[A-Za-z0-9_.\-]+(\[[^\]]+\])?[<>=!~]", d) for d in declared)


def test_base_image_is_pinned_by_digest():
    from pathlib import Path

    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    froms = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    assert froms, "no FROM lines found"
    for line in froms:
        assert "@sha256:" in line, f"base image is not pinned by digest: {line}"


# --- Admin bootstrap CLI ----------------------------------------------------
# The only path that can mint an administrator, so it is worth pinning: it must
# create, must promote-and-recover, and must not accept a weak password.


@pytest.mark.asyncio
async def test_create_admin_script_creates_then_promotes(db):
    from app.database.session import get_sessionmaker
    from app.repositories.user_repository import UserRepository
    from app.scripts.create_admin import _create
    from app.security.rbac import Role

    first = await _create("boss@example.com", "a-strong-admin-pw")
    assert "Created admin" in first

    async with get_sessionmaker()() as session:
        user = await UserRepository(session).get_by_email("boss@example.com")
        assert user is not None
        assert user.role == Role.admin.value
        assert user.is_active is True
        original_hash = user.password_hash

    # Re-running is the documented recovery path: promote, re-enable, reset.
    again = await _create("boss@example.com", "a-different-strong-pw")
    assert "Promoted existing account" in again
    async with get_sessionmaker()() as session:
        user = await UserRepository(session).get_by_email("boss@example.com")
        assert user.role == Role.admin.value
        assert user.password_hash != original_hash


def test_create_admin_script_refuses_a_weak_password(monkeypatch, capsys):
    from app.scripts import create_admin

    monkeypatch.setenv("TIP_ADMIN_PASSWORD", "short")
    assert create_admin.main(["--email", "x@example.com"]) == 1
    assert "at least" in capsys.readouterr().err


def test_create_admin_script_reads_the_password_from_the_environment(monkeypatch):
    from app.scripts.create_admin import _read_password

    monkeypatch.setenv("TIP_ADMIN_PASSWORD", "from-the-environment")
    assert _read_password() == "from-the-environment"


@pytest.mark.asyncio
async def test_a_token_for_a_missing_account_is_unauthenticated_not_missing(client, db):
    """A valid signature over a subject that no longer exists is a 401.

    The principal is resolved by loading the account, so the lookup can miss.
    Letting that surface as the repository's 404 would point the caller at the
    wrong problem and turn the endpoint into a probe for which subject ids are
    real.
    """
    from app.security.tokens import get_token_service

    pair = get_token_service().issue_pair(subject="no-such-user", role="analyst")
    r = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {pair.access_token}"}
    )
    assert r.status_code == 401
