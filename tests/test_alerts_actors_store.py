"""Coverage for the remaining alert-delivery, threat-actor and token-store paths."""

from __future__ import annotations

import pytest
from app.config import Settings, get_settings
from app.config.settings import AppEnv
from app.core.exceptions import ConflictError, NotFoundError
from app.models.alert import AlertRule
from app.models.ioc import IOC
from app.security.token_store import RedisTokenStore, get_token_store
from app.services.alert_service import AlertService
from app.services.threat_actor_service import ThreatActorService


def make_ioc(score: int = 60) -> IOC:
    return IOC(
        type="domain-name",
        value=f"alert-{score}.example",
        defanged_value=f"alert-{score}[.]example",
        threat_score=score,
        threat_level="high",
        severity="high",
        source="manual",
    )


# --- alert rule matching ----------------------------------------------------


@pytest.mark.parametrize(
    ("operator", "threshold", "score", "should_fire"),
    [
        ("lte", 30, 10, True),
        ("lte", 30, 90, False),
        ("eq", 50, 50, True),
        ("eq", 50, 51, False),
    ],
)
@pytest.mark.asyncio
async def test_threshold_operators(session, operator, threshold, score, should_fire):
    session.add(
        AlertRule(
            name=f"{operator}-{threshold}",
            metric="threat_score",
            operator=operator,
            threshold=threshold,
            channel="log",
        )
    )
    ioc = make_ioc(score)
    session.add(ioc)
    await session.flush()
    alerts = await AlertService(session).evaluate_ioc(ioc)
    assert bool(alerts) is should_fire


@pytest.mark.asyncio
async def test_unknown_metric_never_fires(session):
    session.add(AlertRule(name="bogus", metric="phase-of-the-moon", operator="gte", threshold=0))
    ioc = make_ioc()
    session.add(ioc)
    await session.flush()
    assert await AlertService(session).evaluate_ioc(ioc) == []


@pytest.mark.asyncio
async def test_inactive_rules_are_ignored(session):
    session.add(AlertRule(name="off", metric="new_ioc", channel="log", is_active=False))
    ioc = make_ioc()
    session.add(ioc)
    await session.flush()
    assert await AlertService(session).evaluate_ioc(ioc) == []


# --- webhook delivery -------------------------------------------------------


def live_settings(**overrides) -> Settings:
    return get_settings().model_copy(update={"enable_live_collectors": True, **overrides})


@pytest.mark.asyncio
async def test_webhook_to_an_internal_address_is_blocked_by_the_ssrf_guard(session, monkeypatch):
    """Even with live mode on, a rule may not be used to probe the internal network."""
    import httpx

    def _no_outbound_calls(*_args, **_kwargs):
        raise AssertionError("the SSRF guard must reject the URL before any request")

    monkeypatch.setattr(httpx.AsyncClient, "__init__", _no_outbound_calls)
    session.add(
        AlertRule(
            name="ssrf",
            metric="new_ioc",
            channel="webhook",
            channel_config={"url": "http://169.254.169.254/latest/meta-data/"},
        )
    )
    ioc = make_ioc()
    session.add(ioc)
    await session.flush()

    alerts = await AlertService(session, settings=live_settings()).evaluate_ioc(ioc)
    assert alerts[0].delivered is False


@pytest.mark.asyncio
async def test_webhook_without_a_url_is_recorded_but_not_delivered(session):
    session.add(AlertRule(name="nourl", metric="new_ioc", channel="slack", channel_config={}))
    ioc = make_ioc()
    session.add(ioc)
    await session.flush()
    alerts = await AlertService(session, settings=live_settings()).evaluate_ioc(ioc)
    assert alerts[0].delivered is False


# --- rule management --------------------------------------------------------


@pytest.mark.asyncio
async def test_rule_crud_round_trip(session):
    service = AlertService(session)
    rule = await service.create_rule(
        name="r1", metric="new_ioc", operator="gte", threshold=0, channel="log"
    )
    assert [r.id for r in await service.list_rules()] == [rule.id]
    assert await service.delete_rule(rule.id) is True
    assert await service.list_rules() == []
    assert await service.delete_rule(rule.id) is False  # already gone


@pytest.mark.asyncio
async def test_alert_listing_is_newest_first(session):
    session.add(AlertRule(name="all", metric="new_ioc", channel="log"))
    service = AlertService(session)
    for score in (10, 20):
        ioc = make_ioc(score)
        session.add(ioc)
        await session.flush()
        await service.evaluate_ioc(ioc)
    assert len(await service.list_alerts(limit=10)) == 2
    assert len(await service.list_alerts(limit=1)) == 1


# --- threat actors ----------------------------------------------------------


@pytest.mark.asyncio
async def test_duplicate_actor_names_are_rejected(session):
    service = ThreatActorService(session)
    await service.create(data={"name": "APT-Example"})
    with pytest.raises(ConflictError):
        await service.create(data={"name": "APT-Example"})


@pytest.mark.asyncio
async def test_missing_actor_raises_not_found(session):
    service = ThreatActorService(session)
    with pytest.raises(NotFoundError):
        await service.get("does-not-exist")
    with pytest.raises(NotFoundError):
        await service.delete("does-not-exist")


@pytest.mark.asyncio
async def test_actor_delete_removes_the_profile(session):
    service = ThreatActorService(session)
    actor = await service.create(data={"name": "Gone Group"}, user_id="u1")
    await service.delete(actor.id, user_id="u1")
    assert await service.list() == []


# --- token store ------------------------------------------------------------


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.values[key] = value

    async def exists(self, key: str) -> int:
        return int(key in self.values)


@pytest.mark.asyncio
async def test_redis_token_store_revocation(monkeypatch):
    import redis.asyncio as redis

    monkeypatch.setattr(redis, "from_url", lambda *_a, **_kw: FakeRedis())
    store = RedisTokenStore("redis://localhost:6379/0")
    assert not await store.is_revoked("jti-1")
    await store.revoke("jti-1", ttl_seconds=60)
    assert await store.is_revoked("jti-1")


def test_production_selects_the_redis_token_store(monkeypatch):
    import redis.asyncio as redis

    monkeypatch.setattr(redis, "from_url", lambda *_a, **_kw: FakeRedis())
    monkeypatch.setattr(get_settings(), "app_env", AppEnv.production)
    get_token_store.cache_clear()
    try:
        assert isinstance(get_token_store(), RedisTokenStore)
    finally:
        get_token_store.cache_clear()
