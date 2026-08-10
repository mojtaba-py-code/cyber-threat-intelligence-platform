"""Tests for the distributed (Redis-backed) login throttle.

A fake Redis stands in for the real one: the point under test is our lockout
logic and its failure behaviour, not the client library.
"""

from __future__ import annotations

import pytest
from app.config import get_settings
from app.config.settings import AppEnv
from app.security.throttle import (
    InMemoryLoginThrottle,
    RedisLoginThrottle,
    get_login_throttle,
)


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}
        self.ttls: dict[str, int] = {}

    async def exists(self, key: str) -> int:
        return int(key in self.values)

    async def incr(self, key: str) -> int:
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.ttls[key] = seconds

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.values[key] = 1
        if ex is not None:
            self.ttls[key] = ex

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -2)

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self.values.pop(key, None)
            self.ttls.pop(key, None)


class BrokenRedis:
    """Every call fails, as during a cache outage."""

    def __getattr__(self, _name):
        async def _fail(*_args, **_kwargs):
            raise ConnectionError("redis is down")

        return _fail


@pytest.fixture
def fake_redis(monkeypatch) -> FakeRedis:
    import redis.asyncio as redis

    fake = FakeRedis()
    monkeypatch.setattr(redis, "from_url", lambda *_a, **_kw: fake)
    return fake


def make_throttle(**kwargs) -> RedisLoginThrottle:
    return RedisLoginThrottle("redis://localhost:6379/0", **kwargs)


@pytest.mark.asyncio
async def test_lockout_trips_after_the_configured_attempts(fake_redis):
    throttle = make_throttle(max_attempts=3, lockout_seconds=120)
    for _ in range(2):
        await throttle.record_failure("a@b.com")
    assert not await throttle.is_locked("a@b.com")

    await throttle.record_failure("a@b.com")
    assert await throttle.is_locked("a@b.com")
    assert await throttle.retry_after("a@b.com") == 120


@pytest.mark.asyncio
async def test_the_failure_window_expires_so_counts_do_not_live_forever(fake_redis):
    throttle = make_throttle(max_attempts=5, lockout_seconds=300)
    await throttle.record_failure("a@b.com")
    assert fake_redis.ttls["login_fail:a@b.com"] == 300


@pytest.mark.asyncio
async def test_identities_are_normalised_across_replicas(fake_redis):
    throttle = make_throttle(max_attempts=2, lockout_seconds=60)
    await throttle.record_failure(" A@B.com ")
    await throttle.record_failure("a@b.COM")
    assert await throttle.is_locked("A@B.com")


@pytest.mark.asyncio
async def test_a_successful_login_clears_the_lock(fake_redis):
    throttle = make_throttle(max_attempts=1, lockout_seconds=60)
    await throttle.record_failure("a@b.com")
    assert await throttle.is_locked("a@b.com")
    await throttle.record_success("a@b.com")
    assert not await throttle.is_locked("a@b.com")
    assert await throttle.retry_after("a@b.com") == 0
    assert fake_redis.values == {}


@pytest.mark.asyncio
async def test_an_unknown_identity_has_no_lockout(fake_redis):
    throttle = make_throttle()
    assert not await throttle.is_locked("nobody@example.com")
    # Redis returns -2 for a missing key; that must not surface as a negative wait.
    assert await throttle.retry_after("nobody@example.com") == 0


@pytest.mark.asyncio
async def test_a_redis_outage_fails_open_rather_than_locking_everyone_out(monkeypatch):
    import redis.asyncio as redis

    monkeypatch.setattr(redis, "from_url", lambda *_a, **_kw: BrokenRedis())
    throttle = make_throttle()

    # None of these may raise: an unreachable cache must not deny every login.
    await throttle.record_failure("a@b.com")
    await throttle.record_success("a@b.com")
    assert not await throttle.is_locked("a@b.com")
    assert await throttle.retry_after("a@b.com") == 0


def test_production_selects_the_distributed_backend(monkeypatch, fake_redis):
    get_login_throttle.cache_clear()
    monkeypatch.setattr(get_settings(), "app_env", AppEnv.production)
    try:
        assert isinstance(get_login_throttle(), RedisLoginThrottle)
    finally:
        get_login_throttle.cache_clear()


def test_development_stays_in_process():
    get_login_throttle.cache_clear()
    try:
        assert isinstance(get_login_throttle(), InMemoryLoginThrottle)
    finally:
        get_login_throttle.cache_clear()
