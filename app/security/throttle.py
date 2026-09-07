"""Per-identity brute-force throttling for authentication.

Two backends share one async interface, mirroring
:mod:`app.security.token_store`: an in-process default for single-instance and
test runs, and a Redis-backed variant so that a lockout applies across every API
replica — otherwise an attacker simply spreads attempts over the fleet and the
per-process counter never trips.

Only a normalised identity and its failure count are stored, never a password.
"""

from __future__ import annotations

import functools
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field

from app.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

_FAILURE_PREFIX = "login_fail:"
_LOCK_PREFIX = "login_lock:"


class LoginThrottle(ABC):
    """Records authentication failures and locks an identity out."""

    max_attempts: int
    lockout_seconds: int

    @abstractmethod
    async def is_locked(self, identity: str) -> bool: ...

    @abstractmethod
    async def retry_after(self, identity: str) -> int: ...

    @abstractmethod
    async def record_failure(self, identity: str) -> None: ...

    @abstractmethod
    async def record_success(self, identity: str) -> None: ...

    @staticmethod
    def normalise(identity: str) -> str:
        return identity.strip().lower()


@dataclass
class _Entry:
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class InMemoryLoginThrottle(LoginThrottle):
    max_attempts: int = 5
    lockout_seconds: int = 300
    clock: Callable[[], float] = field(default=time.monotonic)
    _entries: dict[str, _Entry] = field(default_factory=dict, init=False)

    async def is_locked(self, identity: str) -> bool:
        key = self.normalise(identity)
        entry = self._entries.get(key)
        if entry is None or not entry.locked_until:
            return False
        if self.clock() < entry.locked_until:
            return True
        self._entries.pop(key, None)  # lockout elapsed; forgive the failures
        return False

    async def retry_after(self, identity: str) -> int:
        entry = self._entries.get(self.normalise(identity))
        if entry is None or not entry.locked_until:
            return 0
        return max(0, int(entry.locked_until - self.clock()))

    async def record_failure(self, identity: str) -> None:
        entry = self._entries.setdefault(self.normalise(identity), _Entry())
        entry.failures += 1
        if entry.failures >= self.max_attempts:
            entry.locked_until = self.clock() + self.lockout_seconds

    async def record_success(self, identity: str) -> None:
        self._entries.pop(self.normalise(identity), None)


class RedisLoginThrottle(LoginThrottle):
    """Fleet-wide lockout backed by Redis counters with a TTL.

    A Redis outage must not lock every user out of the platform, so no call
    here raises. It must not *unlock* the platform either: an earlier version
    reported "not locked" whenever Redis was unreachable, which turned a cache
    outage into an open door for password guessing. Every operation therefore
    degrades onto an in-process throttle instead — protection narrows from
    fleet-wide to per-replica, which is what the single-instance default gives
    anyway, rather than disappearing.
    """

    def __init__(
        self, redis_url: str, *, max_attempts: int = 5, lockout_seconds: int = 300
    ) -> None:
        import redis.asyncio as redis

        self._redis = redis.from_url(redis_url, decode_responses=True)
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._fallback = InMemoryLoginThrottle(
            max_attempts=max_attempts, lockout_seconds=lockout_seconds
        )

    def _degraded(self, exc: Exception) -> None:
        log.warning("throttle_backend_unavailable", error=str(exc), fallback="in-process")

    async def is_locked(self, identity: str) -> bool:
        try:
            if bool(await self._redis.exists(_LOCK_PREFIX + self.normalise(identity))):
                return True
        except Exception as exc:  # noqa: BLE001 - fall back, never fail open
            self._degraded(exc)
        return await self._fallback.is_locked(identity)

    async def retry_after(self, identity: str) -> int:
        try:
            ttl = int(await self._redis.ttl(_LOCK_PREFIX + self.normalise(identity)))
            if ttl > 0:
                return ttl
        except Exception as exc:  # noqa: BLE001
            self._degraded(exc)
        return await self._fallback.retry_after(identity)

    async def record_failure(self, identity: str) -> None:
        # Recorded locally as well as in Redis: if Redis drops out midway
        # through an attack the local counter has the earlier attempts and can
        # still trip, instead of restarting from zero.
        await self._fallback.record_failure(identity)
        key = self.normalise(identity)
        try:
            failures = await self._redis.incr(_FAILURE_PREFIX + key)
            # Expire the window on first failure so counts do not live forever.
            if failures == 1:
                await self._redis.expire(_FAILURE_PREFIX + key, self.lockout_seconds)
            if failures >= self.max_attempts:
                await self._redis.set(_LOCK_PREFIX + key, "1", ex=self.lockout_seconds)
        except Exception as exc:  # noqa: BLE001 - a lost failure count is not fatal
            self._degraded(exc)

    async def record_success(self, identity: str) -> None:
        await self._fallback.record_success(identity)
        key = self.normalise(identity)
        try:
            await self._redis.delete(_FAILURE_PREFIX + key, _LOCK_PREFIX + key)
        except Exception as exc:  # noqa: BLE001
            self._degraded(exc)


@functools.lru_cache(maxsize=1)
def get_login_throttle() -> LoginThrottle:
    settings = get_settings()
    if settings.is_production:
        try:
            return RedisLoginThrottle(settings.redis_url)
        except Exception as exc:  # noqa: BLE001
            log.warning("redis_throttle_unavailable", error=str(exc))
    return InMemoryLoginThrottle()
