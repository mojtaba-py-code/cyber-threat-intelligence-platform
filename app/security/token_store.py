"""Revocation store for JWT identifiers (``jti``) — refresh rotation & logout.

Two backends implement the same async interface: an in-process default and a
Redis-backed variant for multiple replicas. Only opaque identifiers and
expiries are stored, never token contents.
"""

from __future__ import annotations

import functools
import time
from abc import ABC, abstractmethod
from collections.abc import Callable

from app.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)
_PREFIX = "revoked_jti:"


class TokenStore(ABC):
    @abstractmethod
    async def revoke(self, jti: str, *, ttl_seconds: int) -> None: ...

    @abstractmethod
    async def is_revoked(self, jti: str) -> bool: ...


class InMemoryTokenStore(TokenStore):
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._revoked: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        for jti in [j for j, exp in self._revoked.items() if exp <= now]:
            del self._revoked[jti]

    async def revoke(self, jti: str, *, ttl_seconds: int) -> None:
        now = self._clock()
        self._prune(now)
        self._revoked[jti] = now + max(ttl_seconds, 1)

    async def is_revoked(self, jti: str) -> bool:
        now = self._clock()
        exp = self._revoked.get(jti)
        if exp is None:
            return False
        if exp <= now:
            del self._revoked[jti]
            return False
        return True


class RedisTokenStore(TokenStore):
    def __init__(self, redis_url: str) -> None:
        import redis.asyncio as redis

        self._redis = redis.from_url(redis_url, decode_responses=True)

    async def revoke(self, jti: str, *, ttl_seconds: int) -> None:
        await self._redis.set(_PREFIX + jti, "1", ex=max(ttl_seconds, 1))

    async def is_revoked(self, jti: str) -> bool:
        return bool(await self._redis.exists(_PREFIX + jti))


@functools.lru_cache(maxsize=1)
def get_token_store() -> TokenStore:
    settings = get_settings()
    # Reuse the Redis URL in production; in-memory otherwise (dev/test).
    if settings.is_production:
        try:
            return RedisTokenStore(settings.redis_url)
        except Exception as exc:  # noqa: BLE001
            log.warning("redis_token_store_unavailable", error=str(exc))
    return InMemoryTokenStore()
