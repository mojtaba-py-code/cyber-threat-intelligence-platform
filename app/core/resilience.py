"""Resilience primitives: a circuit breaker and retry helper.

Outbound calls to threat-intelligence sources are unreliable — they rate limit,
time out, or go down. These utilities keep a misbehaving source from taking down
the platform.
"""

from __future__ import annotations

import asyncio
import functools
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ParamSpec, TypeVar

from app.core.exceptions import CircuitOpenError
from app.core.logging import get_logger

log = get_logger(__name__)

P = ParamSpec("P")
T = TypeVar("T")


class CircuitState(StrEnum):
    closed = "closed"
    open = "open"
    half_open = "half_open"


@dataclass
class CircuitBreaker:
    """A minimal async circuit breaker with an injectable monotonic clock."""

    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    clock: Callable[[], float] = field(default=time.monotonic)

    _state: CircuitState = field(default=CircuitState.closed, init=False)
    _failures: int = field(default=0, init=False)
    _opened_at: float = field(default=0.0, init=False)
    _probe_in_flight: bool = field(default=False, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    @property
    def state(self) -> CircuitState:
        return self._state

    def _can_attempt(self) -> bool:
        if self._state is CircuitState.closed:
            return True
        if self._state is CircuitState.open:
            if self.clock() - self._opened_at >= self.recovery_timeout:
                self._state = CircuitState.half_open
                self._probe_in_flight = True
                return True
            return False
        if self._probe_in_flight:
            return False
        self._probe_in_flight = True
        return True

    def record_success(self) -> None:
        self._failures = 0
        self._state = CircuitState.closed
        self._probe_in_flight = False

    def record_failure(self) -> None:
        self._failures += 1
        self._probe_in_flight = False
        if self._state is CircuitState.half_open or self._failures >= self.failure_threshold:
            self._state = CircuitState.open
            self._opened_at = self.clock()
            log.warning("circuit_opened", circuit=self.name, failures=self._failures)

    async def call(self, func: Callable[P, Awaitable[T]], *args: P.args, **kwargs: P.kwargs) -> T:
        async with self._lock:
            if not self._can_attempt():
                raise CircuitOpenError(details={"circuit": self.name})
        try:
            result = await func(*args, **kwargs)
        except Exception:
            async with self._lock:
                self.record_failure()
            raise
        else:
            async with self._lock:
                self.record_success()
            return result


_breakers: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    name: str, *, failure_threshold: int = 5, recovery_timeout: float = 30.0
) -> CircuitBreaker:
    breaker = _breakers.get(name)
    if breaker is None:
        breaker = CircuitBreaker(
            name=name, failure_threshold=failure_threshold, recovery_timeout=recovery_timeout
        )
        _breakers[name] = breaker
    return breaker


def reset_circuit_breakers() -> None:
    _breakers.clear()


def async_retry(
    *,
    attempts: int = 3,
    base_delay: float = 0.2,
    max_delay: float = 5.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Retry an async callable with exponential backoff (injectable sleep)."""

    def decorator(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            delay = base_delay
            last_exc: Exception | None = None
            for attempt in range(1, attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as exc:  # noqa: PERF203
                    last_exc = exc
                    if attempt == attempts:
                        break
                    await sleep(min(delay, max_delay))
                    delay *= 2
            assert last_exc is not None
            raise last_exc

        return wrapper

    return decorator
