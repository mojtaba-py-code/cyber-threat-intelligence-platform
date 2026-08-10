"""Tests for the circuit breaker and retry helper."""

from __future__ import annotations

import pytest
from app.core.exceptions import CircuitOpenError
from app.core.resilience import (
    CircuitBreaker,
    CircuitState,
    async_retry,
    get_circuit_breaker,
    reset_circuit_breakers,
)


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


async def _boom():
    raise ValueError("boom")


async def _ok():
    return "ok"


@pytest.mark.asyncio
async def test_circuit_opens_and_recovers():
    clock = _Clock()
    cb = CircuitBreaker(name="t", failure_threshold=2, recovery_timeout=5, clock=clock)
    for _ in range(2):
        with pytest.raises(ValueError):
            await cb.call(_boom)
    assert cb.state is CircuitState.open
    with pytest.raises(CircuitOpenError):
        await cb.call(_ok)
    clock.t = 6
    assert await cb.call(_ok) == "ok"
    assert cb.state is CircuitState.closed


@pytest.mark.asyncio
async def test_retry_succeeds_then_exhausts():
    calls = {"n": 0}

    async def _sleep(_s):
        return None

    @async_retry(attempts=3, sleep=_sleep)
    async def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("transient")
        return "done"

    assert await flaky() == "done"

    @async_retry(attempts=2, sleep=_sleep)
    async def always_fail():
        raise ValueError("permanent")

    with pytest.raises(ValueError):
        await always_fail()


def test_shared_breaker_registry():
    reset_circuit_breakers()
    a = get_circuit_breaker("collector:x")
    assert a is get_circuit_breaker("collector:x")
    assert a is not get_circuit_breaker("collector:y")
    reset_circuit_breakers()
