"""Async HTTP client for collectors, guarded by a per-source circuit breaker.

Used for calls to **fixed, trusted provider API hosts** (AbuseIPDB, URLHaus, …),
so no SSRF guard is required here — that guard applies only to user-supplied
destinations (see :mod:`app.core.ssrf`). Timeouts, retry and a circuit breaker
keep a flaky provider from stalling the platform.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.core.exceptions import CollectorError, CollectorUnavailableError
from app.core.resilience import async_retry, get_circuit_breaker

_DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class ProviderHttpClient:
    def __init__(self, provider: str, *, timeout: httpx.Timeout | None = None) -> None:
        self._provider = provider
        self._timeout = timeout or _DEFAULT_TIMEOUT
        self._breaker = get_circuit_breaker(f"collector:{provider}")

    async def get_json(
        self, url: str, *, headers: dict[str, str] | None = None, params: dict | None = None
    ) -> Any:
        async def _do() -> Any:
            @async_retry(attempts=3, exceptions=(httpx.TransportError,))
            async def _request() -> httpx.Response:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    return await client.get(url, headers=headers, params=params)

            try:
                resp = await _request()
            except httpx.TransportError as exc:
                raise CollectorUnavailableError(
                    f"{self._provider} is unreachable: {exc}", details={"provider": self._provider}
                ) from exc
            if resp.status_code >= 500:
                raise CollectorUnavailableError(
                    f"{self._provider} returned {resp.status_code}",
                    details={"provider": self._provider},
                )
            if resp.status_code >= 400:
                raise CollectorError(
                    f"{self._provider} returned {resp.status_code}",
                    details={"provider": self._provider, "status": resp.status_code},
                )
            return resp.json()

        return await self._breaker.call(_do)
