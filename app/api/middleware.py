"""Custom ASGI middleware: request IDs, security headers, and rate limiting."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.api.client_ip import ProxyTrust
from app.core.exceptions import RateLimitError

log = structlog.get_logger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(
            request_id=request_id, path=request.url.path, method=request.method
        )
        start = time.monotonic()
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()
        response.headers["x-request-id"] = request_id
        response.headers["x-response-time-ms"] = str(round((time.monotonic() - start) * 1000, 2))
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
        _apply_security_headers(response, secure=(forwarded_proto or request.url.scheme) == "https")
        return response


def _apply_security_headers(response: Response, *, secure: bool) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"
    )
    # HSTS is meaningless — and ignored — on a plain-HTTP response, so it is
    # only sent when the request actually arrived over TLS. Behind the proxy
    # that is what X-Forwarded-Proto reports.
    if secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )


class InMemoryRateLimiter(BaseHTTPMiddleware):
    """Sliding per-IP rate limiter, counted per process.

    This is the application's own backstop, not the deployment's rate limit:
    with several API replicas each keeps its own window, so the effective limit
    multiplies by the replica count. The edge limit that actually bounds a
    caller is nginx's ``limit_req`` in ``deploy/nginx.conf``, which sees every
    request regardless of which replica serves it.
    """

    def __init__(
        self, app, *, limit_per_minute: int = 120, proxy_trust: ProxyTrust | None = None
    ) -> None:
        super().__init__(app)
        self._limit = limit_per_minute
        self._window = 60.0
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._last_sweep = 0.0
        # Liveness and readiness only: an orchestrator polls them far more often
        # than the limit allows. Nothing else is exempt — an exemption for a
        # path that does not exist becomes an unmetered hole the day someone
        # adds it.
        self._exempt = {"/api/v1/health", "/api/v1/ready"}
        self._proxy_trust = proxy_trust or ProxyTrust()

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self._exempt:
            return await call_next(request)
        client = self._proxy_trust.client_ip(request) or "unknown"
        now = time.monotonic()
        bucket = self._hits[client]
        while bucket and now - bucket[0] > self._window:
            bucket.popleft()
        if len(bucket) >= self._limit:
            err = RateLimitError()
            retry_after = max(0, int(self._window - (now - bucket[0]))) if bucket else 60
            return JSONResponse(
                err.to_dict(),
                status_code=err.status_code,
                headers={"Retry-After": str(retry_after)},
            )
        bucket.append(now)
        self._maybe_sweep(now)
        return await call_next(request)

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep < self._window:
            return
        self._last_sweep = now
        stale = [ip for ip, hits in self._hits.items() if not hits or now - hits[-1] > self._window]
        for ip in stale:
            del self._hits[ip]
