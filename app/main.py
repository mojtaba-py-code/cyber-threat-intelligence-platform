"""FastAPI application factory."""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app import __version__
from app.api.client_ip import ProxyTrust
from app.api.errors import register_exception_handlers
from app.api.middleware import InMemoryRateLimiter, RequestContextMiddleware
from app.api.v1.router import api_router
from app.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.database.session import init_models, reset_engine

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.validate_runtime()
    if not settings.is_production:
        await init_models()
    log.info(
        "application_startup",
        env=str(settings.app_env),
        live_collectors=settings.enable_live_collectors,
        version=__version__,
    )
    try:
        yield
    finally:
        await reset_engine()
        log.info("application_shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(
        level="DEBUG" if settings.app_debug else "INFO", json_output=settings.is_production
    )

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Cyber Security Threat Intelligence Platform — collect, enrich, score, "
            "correlate and visualise cyber threat intelligence. Collectors are "
            "offline-first (bundled sample intelligence) until an operator enables "
            "live collection."
        ),
        lifespan=lifespan,
        # Interactive docs are a map of the API; production serves them only if
        # the operator opts in explicitly.
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )

    # Starlette runs the last-added middleware outermost, so the effective order
    # is RequestContext -> CORS -> RateLimiter. CORS deliberately sits outside
    # the limiter: a rejected request still needs its CORS headers, or a browser
    # reports an opaque network failure instead of the 429 it was actually sent.
    # Cheap preflights therefore skip the app limiter; nginx's limit_req covers
    # them at the edge.
    app.add_middleware(
        InMemoryRateLimiter,
        limit_per_minute=settings.rate_limit_per_minute,
        proxy_trust=ProxyTrust(settings.trusted_proxy_cidrs),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestContextMiddleware)

    register_exception_handlers(app)
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    dashboard_template = (Path(__file__).parent / "web" / "dashboard.html").read_text(
        encoding="utf-8"
    )

    @app.get("/", include_in_schema=False)
    async def root() -> dict:
        # Only advertise the interactive docs when they are actually served —
        # in production they are not, and pointing a client at a 404 is worse
        # than saying nothing.
        body = {
            "name": settings.app_name,
            "version": __version__,
            "dashboard": "/dashboard",
            "health": f"{settings.api_v1_prefix}/health",
        }
        if settings.docs_enabled:
            body["docs"] = "/docs"
        return body

    @app.get("/dashboard", include_in_schema=False)
    async def dashboard() -> HTMLResponse:
        # The dashboard is one self-contained file, so its script and style
        # blocks are inline. Rather than weaken the policy with 'unsafe-inline'
        # — which would also re-enable any injected script — each response
        # carries a fresh nonce that only these two blocks bear.
        nonce = secrets.token_urlsafe(16)
        return HTMLResponse(
            dashboard_template.replace("{{nonce}}", nonce),
            headers={
                "Content-Security-Policy": (
                    f"default-src 'self'; script-src 'nonce-{nonce}'; "
                    f"style-src 'nonce-{nonce}'; img-src 'self' data:; "
                    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                    "form-action 'none'"
                )
            },
        )

    return app


app = create_app()
