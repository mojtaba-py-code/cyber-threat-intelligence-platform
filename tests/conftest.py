"""Shared pytest fixtures.

Environment is configured before any application module is imported so cached
settings pick up the test database and deterministic keys.
"""

from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("APP_DEBUG", "false")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("MASTER_ENCRYPTION_KEY", "0FwqA3vE8m2K4rN6sT9uW1xZ3bD5gH7jK9mP1qS4uV8=")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-that-is-long-enough-1234567890")
os.environ.setdefault("ENABLE_LIVE_COLLECTORS", "false")

from collections.abc import AsyncIterator  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from app.core.events import get_event_bus  # noqa: E402
from app.database.session import get_sessionmaker, init_models, reset_engine  # noqa: E402
from app.main import create_app  # noqa: E402
from app.security.throttle import get_login_throttle  # noqa: E402
from app.security.token_store import get_token_store  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402


@pytest_asyncio.fixture
async def db() -> AsyncIterator[None]:
    await reset_engine()
    await init_models()
    get_login_throttle.cache_clear()
    get_token_store.cache_clear()
    get_event_bus.cache_clear()  # no subscribers may leak between tests
    yield
    await reset_engine()


@pytest_asyncio.fixture
async def session(db) -> AsyncIterator:
    maker = get_sessionmaker()
    async with maker() as s:
        yield s


@pytest_asyncio.fixture
async def client(db) -> AsyncIterator[AsyncClient]:
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def register_payload() -> dict:
    return {"email": "analyst@example.com", "password": "analyst-strong-pw"}
