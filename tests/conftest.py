"""Shared pytest fixtures.

Environment is configured before any application module is imported so cached
settings pick up the test database and keys. The encryption key is minted per
run rather than committed: a hard-coded Fernet key is indistinguishable from a
leaked one, both to a reader and to a secret scanner.
"""

from __future__ import annotations

import os

from cryptography.fernet import Fernet

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("APP_DEBUG", "false")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("MASTER_ENCRYPTION_KEY", Fernet.generate_key().decode())
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-that-is-long-enough-1234567890")
os.environ.setdefault("ENABLE_LIVE_COLLECTORS", "false")

from collections.abc import AsyncIterator  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from app.config.settings import Settings  # noqa: E402
from app.core.events import get_event_bus  # noqa: E402
from app.database.session import get_sessionmaker, init_models, reset_engine  # noqa: E402
from app.main import create_app  # noqa: E402
from app.repositories.user_repository import UserRepository  # noqa: E402
from app.security.rbac import Role  # noqa: E402
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


async def make_user(client, *, email: str, password: str, role: Role | None = None) -> dict:
    """Register a real account, optionally set its role, return auth headers.

    A principal's role is read from its row on every request, so a token minted
    for an id that was never persisted is not a valid principal any more. Tests
    that need a particular role therefore create the account rather than forging
    a claim. ``role=None`` keeps whatever registration hands out.
    """
    await client.post("/api/v1/auth/register", json={"email": email, "password": password})
    if role is not None:
        maker = get_sessionmaker()
        async with maker() as s:
            user = await UserRepository(s).get_by_email(email)
            assert user is not None
            user.role = role.value
            await s.commit()
    tokens = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    return {"Authorization": f"Bearer {tokens.json()['access_token']}"}


@pytest.fixture
def settings_factory():
    """Build a Settings object without reading the developer's .env file."""

    def _make(**overrides):
        return Settings(_env_file=None, **overrides)

    return _make


@pytest_asyncio.fixture
async def viewer_headers(client) -> dict:
    """Auth headers for a persisted account holding the read-only role."""
    return await make_user(
        client, email="viewer@example.com", password="viewer-strong-pw", role=Role.viewer
    )


@pytest_asyncio.fixture
async def admin_headers(client) -> dict:
    """Auth headers for a persisted account holding the admin role."""
    return await make_user(
        client, email="admin@example.com", password="admin-strong-pw", role=Role.admin
    )
