"""FastAPI dependency-injection wiring.

Constructs repositories and services per request from the request-scoped
session. Authentication accepts either a JWT bearer token **or** an ``X-API-Key``
header, both resolving to a :class:`CurrentPrincipal` with a role that RBAC
checks against.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.client_ip import ProxyTrust
from app.config import get_settings
from app.core.exceptions import AuthenticationError, PermissionDeniedError
from app.database.session import get_session
from app.enrichment.engine import EnrichmentEngine, get_enrichment_engine
from app.repositories.api_key_repository import ApiKeyRepository
from app.repositories.audit_repository import AuditRepository
from app.repositories.correlation_repository import CorrelationRepository
from app.repositories.enrichment_repository import EnrichmentRepository
from app.repositories.ioc_repository import IOCRepository
from app.repositories.user_repository import UserRepository
from app.security.crypto import PasswordHasher, get_password_hasher
from app.security.rbac import Permission, has_permission
from app.security.throttle import LoginThrottle, get_login_throttle
from app.security.token_store import TokenStore, get_token_store
from app.security.tokens import TokenService, get_token_service
from app.services.alert_service import AlertService
from app.services.auth_service import AuthService
from app.services.correlation_service import CorrelationService
from app.services.ioc_service import IOCService

SessionDep = Annotated[AsyncSession, Depends(get_session)]

_bearer = HTTPBearer(auto_error=False)


def get_hasher() -> PasswordHasher:
    return get_password_hasher()


def get_tokens() -> TokenService:
    return get_token_service()


def get_tokstore() -> TokenStore:
    return get_token_store()


def get_throttle() -> LoginThrottle:
    return get_login_throttle()


def get_engine_dep() -> EnrichmentEngine:
    return get_enrichment_engine()


# --- Service factories -----------------------------------------------------


def get_auth_service(
    session: SessionDep,
    hasher: Annotated[PasswordHasher, Depends(get_hasher)],
    tokens: Annotated[TokenService, Depends(get_tokens)],
    token_store: Annotated[TokenStore, Depends(get_tokstore)],
    throttle: Annotated[LoginThrottle, Depends(get_throttle)],
) -> AuthService:
    return AuthService(
        users=UserRepository(session),
        api_keys=ApiKeyRepository(session),
        audit=AuditRepository(session),
        hasher=hasher,
        tokens=tokens,
        token_store=token_store,
        throttle=throttle,
    )


def get_alert_service(session: SessionDep) -> AlertService:
    return AlertService(session)


def get_ioc_service(
    session: SessionDep,
    engine: Annotated[EnrichmentEngine, Depends(get_engine_dep)],
) -> IOCService:
    return IOCService(
        iocs=IOCRepository(session),
        enrichments=EnrichmentRepository(session),
        engine=engine,
        audit=AuditRepository(session),
        correlation=CorrelationRepository(session),
        alerts=AlertService(session),
    )


def get_correlation_service(session: SessionDep) -> CorrelationService:
    return CorrelationService(
        correlation=CorrelationRepository(session), audit=AuditRepository(session)
    )


# --- Authentication --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CurrentPrincipal:
    id: str
    role: str
    kind: str  # "user" | "api_key"


async def get_current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
    tokens: Annotated[TokenService, Depends(get_tokens)],
    token_store: Annotated[TokenStore, Depends(get_tokstore)],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> CurrentPrincipal:
    if credentials is not None:
        claims = tokens.decode(credentials.credentials, expected_type="access")
        # Honour revocation (logout / "log out everywhere") for access tokens too.
        if await token_store.is_revoked(claims.jti):
            raise AuthenticationError("Token has been revoked.")
        return CurrentPrincipal(id=claims.subject, role=claims.role, kind="user")
    if x_api_key:
        record = await auth.resolve_api_key(x_api_key)
        return CurrentPrincipal(id=record.user_id, role=record.role, kind="api_key")
    raise AuthenticationError("Authentication required (bearer token or X-API-Key).")


CurrentPrincipalDep = Annotated[CurrentPrincipal, Depends(get_current_principal)]


def require(permission: Permission):
    async def _dep(principal: CurrentPrincipalDep) -> CurrentPrincipal:
        if not has_permission(principal.role, permission):
            raise PermissionDeniedError(
                f"Role '{principal.role}' lacks permission '{permission.value}'."
            )
        return principal

    return _dep


@functools.lru_cache(maxsize=1)
def get_proxy_trust() -> ProxyTrust:
    return ProxyTrust(get_settings().trusted_proxy_cidrs)


def client_ip(request: Request) -> str | None:
    """The caller's address, honouring X-Forwarded-For only from trusted proxies."""
    return get_proxy_trust().client_ip(request)
