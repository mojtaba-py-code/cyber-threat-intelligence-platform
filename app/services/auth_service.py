"""Authentication, token lifecycle and API-key management."""

from __future__ import annotations

import functools
from datetime import UTC, datetime

from app.config import get_settings
from app.core.exceptions import (
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    InvalidApiKeyError,
    NotFoundError,
    PermissionDeniedError,
)
from app.core.logging import get_logger
from app.models.api_key import ApiKey
from app.models.user import User
from app.repositories.api_key_repository import ApiKeyRepository
from app.repositories.audit_repository import AuditRepository
from app.repositories.user_repository import UserRepository
from app.security.api_keys import GeneratedApiKey, generate_api_key, hash_api_key
from app.security.crypto import PasswordHasher
from app.security.rbac import Role
from app.security.throttle import LoginThrottle
from app.security.token_store import TokenStore
from app.security.tokens import TokenPair, TokenService

log = get_logger(__name__)


def _remaining_ttl(expires_at: datetime) -> int:
    return max(1, int((expires_at - datetime.now(UTC)).total_seconds()))


@functools.lru_cache(maxsize=1)
def _decoy_hash() -> str:
    return PasswordHasher().hash("decoy-password-for-constant-time-auth")


class AuthService:
    def __init__(
        self,
        *,
        users: UserRepository,
        api_keys: ApiKeyRepository,
        audit: AuditRepository,
        hasher: PasswordHasher,
        tokens: TokenService,
        token_store: TokenStore,
        throttle: LoginThrottle,
    ) -> None:
        self._users = users
        self._api_keys = api_keys
        self._audit = audit
        self._hasher = hasher
        self._tokens = tokens
        self._token_store = token_store
        self._throttle = throttle

    # -- users / login ------------------------------------------------------
    async def register(self, *, email: str, password: str, role: Role | None = None) -> User:
        settings = get_settings()
        if not settings.allow_open_registration:
            raise PermissionDeniedError("Open registration is disabled.")
        email = email.lower()
        if await self._users.email_exists(email):
            raise ConflictError("A user with this email already exists.")
        if role is None:
            try:
                role = Role(settings.registration_default_role)
            except ValueError:
                role = Role.viewer
        user = User(email=email, password_hash=self._hasher.hash(password), role=role.value)
        await self._users.add(user)
        await self._audit.record(action="user.register", user_id=user.id)
        return user

    async def authenticate(self, *, email: str, password: str, ip: str | None = None) -> TokenPair:
        email = email.lower()
        if await self._throttle.is_locked(email):
            raise AccountLockedError(
                details={"retry_after": await self._throttle.retry_after(email)}
            )
        user = await self._users.get_by_email(email)
        if user is None:
            self._hasher.verify(_decoy_hash(), password)  # constant-time-ish
            await self._throttle.record_failure(email)
            await self._audit.record(action="auth.login_failed", ip_address=ip)
            raise AuthenticationError("Invalid email or password.")
        if not self._hasher.verify(user.password_hash, password):
            await self._throttle.record_failure(email)
            await self._audit.record(action="auth.login_failed", user_id=user.id, ip_address=ip)
            raise AuthenticationError("Invalid email or password.")
        if not user.is_active:
            # Generic message so a disabled account is not distinguishable from a
            # non-existent one (avoids account-status enumeration).
            raise AuthenticationError("Invalid email or password.")
        await self._throttle.record_success(email)
        if self._hasher.needs_rehash(user.password_hash):
            user.password_hash = self._hasher.hash(password)
        await self._audit.record(action="auth.login", user_id=user.id, ip_address=ip)
        return self._tokens.issue_pair(subject=user.id, role=user.role)

    async def refresh(self, refresh_token: str) -> TokenPair:
        claims = self._tokens.decode(refresh_token, expected_type="refresh")
        if await self._token_store.is_revoked(claims.jti):
            raise AuthenticationError("This refresh token has been revoked.")
        user = await self._users.get(claims.subject)
        if user is None or not user.is_active:
            raise AuthenticationError("User no longer active.")
        await self._token_store.revoke(claims.jti, ttl_seconds=_remaining_ttl(claims.expires_at))
        return self._tokens.issue_pair(subject=user.id, role=user.role)

    async def logout(self, refresh_token: str, *, access_token: str | None = None) -> None:
        """Revoke the refresh token (and, if provided, the current access token).

        Revoking the access ``jti`` makes logout terminate the live session
        immediately rather than lingering until the short access TTL expires.
        """
        try:
            claims = self._tokens.decode(refresh_token, expected_type="refresh")
        except Exception:  # noqa: BLE001 - logout is best-effort and idempotent
            claims = None
        if claims is not None:
            await self._token_store.revoke(
                claims.jti, ttl_seconds=_remaining_ttl(claims.expires_at)
            )
            await self._audit.record(action="auth.logout", user_id=claims.subject)
        if access_token:
            try:
                acc = self._tokens.decode(access_token, expected_type="access")
                await self._token_store.revoke(acc.jti, ttl_seconds=_remaining_ttl(acc.expires_at))
            except Exception:  # noqa: BLE001, S110 - best-effort; a bad token is simply ignored
                pass

    async def get_user(self, user_id: str) -> User:
        user = await self._users.get(user_id)
        if user is None:
            raise NotFoundError("User not found.")
        return user

    # -- API keys -----------------------------------------------------------
    async def create_api_key(self, *, user_id: str, name: str) -> tuple[ApiKey, GeneratedApiKey]:
        user = await self.get_user(user_id)
        generated = generate_api_key()
        record = ApiKey(
            user_id=user.id,
            name=name,
            key_hash=generated.key_hash,
            prefix=generated.prefix,
            role=user.role,
        )
        await self._api_keys.add(record)
        await self._audit.record(action="apikey.create", user_id=user.id, detail={"name": name})
        return record, generated

    async def list_api_keys(self, user_id: str) -> list[ApiKey]:
        return await self._api_keys.list_for_user(user_id)

    async def get_api_key(self, *, user_id: str, key_id: str) -> ApiKey:
        record = await self._api_keys.get_for_user(key_id, user_id)
        if record is None:
            raise NotFoundError("API key not found.")
        return record

    async def revoke_api_key(self, *, user_id: str, key_id: str) -> None:
        record = await self._api_keys.get_for_user(key_id, user_id)
        if record is None:
            raise NotFoundError("API key not found.")
        record.is_active = False
        await self._audit.record(action="apikey.revoke", user_id=user_id, detail={"id": key_id})

    async def resolve_api_key(self, raw_key: str) -> ApiKey:
        record = await self._api_keys.get_by_hash(hash_api_key(raw_key))
        if record is None or not record.is_active:
            raise InvalidApiKeyError()
        # A deactivated owner must not retain access through their keys.
        owner = await self._users.get(record.user_id)
        if owner is None or not owner.is_active:
            raise InvalidApiKeyError()
        record.last_used_at = datetime.now(UTC)
        return record
