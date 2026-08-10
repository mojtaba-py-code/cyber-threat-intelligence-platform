"""Tests for crypto, tokens, RBAC, API keys, throttle and token store."""

from __future__ import annotations

from datetime import timedelta

import pytest
from app.core.exceptions import EncryptionError, InvalidTokenError
from app.security.api_keys import generate_api_key, hash_api_key, verify_api_key
from app.security.crypto import PasswordHasher, SecretCipher, generate_master_key
from app.security.rbac import Permission, Role, has_permission
from app.security.throttle import InMemoryLoginThrottle
from app.security.token_store import InMemoryTokenStore
from app.security.tokens import TokenService


def test_cipher_roundtrip_and_rotation():
    old, new = generate_master_key(), generate_master_key()
    token = SecretCipher([old]).encrypt("api-secret")
    assert SecretCipher([new, old]).decrypt(token) == "api-secret"


def test_cipher_wrong_key_fails():
    token = SecretCipher([generate_master_key()]).encrypt("x")
    with pytest.raises(EncryptionError):
        SecretCipher([generate_master_key()]).decrypt(token)


def test_password_hash_verify():
    h = PasswordHasher()
    hashed = h.hash("correct horse battery staple")
    assert h.verify(hashed, "correct horse battery staple")
    assert not h.verify(hashed, "wrong")


def test_api_key_generate_and_verify():
    key = generate_api_key()
    assert key.raw.startswith("tip_")
    assert verify_api_key(key.raw, key.key_hash)
    assert not verify_api_key("tip_wrong", key.key_hash)
    assert hash_api_key(key.raw) == key.key_hash


def _tokens() -> TokenService:
    return TokenService(
        secret="k" * 40, access_ttl=timedelta(minutes=5), refresh_ttl=timedelta(days=1)
    )


def test_token_roundtrip_and_type_check():
    svc = _tokens()
    pair = svc.issue_pair(subject="u1", role="analyst")
    claims = svc.decode(pair.access_token, expected_type="access")
    assert claims.subject == "u1"
    with pytest.raises(InvalidTokenError):
        svc.decode(pair.access_token, expected_type="refresh")


def test_rbac():
    assert has_permission(Role.admin, Permission.admin_manage)
    assert has_permission(Role.analyst, Permission.ioc_write)
    assert not has_permission(Role.viewer, Permission.ioc_write)


@pytest.mark.asyncio
async def test_token_store_revocation():
    store = InMemoryTokenStore(clock=lambda: 0.0)
    await store.revoke("j1", ttl_seconds=10)
    assert await store.is_revoked("j1")


@pytest.mark.asyncio
async def test_throttle_lockout():
    clk = {"t": 0.0}
    throttle = InMemoryLoginThrottle(max_attempts=3, lockout_seconds=100, clock=lambda: clk["t"])
    for _ in range(3):
        await throttle.record_failure("a@b.com")
    assert await throttle.is_locked("a@b.com")
    assert await throttle.retry_after("a@b.com") == 100
    clk["t"] = 101
    assert not await throttle.is_locked("a@b.com")


@pytest.mark.asyncio
async def test_throttle_is_case_insensitive_and_cleared_on_success():
    throttle = InMemoryLoginThrottle(max_attempts=2, lockout_seconds=60, clock=lambda: 0.0)
    await throttle.record_failure("  A@B.com ")
    await throttle.record_success("a@b.com")
    # A successful login forgives earlier failures, so the next one starts over.
    await throttle.record_failure("a@b.com")
    assert not await throttle.is_locked("A@B.COM")
    assert await throttle.retry_after("a@b.com") == 0
    await throttle.record_failure("a@b.com")
    assert await throttle.is_locked("A@B.COM")
