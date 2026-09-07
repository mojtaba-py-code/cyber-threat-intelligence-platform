"""Cryptographic primitives: secrets at rest and password hashing.

* :class:`SecretCipher` — authenticated symmetric encryption (Fernet / AES-128-CBC
  + HMAC-SHA256) with key rotation via :class:`MultiFernet`. Used to protect
  provider API keys before they are stored. Rotation is driven from
  configuration: ``MASTER_ENCRYPTION_KEY`` takes a comma-separated list whose
  first entry encrypts and whose remaining entries only decrypt, so retired
  keys keep old ciphertext readable until :meth:`SecretCipher.rotate` has
  re-encrypted it.
* :class:`PasswordHasher` — Argon2id password hashing for user credentials.
"""

from __future__ import annotations

import functools

from argon2 import PasswordHasher as _Argon2Hasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.config import get_settings
from app.core.exceptions import EncryptionError
from app.core.logging import get_logger

log = get_logger(__name__)


def generate_master_key() -> str:
    """Generate a fresh urlsafe base64 32-byte key suitable for ``SecretCipher``."""
    return Fernet.generate_key().decode("ascii")


class SecretCipher:
    """Encrypt/decrypt small secrets with key-rotation support."""

    def __init__(self, keys: list[str]) -> None:
        if not keys:
            raise EncryptionError("SecretCipher requires at least one key.")
        try:
            fernets = [Fernet(key.encode("ascii")) for key in keys]
        except (ValueError, TypeError) as exc:
            raise EncryptionError("Invalid encryption key material.") from exc
        self._multi = MultiFernet(fernets)

    def encrypt(self, plaintext: str) -> str:
        if plaintext is None:
            raise EncryptionError("Cannot encrypt None.")
        return self._multi.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._multi.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            raise EncryptionError("Failed to decrypt secret (bad key or corrupt data).") from exc

    def rotate(self, token: str) -> str:
        try:
            return self._multi.rotate(token.encode("ascii")).decode("ascii")
        except (InvalidToken, ValueError) as exc:
            raise EncryptionError("Failed to rotate secret.") from exc


class PasswordHasher:
    """Argon2id password hashing with transparent rehash-on-verify."""

    def __init__(self) -> None:
        self._hasher = _Argon2Hasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, hashed: str, password: str) -> bool:
        try:
            self._hasher.verify(hashed, password)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            # A corrupt or foreign hash is a failed login, not a 500 — otherwise
            # one damaged row turns into a server error an attacker can probe for.
            return False
        return True

    def needs_rehash(self, hashed: str) -> bool:
        return self._hasher.check_needs_rehash(hashed)


@functools.lru_cache(maxsize=1)
def get_secret_cipher() -> SecretCipher:
    settings = get_settings()
    keys = settings.master_encryption_keys
    if not keys:
        if settings.is_production:
            raise EncryptionError("MASTER_ENCRYPTION_KEY is required in production.")
        keys = [generate_master_key()]
        log.warning("using_ephemeral_encryption_key", env=str(settings.app_env))
    if len(keys) > 1:
        log.info("encryption_key_rotation_active", keys=len(keys))
    return SecretCipher(keys)


@functools.lru_cache(maxsize=1)
def get_password_hasher() -> PasswordHasher:
    return PasswordHasher()
