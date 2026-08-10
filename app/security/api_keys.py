"""API-key generation and verification for machine/API access.

A raw key is shown to the user exactly once. Only its SHA-256 hash is stored,
plus a short non-secret prefix used to identify the key in listings and to speed
up lookups. Verification hashes the presented key and compares in constant time.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

_KEY_PREFIX = "tip"
_PREFIX_LEN = 12  # identifying prefix length (non-secret)


@dataclass(frozen=True, slots=True)
class GeneratedApiKey:
    raw: str  # returned to the user once, never stored
    prefix: str  # stored for identification
    key_hash: str  # stored (SHA-256 hex)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()


def generate_api_key() -> GeneratedApiKey:
    raw = f"{_KEY_PREFIX}_{secrets.token_urlsafe(32)}"
    return GeneratedApiKey(raw=raw, prefix=raw[:_PREFIX_LEN], key_hash=hash_api_key(raw))


def verify_api_key(raw: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(raw), stored_hash)


def key_prefix(raw: str) -> str:
    return raw[:_PREFIX_LEN]
