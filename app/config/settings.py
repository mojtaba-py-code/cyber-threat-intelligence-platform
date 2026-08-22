"""Centralised, validated application configuration.

All configuration flows through a single :class:`Settings` object loaded from
environment variables (and an optional ``.env`` file). Nothing else in the
codebase reads ``os.environ`` directly, keeping configuration discoverable,
typed and testable.
"""

from __future__ import annotations

import functools
import logging
from enum import StrEnum

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)


class AppEnv(StrEnum):
    development = "development"
    staging = "staging"
    production = "production"


class Settings(BaseSettings):
    """Runtime configuration, validated at process start."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ---
    app_env: AppEnv = AppEnv.development
    app_debug: bool = True
    app_name: str = "Threat Intel Platform"
    api_v1_prefix: str = "/api/v1"

    # --- Security ---
    master_encryption_key: str = ""
    jwt_secret_key: str = ""
    jwt_access_ttl_minutes: int = 30
    jwt_refresh_ttl_days: int = 14
    jwt_algorithm: str = "HS256"
    # Role granted to self-registered users. Defaults to the writable "analyst"
    # for the offline demo; production must set this to "viewer" (or disable
    # open registration) so anonymous users cannot write indicators — see
    # validate_runtime(), which refuses to start otherwise.
    registration_default_role: str = "analyst"
    allow_open_registration: bool = True

    # --- Collector safety ---
    enable_live_collectors: bool = False
    outbound_allowed_hosts: list[str] = Field(default_factory=list)

    # --- Provider API keys (SecretStr so they never render in logs/repr) ---
    abuseipdb_api_key: SecretStr = SecretStr("")
    virustotal_api_key: SecretStr = SecretStr("")
    otx_api_key: SecretStr = SecretStr("")
    shodan_api_key: SecretStr = SecretStr("")
    greynoise_api_key: SecretStr = SecretStr("")

    # --- Database / cache ---
    database_url: str = "postgresql+asyncpg://tip:tip@localhost:5432/threatintel"
    redis_url: str = "redis://localhost:6379/0"

    # --- Celery ---
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # --- CORS / rate limiting ---
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    rate_limit_per_minute: int = 120
    # Networks whose X-Forwarded-For may be believed. Empty (the default) means
    # the header is ignored entirely: trusting it from arbitrary clients would
    # let anyone forge a source IP and step around the per-IP rate limiter.
    trusted_proxy_cidrs: list[str] = Field(default_factory=list)

    # --- API documentation ---
    expose_api_docs: bool = True

    @field_validator("cors_origins", "outbound_allowed_hosts", "trusted_proxy_cidrs", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env is AppEnv.production

    @property
    def docs_enabled(self) -> bool:
        """Interactive docs default to off in production."""
        return self.expose_api_docs and not self.is_production

    @property
    def sync_database_url(self) -> str:
        """Synchronous DSN (used by Alembic migrations)."""
        return self.database_url.replace("+asyncpg", "").replace("+aiosqlite", "")

    def provider_key(self, provider: str) -> str:
        """Return the configured API key for a provider, or an empty string."""
        secret: SecretStr | None = getattr(self, f"{provider}_api_key", None)
        return secret.get_secret_value() if secret is not None else ""

    def validate_runtime(self) -> None:
        """Fail fast on unsafe production configuration."""
        if not self.is_production:
            return
        missing: list[str] = []
        if not self.master_encryption_key:
            missing.append("MASTER_ENCRYPTION_KEY")
        if not self.jwt_secret_key or len(self.jwt_secret_key) < 32:
            missing.append("JWT_SECRET_KEY (>= 32 chars)")
        if self.app_debug:
            missing.append("APP_DEBUG must be false in production")
        if "*" in self.cors_origins:
            missing.append("CORS_ORIGINS must not be '*' in production")
        # Open registration into a writable role would let any stranger add and
        # edit indicators; on a public deployment self-service sign-up may only
        # hand out the read-only role.
        if self.allow_open_registration and self.registration_default_role != "viewer":
            missing.append(
                "ALLOW_OPEN_REGISTRATION must be false, or REGISTRATION_DEFAULT_ROLE "
                "must be 'viewer', in production"
            )
        if missing:
            raise RuntimeError(
                "Refusing to start in production with unsafe configuration: " + ", ".join(missing)
            )


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
