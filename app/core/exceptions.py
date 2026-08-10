"""Application-wide exception hierarchy.

Every deliberately-raised error derives from :class:`AppError`, which carries an
HTTP status code and a stable, machine-readable ``code``. The API layer converts
these into consistent JSON error responses.
"""

from __future__ import annotations


class AppError(Exception):
    """Base class for all expected application errors."""

    status_code: int = 500
    code: str = "internal_error"
    message: str = "An unexpected error occurred."

    def __init__(self, message: str | None = None, *, details: dict | None = None) -> None:
        self.message = message or self.message
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict:
        payload: dict = {"error": {"code": self.code, "message": self.message}}
        if self.details:
            payload["error"]["details"] = self.details
        return payload


# --- Authentication / authorization ---------------------------------------


class AuthenticationError(AppError):
    status_code = 401
    code = "authentication_error"
    message = "Authentication failed."


class InvalidTokenError(AuthenticationError):
    code = "invalid_token"
    message = "The provided token is invalid or expired."


class InvalidApiKeyError(AuthenticationError):
    code = "invalid_api_key"
    message = "The provided API key is invalid or revoked."


class PermissionDeniedError(AppError):
    status_code = 403
    code = "permission_denied"
    message = "You do not have permission to perform this action."


class AccountLockedError(AppError):
    status_code = 429
    code = "account_locked"
    message = "Too many failed attempts. This account is temporarily locked."


# --- Resource / validation -------------------------------------------------


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"
    message = "The requested resource was not found."


class ConflictError(AppError):
    status_code = 409
    code = "conflict"
    message = "The request conflicts with the current state."


class ValidationError(AppError):
    status_code = 422
    code = "validation_error"
    message = "The request payload failed validation."


class RateLimitError(AppError):
    status_code = 429
    code = "rate_limited"
    message = "Too many requests. Please slow down."


# --- Security --------------------------------------------------------------


class EncryptionError(AppError):
    code = "encryption_error"
    message = "Failed to encrypt or decrypt sensitive data."


class SSRFError(AppError):
    status_code = 400
    code = "ssrf_blocked"
    message = "The requested destination is not allowed."


# --- Collectors / enrichment ----------------------------------------------


class CollectorError(AppError):
    status_code = 502
    code = "collector_error"
    message = "A threat-intelligence source returned an error."


class CollectorUnavailableError(CollectorError):
    status_code = 503
    code = "collector_unavailable"
    message = "The threat-intelligence source is currently unavailable."


class LiveCollectorsDisabledError(AppError):
    status_code = 409
    code = "live_collectors_disabled"
    message = (
        "Live collectors are disabled by server policy; bundled sample "
        "intelligence is served instead until an operator enables them."
    )


class UnknownIndicatorError(ValidationError):
    code = "unknown_indicator"
    message = "The supplied value is not a recognised indicator."


class CircuitOpenError(CollectorUnavailableError):
    code = "circuit_open"
    message = "The circuit breaker is open for this source; try again shortly."
