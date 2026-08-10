"""Indicator parsing, classification and (de)fanging.

Threat feeds and analysts routinely *defang* indicators so they cannot be
accidentally clicked or auto-resolved (``hxxp://evil[.]com``). This module
refangs input before classification and can defang for safe display, and it
detects the :class:`~app.ioc.types.IOCType` of a raw value using strict,
well-ordered rules.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.exceptions import UnknownIndicatorError
from app.ioc.types import IOCType

# --- (de)fang ---------------------------------------------------------------

_REFANG_REPLACEMENTS = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    (" dot ", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[@]", "@"),
    ("\\.", "."),
)


def refang(value: str) -> str:
    """Convert a defanged indicator back to its real form."""
    out = value.strip()
    lowered = out
    for token, repl in _REFANG_REPLACEMENTS:
        # Case-insensitive replacement for scheme tokens, literal for punctuation.
        if token.isalpha() or token.startswith(("h", "f")):
            lowered = re.sub(re.escape(token), repl, lowered, flags=re.IGNORECASE)
        else:
            lowered = lowered.replace(token, repl)
    return lowered.strip()


def defang(value: str) -> str:
    """Render an indicator safe for display (no clickable/resolvable form)."""
    # ``http`` → ``hxxp`` already turns ``https`` into ``hxxps`` in one pass.
    out = value.replace("http", "hxxp")
    out = out.replace(".", "[.]").replace("://", "[://]")
    out = out.replace("@", "[at]")
    return out


# --- classification ---------------------------------------------------------

_MD5_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
_SHA1_RE = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9\-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ParsedIndicator:
    type: IOCType
    value: str  # normalised, refanged canonical form


def is_hash(value: str) -> bool:
    v = value.strip()
    return bool(_MD5_RE.match(v) or _SHA1_RE.match(v) or _SHA256_RE.match(v))


def _hash_type(value: str) -> IOCType | None:
    if _MD5_RE.match(value):
        return IOCType.md5
    if _SHA1_RE.match(value):
        return IOCType.sha1
    if _SHA256_RE.match(value):
        return IOCType.sha256
    return None


def _ip_type(value: str) -> IOCType | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return IOCType.ipv6 if ip.version == 6 else IOCType.ipv4


def classify_indicator(raw: str) -> ParsedIndicator:
    """Detect the IOC type of ``raw`` and return its normalised form.

    Order is deliberate: unambiguous formats (hash, CVE, technique) first, then
    URL (has a scheme), email, IP, and finally domain. Raises
    :class:`UnknownIndicatorError` when nothing matches.
    """
    value = refang(raw).strip()
    if not value:
        raise UnknownIndicatorError("Empty indicator.")

    if (htype := _hash_type(value)) is not None:
        return ParsedIndicator(htype, value.lower())
    if _CVE_RE.match(value):
        return ParsedIndicator(IOCType.cve, value.upper())
    if _TECHNIQUE_RE.match(value):
        return ParsedIndicator(IOCType.mitre_technique, value.upper())

    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme and parts.netloc:
            return ParsedIndicator(IOCType.url, value)

    if _EMAIL_RE.match(value):
        return ParsedIndicator(IOCType.email, value.lower())

    # Bare IP (strip an optional port for classification only).
    host = value.split(":", 1)[0] if value.count(":") == 1 and "." in value else value
    if (iptype := _ip_type(host)) is not None:
        return ParsedIndicator(iptype, host)

    if _DOMAIN_RE.match(value):
        return ParsedIndicator(IOCType.domain, value.lower())

    raise UnknownIndicatorError(f"Unrecognised indicator: {raw!r}", details={"value": raw})


def extract_host(indicator_value: str, ioc_type: IOCType) -> str | None:
    """Return the network host of a URL/domain/IP indicator, else ``None``."""
    if ioc_type in (IOCType.ipv4, IOCType.ipv6, IOCType.domain, IOCType.hostname):
        return indicator_value
    if ioc_type is IOCType.url:
        return urlsplit(indicator_value).hostname
    return None
