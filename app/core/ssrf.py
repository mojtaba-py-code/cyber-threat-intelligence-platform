"""SSRF (Server-Side Request Forgery) guard for user-controlled fetches.

A threat platform frequently fetches attacker-controlled destinations (a
submitted URL's landing page, a domain's resources). Without guarding, an
attacker could point those at internal services or the cloud metadata endpoint.
This module validates a URL before any outbound request:

* only ``http``/``https`` schemes are allowed;
* the host is resolved and **every** resolved address must be a *public*
  unicast address — loopback, private, link-local (incl. 169.254.169.254
  metadata), reserved, multicast and unspecified ranges are rejected;
* an optional operator allow-list can restrict destinations further.

Note: this is not a full defence against DNS rebinding (which needs
connect-time pinning); it blocks the overwhelming majority of SSRF vectors and
is applied only to *user-supplied* destinations, never to fixed provider APIs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.exceptions import SSRFError
from app.core.logging import get_logger

log = get_logger(__name__)

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def ip_is_public(ip: str) -> bool:
    """True only for globally-routable unicast addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


@dataclass(frozen=True, slots=True)
class SafeTarget:
    url: str
    host: str
    port: int
    resolved_ips: tuple[str, ...]


class SSRFGuard:
    def __init__(self, allowed_hosts: list[str] | None = None) -> None:
        # Normalised allow-list; empty means "any public host".
        self._allowed = {h.lower().lstrip(".") for h in (allowed_hosts or []) if h}

    def _host_allowed(self, host: str) -> bool:
        if not self._allowed:
            return True
        host = host.lower()
        return any(host == a or host.endswith("." + a) for a in self._allowed)

    async def _resolve(self, host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise SSRFError(f"Could not resolve host: {host}", details={"host": host}) from exc
        return [str(info[4][0]) for info in infos]

    async def validate(self, url: str) -> SafeTarget:
        """Validate ``url`` for outbound fetching or raise :class:`SSRFError`."""
        parts = urlsplit(url)
        if parts.scheme.lower() not in _ALLOWED_SCHEMES:
            raise SSRFError("Only http(s) URLs may be fetched.", details={"scheme": parts.scheme})
        host = parts.hostname
        if not host:
            raise SSRFError("URL has no host.")
        if not self._host_allowed(host):
            raise SSRFError("Destination host is not in the allow-list.", details={"host": host})

        # A literal IP host must itself be public.
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None and not ip_is_public(host):
            raise SSRFError("Destination IP is not a public address.", details={"host": host})

        port = parts.port or (443 if parts.scheme == "https" else 80)
        resolved = await self._resolve(host, port)
        for ip in resolved:
            if not ip_is_public(ip):
                log.warning("ssrf_blocked", host=host, ip=ip)
                raise SSRFError(
                    "Destination resolves to a non-public address.",
                    details={"host": host, "ip": ip},
                )
        return SafeTarget(url=url, host=host, port=port, resolved_ips=tuple(resolved))
