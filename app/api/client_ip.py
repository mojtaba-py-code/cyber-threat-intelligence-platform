"""Determine the real client address behind a reverse proxy.

Behind Nginx every request arrives from the proxy, so a naive
``request.client.host`` makes the per-IP rate limiter degenerate into a single
global bucket — one noisy client then throttles everyone — and records the
proxy's address in the audit log instead of the caller's.

``X-Forwarded-For`` fixes that but is client-supplied, so it is honoured **only**
when the immediate peer is inside an operator-configured trusted network, and
only the right-most untrusted hop is taken: the tail of the header is the part
the proxy itself appended, and everything to its left may be attacker-forged.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from starlette.requests import Request

from app.core.logging import get_logger

log = get_logger(__name__)


class ProxyTrust:
    def __init__(self, trusted_cidrs: Sequence[str] | None = None) -> None:
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in trusted_cidrs or []:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("ignoring_invalid_trusted_proxy_cidr", cidr=cidr)

    @property
    def configured(self) -> bool:
        return bool(self._networks)

    def trusts(self, address: str | None) -> bool:
        if not address or not self._networks:
            return False
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in network for network in self._networks)

    def client_ip(self, request: Request) -> str | None:
        """Return the caller's address, or ``None`` if it cannot be determined."""
        peer = request.client.host if request.client else None
        if not self.trusts(peer):
            return peer
        forwarded = request.headers.get("x-forwarded-for", "")
        # Walk right-to-left and stop at the first hop we did not put there.
        for hop in reversed([part.strip() for part in forwarded.split(",") if part.strip()]):
            if not self.trusts(hop):
                return hop
        return peer
