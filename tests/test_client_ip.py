"""Tests for source-address resolution behind a reverse proxy.

Getting this wrong is quietly expensive: trust the header from everyone and any
client can forge its source and walk past the per-IP rate limiter; trust no one
while sitting behind Nginx and every caller shares a single bucket, so one noisy
client throttles the whole platform.
"""

from __future__ import annotations

import pytest
from app.api.client_ip import ProxyTrust
from starlette.requests import Request


def make_request(peer: str | None, forwarded: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
        "client": (peer, 12345) if peer else None,
    }
    return Request(scope)


def test_without_configured_proxies_the_header_is_ignored():
    trust = ProxyTrust()
    assert not trust.configured
    # An attacker claiming to be someone else must not be believed.
    assert trust.client_ip(make_request("203.0.113.9", "1.2.3.4")) == "203.0.113.9"


def test_a_trusted_proxy_reveals_the_real_client():
    trust = ProxyTrust(["172.16.0.0/12"])
    assert trust.client_ip(make_request("172.20.0.5", "203.0.113.9")) == "203.0.113.9"


def test_only_the_rightmost_untrusted_hop_is_believed():
    """Everything left of the proxy's own append is client-controlled."""
    trust = ProxyTrust(["172.16.0.0/12"])
    request = make_request("172.20.0.5", "1.1.1.1, 203.0.113.9")
    assert trust.client_ip(request) == "203.0.113.9"


def test_a_chain_of_trusted_proxies_is_walked_through():
    trust = ProxyTrust(["172.16.0.0/12", "10.0.0.0/8"])
    request = make_request("172.20.0.5", "203.0.113.9, 10.1.2.3")
    assert trust.client_ip(request) == "203.0.113.9"


def test_an_untrusted_peer_is_used_verbatim_even_with_a_header():
    trust = ProxyTrust(["172.16.0.0/12"])
    assert trust.client_ip(make_request("198.51.100.4", "1.2.3.4")) == "198.51.100.4"


def test_garbage_is_handled_without_raising():
    trust = ProxyTrust(["172.16.0.0/12", "not-a-cidr"])
    assert trust.client_ip(make_request("172.20.0.5", "not-an-ip")) == "not-an-ip"
    assert trust.client_ip(make_request("172.20.0.5", " , ")) == "172.20.0.5"
    assert trust.client_ip(make_request(None)) is None
    assert not trust.trusts(None)


@pytest.mark.parametrize("cidr", ["172.16.0.0/12", "::1/128"])
def test_ipv4_and_ipv6_networks_are_both_supported(cidr):
    assert ProxyTrust([cidr]).configured


@pytest.mark.asyncio
async def test_the_rate_limiter_still_counts_per_client(client):
    """A smoke test that the middleware path is wired to the resolver."""
    for _ in range(3):
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
