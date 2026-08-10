"""Tests for the SSRF guard."""

from __future__ import annotations

import pytest
from app.core.exceptions import SSRFError
from app.core.ssrf import SSRFGuard, ip_is_public


def test_ip_is_public():
    assert ip_is_public("8.8.8.8")
    assert not ip_is_public("10.0.0.1")
    assert not ip_is_public("127.0.0.1")
    assert not ip_is_public("169.254.169.254")  # cloud metadata
    assert not ip_is_public("::1")
    assert not ip_is_public("192.168.1.1")


@pytest.mark.asyncio
async def test_guard_rejects_non_http_scheme():
    guard = SSRFGuard()
    with pytest.raises(SSRFError):
        await guard.validate("file:///etc/passwd")


@pytest.mark.asyncio
async def test_guard_rejects_literal_private_ip():
    guard = SSRFGuard()
    with pytest.raises(SSRFError):
        await guard.validate("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(SSRFError):
        await guard.validate("http://127.0.0.1:8000/admin")


@pytest.mark.asyncio
async def test_guard_allows_public_literal_ip():
    guard = SSRFGuard()
    target = await guard.validate("http://8.8.8.8/")
    assert target.host == "8.8.8.8"


@pytest.mark.asyncio
async def test_guard_allowlist_blocks_other_hosts():
    guard = SSRFGuard(allowed_hosts=["trusted.example"])
    with pytest.raises(SSRFError):
        await guard.validate("http://8.8.8.8/")
