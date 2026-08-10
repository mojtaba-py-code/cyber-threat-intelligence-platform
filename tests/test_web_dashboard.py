"""Tests for the bundled dashboard page and its content-security policy.

The page is one self-contained file, so its script and style blocks are inline.
The API-wide policy is ``default-src 'self'``, which blocks inline code — the
dashboard is therefore served with a per-response nonce. These tests exist so
that policy and page cannot drift apart and silently break the UI again.
"""

from __future__ import annotations

import re

import pytest


@pytest.mark.asyncio
async def test_dashboard_is_served_with_a_nonce_matching_its_inline_blocks(client):
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")

    policy = response.headers["content-security-policy"]
    nonce = re.search(r"script-src 'nonce-([\w-]+)'", policy).group(1)
    assert f"style-src 'nonce-{nonce}'" in policy
    assert f'<script nonce="{nonce}">' in response.text
    assert f'<style nonce="{nonce}">' in response.text
    assert "{{nonce}}" not in response.text  # the placeholder was substituted


@pytest.mark.asyncio
async def test_the_policy_stays_strict(client):
    policy = (await client.get("/dashboard")).headers["content-security-policy"]
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy
    for directive in ("default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"):
        assert directive in policy


@pytest.mark.asyncio
async def test_each_response_gets_a_fresh_nonce(client):
    first, second = (await client.get("/dashboard")), (await client.get("/dashboard"))
    assert first.headers["content-security-policy"] != second.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_the_page_carries_no_inline_handlers_or_styles(client):
    """A nonce authorises <script> blocks but never onclick= or style= attributes."""
    body = (await client.get("/dashboard")).text
    assert "onclick=" not in body
    assert 'style="' not in body
    assert 'data-action="login"' in body  # behaviour is wired by delegation instead


@pytest.mark.asyncio
async def test_root_advertises_the_dashboard(client):
    body = (await client.get("/")).json()
    assert body["dashboard"] == "/dashboard"
    assert body["docs"] == "/docs"


@pytest.mark.asyncio
async def test_the_dashboard_file_ships_with_the_installed_package():
    """Guards the packaging trap: it is a data file, so a wheel drops it unless
    package-data says otherwise — and the app reads it at startup."""
    from importlib.resources import files

    assert files("app").joinpath("web/dashboard.html").is_file()


def test_docs_are_disabled_in_production(monkeypatch):
    from app.config import get_settings
    from app.config.settings import AppEnv

    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", AppEnv.production)
    assert settings.expose_api_docs is True  # opted in...
    assert settings.docs_enabled is False  # ...but production still says no
