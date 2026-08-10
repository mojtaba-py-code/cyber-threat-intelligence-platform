"""Integration tests for auth, API keys and hardening."""

from __future__ import annotations

import pytest


async def _login(client, payload) -> dict:
    await client.post("/api/v1/auth/register", json=payload)
    r = await client.post(
        "/api/v1/auth/login", json={"email": payload["email"], "password": payload["password"]}
    )
    return r.json()


@pytest.mark.asyncio
async def test_register_login_me(client, register_payload):
    r = await client.post("/api/v1/auth/register", json=register_payload)
    assert r.status_code == 201
    assert r.json()["role"] == "analyst"
    tokens = await _login(client, register_payload)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    me = await client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["email"] == register_payload["email"]


@pytest.mark.asyncio
async def test_duplicate_registration_conflict(client, register_payload):
    await client.post("/api/v1/auth/register", json=register_payload)
    r = await client.post("/api/v1/auth/register", json=register_payload)
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_refresh_rotation(client, register_payload):
    tokens = await _login(client, register_payload)
    first = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert first.status_code == 200
    replay = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_lockout_after_failures(client, register_payload):
    await client.post("/api/v1/auth/register", json=register_payload)
    for _ in range(5):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": register_payload["email"], "password": "wrong-pass"},
        )
        assert r.status_code == 401
    locked = await client.post(
        "/api/v1/auth/login",
        json={"email": register_payload["email"], "password": register_payload["password"]},
    )
    assert locked.status_code == 429


@pytest.mark.asyncio
async def test_api_key_auth_flow(client, register_payload):
    tokens = await _login(client, register_payload)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    created = await client.post("/api/v1/auth/api-keys", headers=headers, json={"name": "ci"})
    assert created.status_code == 201
    raw = created.json()["api_key"]
    assert raw.startswith("tip_")

    # Use the API key (no bearer token) to access a protected endpoint.
    me = await client.get("/api/v1/auth/me", headers={"X-API-Key": raw})
    assert me.status_code == 200
    assert me.json()["email"] == register_payload["email"]

    # The raw key is only returned once — listing never exposes it.
    listing = await client.get("/api/v1/auth/api-keys", headers=headers)
    assert "api_key" not in listing.json()[0]


@pytest.mark.asyncio
async def test_unauthenticated_rejected(client):
    r = await client.get("/api/v1/iocs")
    assert r.status_code in (401, 403)
