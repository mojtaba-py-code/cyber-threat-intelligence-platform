"""System endpoints: health, readiness, and collector registry."""

from __future__ import annotations

from fastapi import APIRouter

from app.collectors.registry import SUPPORTED_COLLECTORS
from app.config import get_settings

router = APIRouter()


@router.get("/health", summary="Liveness probe")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/ready", summary="Readiness probe")
async def ready() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "environment": str(settings.app_env),
        "live_collectors_enabled": settings.enable_live_collectors,
    }


@router.get("/collectors", summary="List supported threat-intel collectors")
async def list_collectors() -> dict:
    return {
        "collectors": [
            {
                "name": info.name,
                "label": info.label,
                "category": info.category,
                "requires_key": info.requires_key,
                "format": info.fmt,
            }
            for info in SUPPORTED_COLLECTORS.values()
        ]
    }
