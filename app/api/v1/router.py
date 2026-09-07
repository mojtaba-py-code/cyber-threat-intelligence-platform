"""Aggregate v1 API router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    admin,
    alerts,
    auth,
    collectors,
    correlation,
    dashboard,
    ioc,
    reports,
    stream,
    system,
    threat_actors,
)

api_router = APIRouter()
api_router.include_router(system.router, tags=["system"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(ioc.router, prefix="/iocs", tags=["iocs"])
api_router.include_router(collectors.router, prefix="/collectors", tags=["collectors"])
api_router.include_router(correlation.router, prefix="/correlation", tags=["correlation"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(stream.router, prefix="/stream", tags=["stream"])
api_router.include_router(threat_actors.router, prefix="/threat-actors", tags=["threat-actors"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
