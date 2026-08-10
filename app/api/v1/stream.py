"""Live alert stream (Server-Sent Events).

SOC work is a watch-floor activity: alerts should arrive, not be polled for. SSE
is used rather than WebSockets because the feed is one-directional, survives
proxies, and reconnects on its own.

Authentication is header-based (bearer token or ``X-API-Key``) like every other
endpoint — deliberately **not** a token in the query string, which would leak
credentials into proxy and access logs. Browsers must therefore consume this
with ``fetch``/``EventSource`` polyfills that can set headers, as the bundled
dashboard does.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from app.api.deps import SessionDep, require
from app.core.events import EventBus, get_event_bus
from app.security.rbac import Permission

router = APIRouter()

BusDep = Annotated[EventBus, Depends(get_event_bus)]

SSE_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    # Tell nginx not to buffer the response, which would defeat streaming.
    "X-Accel-Buffering": "no",
}


@router.get(
    "/alerts",
    dependencies=[Depends(require(Permission.alert_read))],
    summary="Server-Sent Events feed of alerts as they fire",
    response_class=StreamingResponse,
)
async def stream_alerts(
    bus: BusDep,
    session: SessionDep,
    heartbeat: Annotated[float, Query(ge=1.0, le=60.0)] = 15.0,
) -> StreamingResponse:
    # Authentication is the only thing this endpoint touches the database for,
    # and an SSE connection may stay open for hours. Hand the pooled connection
    # back *before* streaming starts, or a handful of watching analysts would
    # exhaust the pool and stall every other request.
    await session.commit()
    await session.close()
    return StreamingResponse(
        bus.stream(heartbeat_seconds=heartbeat),
        media_type="text/event-stream",
        headers=SSE_HEADERS,
    )
