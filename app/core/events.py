"""A small in-process publish/subscribe bus for live streaming.

Alerts are pushed to connected operators as they fire, instead of being polled
for. Each subscriber gets its own **bounded** queue and a slow consumer drops its
oldest events rather than growing without limit — a stalled browser tab must
never become a memory leak in the API process, and back-pressure must never
propagate into the request that created the alert.

The bus is per-process: with several API replicas a client sees the alerts
raised by the worker it is connected to. Fanning out across replicas is a Redis
pub/sub swap behind this same interface.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.logging import get_logger

log = get_logger(__name__)

#: Events buffered per subscriber before the oldest are discarded.
DEFAULT_QUEUE_SIZE = 100


@dataclass(frozen=True, slots=True)
class Event:
    type: str
    data: dict
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_sse(self) -> str:
        """Render as a Server-Sent Events frame."""
        payload = json.dumps({**self.data, "at": self.created_at.isoformat()}, default=str)
        return f"event: {self.type}\ndata: {payload}\n\n"


class EventBus:
    def __init__(self, *, queue_size: int = DEFAULT_QUEUE_SIZE) -> None:
        self._queue_size = queue_size
        self._subscribers: set[asyncio.Queue[Event]] = set()

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    async def publish(self, event_type: str, data: dict) -> None:
        event = Event(type=event_type, data=data)
        for queue in list(self._subscribers):
            self._offer(queue, event)

    def _offer(self, queue: asyncio.Queue[Event], event: Event) -> None:
        """Enqueue without ever blocking the publisher."""
        while True:
            try:
                queue.put_nowait(event)
                return
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()  # drop the oldest and retry
                    continue
                return  # drained concurrently; nothing more we can do

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[Event]]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)

    async def stream(self, *, heartbeat_seconds: float = 15.0) -> AsyncIterator[str]:
        """Yield SSE frames for one client until it disconnects.

        A comment frame is emitted when idle so that proxies and load balancers
        do not time the connection out.
        """
        async with self.subscribe() as queue:
            yield ": connected\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=heartbeat_seconds)
                except TimeoutError:
                    yield ": heartbeat\n\n"
                    continue
                yield event.to_sse()


@functools.lru_cache(maxsize=1)
def get_event_bus() -> EventBus:
    """Return the process-wide event bus."""
    return EventBus()
