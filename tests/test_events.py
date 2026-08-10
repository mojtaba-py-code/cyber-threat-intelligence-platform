"""Tests for the in-process event bus behind the live alert stream."""

from __future__ import annotations

import asyncio
import json

import pytest
from app.core.events import Event, EventBus


@pytest.mark.asyncio
async def test_subscriber_receives_published_events():
    bus = EventBus()
    async with bus.subscribe() as queue:
        await bus.publish("alert", {"title": "first"})
        event = await asyncio.wait_for(queue.get(), timeout=1)
    assert event.type == "alert"
    assert event.data["title"] == "first"


@pytest.mark.asyncio
async def test_every_subscriber_gets_its_own_copy():
    bus = EventBus()
    async with bus.subscribe() as a, bus.subscribe() as b:
        assert bus.subscriber_count == 2
        await bus.publish("alert", {"n": 1})
        assert (await a.get()).data == (await b.get()).data
    assert bus.subscriber_count == 0  # both unsubscribed on exit


@pytest.mark.asyncio
async def test_publishing_with_no_subscribers_is_a_no_op():
    bus = EventBus()
    await bus.publish("alert", {"n": 1})
    assert bus.subscriber_count == 0


@pytest.mark.asyncio
async def test_a_slow_consumer_drops_its_oldest_events_instead_of_growing():
    bus = EventBus(queue_size=3)
    async with bus.subscribe() as queue:
        for n in range(10):
            await bus.publish("alert", {"n": n})
        assert queue.qsize() == 3
        # The three most recent survive; the publisher was never blocked.
        assert [(await queue.get()).data["n"] for _ in range(3)] == [7, 8, 9]


@pytest.mark.asyncio
async def test_stream_emits_a_connect_frame_then_events():
    bus = EventBus()
    stream = bus.stream(heartbeat_seconds=30)
    assert await anext(stream) == ": connected\n\n"

    await asyncio.sleep(0)  # let the subscription register
    await bus.publish("alert", {"title": "boom"})
    frame = await asyncio.wait_for(anext(stream), timeout=1)

    assert frame.startswith("event: alert\ndata: ")
    payload = json.loads(frame.split("data: ", 1)[1])
    assert payload["title"] == "boom"
    assert "at" in payload  # timestamp is added for the client
    await stream.aclose()


@pytest.mark.asyncio
async def test_stream_heartbeats_while_idle_so_proxies_hold_the_connection():
    bus = EventBus()
    stream = bus.stream(heartbeat_seconds=0.01)
    await anext(stream)
    assert await asyncio.wait_for(anext(stream), timeout=1) == ": heartbeat\n\n"
    await stream.aclose()


def test_event_renders_a_well_formed_sse_frame():
    frame = Event(type="alert", data={"title": "x"}).to_sse()
    assert frame.startswith("event: alert\n")
    assert frame.endswith("\n\n")
