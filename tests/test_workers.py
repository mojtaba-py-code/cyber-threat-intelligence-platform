"""Tests for the Celery task layer.

The tasks are deliberately synchronous entry points that drive an async
coroutine with :func:`asyncio.run`, so these tests are synchronous too and call
the tasks exactly as a Celery worker would — no broker required.
"""

from __future__ import annotations

import asyncio

import pytest
from app.config import get_settings
from app.core import resilience
from app.database.session import init_models, reset_engine


async def _create_schema() -> None:
    await reset_engine()
    await init_models()
    await reset_engine()


@pytest.fixture
def worker_db(tmp_path, monkeypatch):
    """Point the worker at a file-backed database.

    Each task runs in its own event loop and disposes the engine when it
    finishes, so an in-memory database would be gone before the task opened it.
    """
    url = "sqlite+aiosqlite:///" + str(tmp_path / "worker.db").replace("\\", "/")
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    asyncio.run(_create_schema())
    yield url
    asyncio.run(reset_engine())
    get_settings.cache_clear()


def test_run_collector_task_ingests_offline_samples(worker_db):
    from app.workers.tasks import run_collector

    result = run_collector("urlhaus", 5)
    assert result["collector"] == "urlhaus"
    assert result["ingested"] >= 1
    assert result["skipped"] == 0


def test_collector_task_is_idempotent_across_runs(worker_db):
    from app.workers.tasks import run_collector

    first = run_collector("cisa_kev", 5)
    second = run_collector("cisa_kev", 5)
    # The same samples upsert rather than duplicate, so both runs succeed.
    assert first["ingested"] == second["ingested"]


def test_cleanup_task_deletes_only_expired_audit_rows(worker_db):
    from app.workers.tasks import cleanup_old_audit_logs, run_collector

    run_collector("urlhaus", 3)  # ingestion writes audit rows
    assert cleanup_old_audit_logs(retention_days=0)["deleted"] >= 1
    assert cleanup_old_audit_logs(retention_days=0)["deleted"] == 0
    # Rows younger than the retention window are kept.
    run_collector("urlhaus", 3)
    assert cleanup_old_audit_logs(retention_days=90)["deleted"] == 0


def test_task_runner_clears_loop_bound_circuit_breakers(worker_db):
    from app.workers.tasks import _run

    resilience.get_circuit_breaker("stale")  # holds a lock bound to another loop
    assert resilience._breakers

    async def _noop() -> str:
        return "done"

    assert _run(_noop()) == "done"
    # Left behind, the next asyncio.run() would await a lock from a dead loop.
    assert not resilience._breakers


def test_beat_schedule_only_references_registered_tasks():
    from app.workers import tasks  # noqa: F401  (registers the tasks)
    from app.workers.celery_app import celery

    scheduled = {entry["task"] for entry in celery.conf.beat_schedule.values()}
    assert scheduled
    assert scheduled <= set(celery.tasks)
    assert celery.conf.task_serializer == "json"  # no pickle deserialisation
    assert celery.conf.accept_content == ["json"]
