"""Celery task definitions.

Tasks run an async coroutine to completion. Each opens its own database session
(workers are separate processes from the API) and delegates to the same service
layer used by the HTTP handlers, so there is no logic duplication.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from app.core.logging import get_logger
from app.workers.celery_app import celery

log = get_logger(__name__)
T = TypeVar("T")


def _run(coro: Awaitable[T]) -> T:
    """Run a coroutine and dispose the engine, avoiding cross-loop reuse."""

    async def _wrapped() -> T:
        from app.core.resilience import reset_circuit_breakers
        from app.database.session import reset_engine

        try:
            return await coro
        finally:
            await reset_engine()
            # Circuit breakers hold an asyncio.Lock bound to this run's loop;
            # clear the registry so the next asyncio.run() rebuilds them.
            reset_circuit_breakers()

    return asyncio.run(_wrapped())


@celery.task(name="app.workers.tasks.run_collector")
def run_collector(name: str, limit: int = 100) -> dict:
    return _run(_run_collector(name, limit))


async def _run_collector(name: str, limit: int) -> dict:
    from app.collectors.factory import get_collector_factory
    from app.database.session import get_sessionmaker
    from app.enrichment.engine import get_enrichment_engine
    from app.repositories.audit_repository import AuditRepository
    from app.repositories.correlation_repository import CorrelationRepository
    from app.repositories.enrichment_repository import EnrichmentRepository
    from app.repositories.ioc_repository import IOCRepository
    from app.services.ioc_service import IOCService

    collector = get_collector_factory().build(name)
    indicators = await collector.collect(limit=limit)
    maker = get_sessionmaker()
    async with maker() as session:
        service = IOCService(
            iocs=IOCRepository(session),
            enrichments=EnrichmentRepository(session),
            engine=get_enrichment_engine(),
            audit=AuditRepository(session),
            correlation=CorrelationRepository(session),
        )
        summary = await service.ingest_from_collector(indicators)
        await session.commit()
    log.info("collector_ran", collector=name, **summary)
    return {"collector": name, **summary}


@celery.task(name="app.workers.tasks.cleanup_old_audit_logs")
def cleanup_old_audit_logs(retention_days: int = 90) -> dict:
    return _run(_cleanup_old_audit_logs(retention_days))


async def _cleanup_old_audit_logs(retention_days: int) -> dict:
    from sqlalchemy import delete

    from app.database.session import get_sessionmaker
    from app.models.audit import AuditLog

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    maker = get_sessionmaker()
    async with maker() as session:
        result = await session.execute(delete(AuditLog).where(AuditLog.created_at < cutoff))
        await session.commit()
    deleted = int(getattr(result, "rowcount", 0) or 0)
    log.info("audit_logs_cleaned", deleted=deleted)
    return {"deleted": deleted}
