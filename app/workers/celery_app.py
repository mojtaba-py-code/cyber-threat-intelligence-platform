"""Celery application and beat schedule.

Background jobs periodically run collectors and housekeeping. Configured from the
same :class:`Settings` as the API. Run:
    celery -A app.workers.celery_app.celery worker --loglevel=info
    celery -A app.workers.celery_app.celery beat   --loglevel=info
"""

from __future__ import annotations

from celery import Celery

from app.config import get_settings

settings = get_settings()

celery = Celery(
    "threat_intel_platform",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=300,
    task_soft_time_limit=270,
)

celery.conf.beat_schedule = {
    "collect-urlhaus": {
        "task": "app.workers.tasks.run_collector",
        "schedule": 900.0,  # every 15 minutes
        "args": ("urlhaus", 100),
    },
    "collect-cisa-kev": {
        "task": "app.workers.tasks.run_collector",
        "schedule": 3600.0,
        "args": ("cisa_kev", 200),
    },
    "cleanup-audit-logs": {
        "task": "app.workers.tasks.cleanup_old_audit_logs",
        "schedule": 86400.0,
    },
}
