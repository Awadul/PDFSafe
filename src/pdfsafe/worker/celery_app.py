"""Celery application factory and runtime wiring."""

from __future__ import annotations

from typing import Any

from celery import Celery
from celery.signals import setup_logging, task_postrun, task_prerun

from pdfsafe.config import get_settings
from pdfsafe.logging import bind_context, clear_context, configure_logging, get_logger

logger = get_logger(__name__)


def create_celery() -> Celery:
    settings = get_settings()

    app = Celery(
        "pdfsafe",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
        include=["pdfsafe.worker.tasks"],
    )

    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=200,
        worker_hijack_root_logger=False,
        task_time_limit=settings.celery_task_time_limit,
        task_soft_time_limit=settings.celery_task_soft_time_limit,
        result_expires=60 * 60 * 24 * 7,
        broker_connection_retry_on_startup=True,
        task_default_queue="default",
        task_routes={
            "pdfsafe.scan": {"queue": "scans"},
            "pdfsafe.rescan": {"queue": "scans"},
            "pdfsafe.watch_folder": {"queue": "default"},
            "pdfsafe.cleanup": {"queue": "default"},
        },
        beat_schedule=_beat_schedule(settings),
    )
    return app


def _beat_schedule(settings: Any) -> dict[str, Any]:
    schedule: dict[str, Any] = {
        "cleanup-stale-scans": {
            "task": "pdfsafe.cleanup",
            "schedule": 900.0,
            "options": {"queue": "default"},
        }
    }
    if settings.watch_enabled:
        schedule["poll-watch-folder"] = {
            "task": "pdfsafe.watch_folder",
            "schedule": float(settings.watch_poll_seconds),
            "options": {"queue": "default"},
        }
    return schedule


celery_app = create_celery()


@setup_logging.connect
def _configure_celery_logging(**_: Any) -> None:
    """Let structlog own logging instead of Celery's default config."""
    configure_logging()


@task_prerun.connect
def _bind_task_context(task_id: str | None = None, task: Any = None, **_: Any) -> None:
    bind_context(task_id=task_id, task_name=getattr(task, "name", None))


@task_postrun.connect
def _clear_task_context(**_: Any) -> None:
    clear_context()
