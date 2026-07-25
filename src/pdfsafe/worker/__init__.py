"""Celery application and task definitions."""

from pdfsafe.worker.celery_app import celery_app

__all__ = ["celery_app"]
