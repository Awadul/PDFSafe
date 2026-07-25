"""Celery tasks."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select

from pdfsafe.config import get_settings
from pdfsafe.db.models import Scan
from pdfsafe.db.session import sync_session_scope
from pdfsafe.enums import ScanStatus, UploadSource, Verdict
from pdfsafe.exceptions import ScanNotFoundError
from pdfsafe.logging import get_logger
from pdfsafe.services.processing import process_scan

logger = get_logger(__name__)

#: Scans stuck in a non-terminal state for longer than this are failed.
STALE_AFTER = timedelta(minutes=30)


@shared_task(name="pdfsafe.scan", bind=True, max_retries=3, acks_late=True)
def scan_task(self: Any, scan_id: str, *, force_ai: bool = False) -> dict[str, Any]:
    """Analyse one uploaded file.

    Retries are explicit rather than declarative: a missing scan row or a
    timeout is permanent, while transport-level failures are worth another go.
    """
    logger.info("scan_task_started", scan_id=scan_id, attempt=self.request.retries + 1)
    try:
        verdict = process_scan(scan_id, force_ai=force_ai)
    except ScanNotFoundError:
        logger.warning("scan_task_missing_row", scan_id=scan_id)
        return {"scan_id": scan_id, "verdict": Verdict.UNKNOWN.value, "error": "not_found"}
    except SoftTimeLimitExceeded:
        logger.error("scan_task_timeout", scan_id=scan_id)
        _mark_failed(scan_id, "analysis_timeout", "Analysis exceeded the worker time limit")
        raise
    except Exception as exc:
        countdown = min(300, 2 ** (self.request.retries + 1) * 5)
        logger.warning(
            "scan_task_retrying",
            scan_id=scan_id,
            error=str(exc),
            attempt=self.request.retries + 1,
            countdown=countdown,
        )
        raise self.retry(exc=exc, countdown=countdown) from exc
    return {"scan_id": scan_id, "verdict": verdict.value}


@shared_task(name="pdfsafe.rescan", bind=True, max_retries=2)
def rescan_task(self: Any, scan_id: str, *, force_ai: bool = True) -> dict[str, Any]:
    """Re-run analysis for an existing scan, optionally forcing an AI review."""
    verdict = process_scan(scan_id, force_ai=force_ai)
    return {"scan_id": scan_id, "verdict": verdict.value}


@shared_task(name="pdfsafe.watch_folder")
def watch_folder_task() -> dict[str, Any]:
    """Ingest any new PDFs dropped into the watch directory.

    Files are moved into a ``.processed`` subdirectory after ingestion so the
    task is idempotent across runs.
    """
    settings = get_settings()
    watch_dir = Path(settings.watch_dir)
    if not watch_dir.is_dir():
        return {"ingested": 0, "reason": "watch_dir_missing"}

    processed_dir = watch_dir / ".processed"
    processed_dir.mkdir(exist_ok=True)

    ingested: list[str] = []
    for path in sorted(watch_dir.glob("*.pdf")):
        if not path.is_file():
            continue
        try:
            scan_id = _ingest_local_file(path, settings)
            path.rename(processed_dir / path.name)
            ingested.append(str(scan_id))
        except Exception as exc:
            logger.warning("watch_ingest_failed", path=str(path), error=str(exc))

    if ingested:
        logger.info("watch_folder_ingested", count=len(ingested))
    return {"ingested": len(ingested), "scan_ids": ingested}


@shared_task(name="pdfsafe.cleanup")
def cleanup_task() -> dict[str, int]:
    """Fail scans that have been stuck in a non-terminal state."""
    cutoff = datetime.now(UTC) - STALE_AFTER
    failed = 0
    with sync_session_scope() as session:
        stale = (
            session.execute(
                select(Scan).where(
                    Scan.status.in_([ScanStatus.PENDING, ScanStatus.ANALYZING, ScanStatus.AI_REVIEW]),
                    Scan.created_at < cutoff,
                )
            )
            .scalars()
            .all()
        )
        for scan in stale:
            scan.status = ScanStatus.FAILED
            scan.verdict = Verdict.UNKNOWN
            scan.error_code = "stale"
            scan.error_message = "Scan exceeded the maximum processing window"
            scan.completed_at = datetime.now(UTC)
            failed += 1

    if failed:
        logger.warning("stale_scans_failed", count=failed)
    return {"failed": failed}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ingest_local_file(path: Path, settings: Any) -> uuid.UUID:
    """Synchronous ingestion used by the folder watcher."""
    from pdfsafe.analysis.utils import md5_hex, sha256_hex
    from pdfsafe.db.models import AuditEvent
    from pdfsafe.storage import get_storage

    data = path.read_bytes()
    if len(data) > settings.max_upload_bytes:
        raise ValueError(f"{path.name} exceeds the size limit")
    if b"%PDF-" not in data[:1024]:
        raise ValueError(f"{path.name} is not a PDF")

    digest = sha256_hex(data)
    storage = get_storage()
    stored = storage.save(storage.build_key(digest, path.name), data)

    with sync_session_scope() as session:
        scan = Scan(
            filename=path.name[:512],
            content_type="application/pdf",
            file_size=len(data),
            sha256=digest,
            md5=md5_hex(data),
            storage_key=stored.key,
            source=UploadSource.WATCH_FOLDER,
            status=ScanStatus.PENDING,
        )
        session.add(scan)
        session.flush()
        session.add(
            AuditEvent(
                scan_id=scan.id,
                event="scan.submitted",
                actor="watch_folder",
                message=f"{path.name} picked up from the watch folder",
                payload={"sha256": digest, "size": len(data)},
            )
        )
        scan_id = scan.id

    scan_task.apply_async(args=[str(scan_id)], queue="scans")
    return scan_id


def _mark_failed(scan_id: str, code: str, message: str) -> None:
    with sync_session_scope() as session:
        scan = session.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            return
        scan.status = ScanStatus.FAILED
        scan.verdict = Verdict.UNKNOWN
        scan.error_code = code
        scan.error_message = message
        scan.completed_at = datetime.now(UTC)


def enqueue_scan(scan_id: uuid.UUID | str, *, force_ai: bool = False) -> str:
    """Queue a scan and return the Celery task id."""
    async_result = scan_task.apply_async(
        args=[str(scan_id)], kwargs={"force_ai": force_ai}, queue="scans"
    )
    return str(async_result.id)
