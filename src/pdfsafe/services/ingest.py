"""Ingestion: validate, store and enqueue an uploaded file."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from anyio import to_thread
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pdfsafe.analysis.pipeline import looks_like_pdf
from pdfsafe.analysis.utils import md5_hex, sha256_hex
from pdfsafe.config import get_settings
from pdfsafe.db.models import AuditEvent, Scan
from pdfsafe.enums import ScanStatus, UploadSource
from pdfsafe.exceptions import FileTooLargeError, UnsupportedFileTypeError, ValidationError
from pdfsafe.logging import get_logger
from pdfsafe.metrics import upload_bytes, uploads_rejected_total, uploads_total
from pdfsafe.storage import get_storage

logger = get_logger(__name__)


@dataclass(slots=True)
class IngestResult:
    """Outcome of an ingestion attempt."""

    scan: Scan
    is_duplicate: bool
    duplicate_of: uuid.UUID | None = None


async def ingest_bytes(
    session: AsyncSession,
    data: bytes,
    *,
    filename: str,
    content_type: str | None = None,
    source: UploadSource = UploadSource.API,
    submitted_by: str | None = None,
    client_ip: str | None = None,
    correlation_id: str | None = None,
    deduplicate: bool = True,
) -> IngestResult:
    """Validate, persist and register a file for scanning.

    The returned :class:`Scan` is flushed but not committed; the caller owns the
    transaction so the enqueue step can be tied to it.
    """
    settings = get_settings()

    _validate(data, filename, content_type, settings.max_upload_bytes, settings.allowed_content_types)

    digest = sha256_hex(data)

    if deduplicate:
        existing = await _find_completed_duplicate(session, digest)
        if existing is not None:
            logger.info("upload_deduplicated", sha256=digest[:12], original=str(existing.id))
            uploads_total.labels(source=source.value).inc()
            return IngestResult(scan=existing, is_duplicate=True, duplicate_of=existing.id)

    storage = get_storage()
    key = storage.build_key(digest, filename)
    stored = await to_thread.run_sync(storage.save, key, data)

    scan = Scan(
        filename=filename[:512],
        content_type=content_type,
        file_size=len(data),
        sha256=digest,
        md5=md5_hex(data),
        storage_key=stored.key,
        source=source,
        submitted_by=submitted_by,
        client_ip=client_ip,
        correlation_id=correlation_id,
        status=ScanStatus.PENDING,
    )
    session.add(scan)
    await session.flush()

    session.add(
        AuditEvent(
            scan_id=scan.id,
            event="scan.submitted",
            actor=submitted_by or source.value,
            message=f"{filename} accepted for analysis",
            payload={"sha256": digest, "size": len(data), "source": source.value},
        )
    )

    uploads_total.labels(source=source.value).inc()
    upload_bytes.observe(len(data))
    logger.info(
        "upload_accepted",
        scan_id=str(scan.id),
        sha256=digest[:12],
        filename=filename,
        size=len(data),
        source=source.value,
    )
    return IngestResult(scan=scan, is_duplicate=False)


def _validate(
    data: bytes,
    filename: str,
    content_type: str | None,
    max_bytes: int,
    allowed_types: list[str],
) -> None:
    if not data:
        uploads_rejected_total.labels(reason="empty").inc()
        raise ValidationError("The uploaded file is empty.")

    if len(data) > max_bytes:
        uploads_rejected_total.labels(reason="too_large").inc()
        raise FileTooLargeError(
            f"File is {len(data)} bytes; the limit is {max_bytes} bytes.",
            size=len(data),
            limit=max_bytes,
        )

    if not filename or filename.strip() in {".", "..", "/"}:
        uploads_rejected_total.labels(reason="bad_filename").inc()
        raise ValidationError("A filename is required.")

    if content_type and allowed_types and content_type.split(";")[0].strip() not in allowed_types:
        uploads_rejected_total.labels(reason="content_type").inc()
        raise UnsupportedFileTypeError(
            f"Content type '{content_type}' is not accepted.", content_type=content_type
        )

    if not looks_like_pdf(data):
        uploads_rejected_total.labels(reason="not_pdf").inc()
        raise UnsupportedFileTypeError(
            "The file does not start with a %PDF- header within the first 1024 bytes."
        )


async def _find_completed_duplicate(session: AsyncSession, digest: str) -> Scan | None:
    """Return a previous *completed* scan of identical content, if any."""
    statement = (
        select(Scan)
        .where(Scan.sha256 == digest, Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    return (await session.execute(statement)).scalar_one_or_none()
