"""Scan submission and retrieval endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile, status

from pdfsafe.api.deps import CurrentPrincipal, DBSession, RateLimited
from pdfsafe.config import get_settings
from pdfsafe.enums import ScanStatus, UploadSource, Verdict
from pdfsafe.exceptions import FileTooLargeError, ValidationError
from pdfsafe.logging import get_logger
from pdfsafe.schemas.scan import (
    ErrorResponse,
    PaginatedScans,
    ScanDetail,
    ScanFilter,
    ScanReviewRequest,
    ScanStats,
    ScanSubmitResponse,
    ScanSummary,
)
from pdfsafe.services.ingest import ingest_bytes
from pdfsafe.services.queries import get_scan, get_stats, list_scans
from pdfsafe.worker.tasks import enqueue_scan

logger = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/scans",
    tags=["scans"],
    dependencies=[RateLimited],
    responses={
        401: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
)


@router.post(
    "",
    response_model=ScanSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a PDF for analysis",
    responses={413: {"model": ErrorResponse}, 415: {"model": ErrorResponse}},
)
async def submit_scan(
    request: Request,
    session: DBSession,
    principal: CurrentPrincipal,
    file: Annotated[UploadFile, File(description="The PDF to analyse.")],
    force_ai: Annotated[bool, Query(description="Bypass the cost gate and always run AI review.")] = False,
    deduplicate: Annotated[bool, Query(description="Reuse a previous verdict for identical content.")] = True,
) -> ScanSubmitResponse:
    """Accept a PDF, store it and queue analysis.

    Returns ``202 Accepted`` immediately; poll ``GET /api/v1/scans/{id}`` or
    watch the dashboard for the verdict.
    """
    settings = get_settings()
    data = await _read_upload(file, settings.max_upload_bytes)

    result = await ingest_bytes(
        session,
        data,
        filename=file.filename or "upload.pdf",
        content_type=file.content_type,
        source=UploadSource.API,
        submitted_by=principal.name,
        client_ip=request.client.host if request.client else None,
        correlation_id=getattr(request.state, "correlation_id", None),
        deduplicate=deduplicate,
    )

    if result.is_duplicate:
        return ScanSubmitResponse(
            id=result.scan.id,
            status=result.scan.status,
            filename=result.scan.filename,
            sha256=result.scan.sha256,
            file_size=result.scan.file_size,
            duplicate_of=result.duplicate_of,
            created_at=result.scan.created_at,
        )

    await session.commit()

    task_id = enqueue_scan(result.scan.id, force_ai=force_ai)
    result.scan.task_id = task_id
    await session.commit()

    return ScanSubmitResponse(
        id=result.scan.id,
        status=result.scan.status,
        filename=result.scan.filename,
        sha256=result.scan.sha256,
        file_size=result.scan.file_size,
        task_id=task_id,
        created_at=result.scan.created_at,
    )


@router.get("", response_model=PaginatedScans, summary="List scans")
async def list_all(
    session: DBSession,
    filters: Annotated[ScanFilter, Depends()],
) -> PaginatedScans:
    rows, total = await list_scans(session, filters)
    return PaginatedScans(
        items=[ScanSummary.model_validate(row) for row in rows],
        total=total,
        limit=filters.limit,
        offset=filters.offset,
    )


@router.get("/stats", response_model=ScanStats, summary="Aggregate statistics")
async def stats(session: DBSession) -> ScanStats:
    return await get_stats(session)


@router.get(
    "/{scan_id}",
    response_model=ScanDetail,
    summary="Fetch a scan",
    responses={404: {"model": ErrorResponse}},
)
async def get_one(session: DBSession, scan_id: uuid.UUID) -> ScanDetail:
    scan = await get_scan(session, scan_id)
    return ScanDetail.model_validate(scan)


@router.post(
    "/{scan_id}/rescan",
    response_model=ScanSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Re-run analysis",
    responses={404: {"model": ErrorResponse}},
)
async def rescan(
    session: DBSession,
    scan_id: uuid.UUID,
    force_ai: Annotated[bool, Query()] = True,
) -> ScanSubmitResponse:
    scan = await get_scan(session, scan_id, detail=False)
    scan.status = ScanStatus.PENDING
    scan.error_code = None
    scan.error_message = None
    await session.commit()

    task_id = enqueue_scan(scan.id, force_ai=force_ai)
    scan.task_id = task_id
    await session.commit()

    return ScanSubmitResponse(
        id=scan.id,
        status=scan.status,
        filename=scan.filename,
        sha256=scan.sha256,
        file_size=scan.file_size,
        task_id=task_id,
        created_at=scan.created_at,
    )


@router.post(
    "/{scan_id}/review",
    response_model=ScanDetail,
    summary="Record an analyst override",
    responses={404: {"model": ErrorResponse}},
)
async def review(
    session: DBSession,
    principal: CurrentPrincipal,
    scan_id: uuid.UUID,
    payload: ScanReviewRequest,
) -> ScanDetail:
    """Override the automated verdict. The original decision is kept for audit."""
    from pdfsafe.db.models import AuditEvent
    from pdfsafe.enums import DecisionSource

    scan = await get_scan(session, scan_id)
    previous = scan.verdict

    scan.verdict = payload.verdict
    scan.reviewed = True
    scan.review_note = payload.note or None
    scan.decided_by = DecisionSource.MANUAL
    if payload.quarantine is not None:
        scan.quarantined = payload.quarantine
    if payload.verdict is Verdict.CLEAN:
        scan.quarantined = False

    session.add(
        AuditEvent(
            scan_id=scan.id,
            event="scan.reviewed",
            actor=principal.name,
            message=payload.note or f"Verdict changed to {payload.verdict.value}",
            payload={"from": previous.value, "to": payload.verdict.value},
        )
    )
    await session.commit()
    await session.refresh(scan)
    return ScanDetail.model_validate(scan)


# ---------------------------------------------------------------------------
async def _read_upload(file: UploadFile, max_bytes: int) -> bytes:
    """Stream the upload into memory with a hard ceiling."""
    if file is None:
        raise ValidationError("A file is required.")

    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(1024 * 256):
        total += len(chunk)
        if total > max_bytes:
            raise FileTooLargeError(
                f"Upload exceeds the {max_bytes} byte limit.", limit=max_bytes
            )
        chunks.append(chunk)
    await file.close()
    return b"".join(chunks)
