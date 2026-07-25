"""Server-rendered dashboard (Jinja2 + HTMX)."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from pdfsafe import __version__
from pdfsafe.api.deps import DBSession
from pdfsafe.config import get_settings
from pdfsafe.enums import ScanStatus, Verdict
from pdfsafe.exceptions import PDFSafeError
from pdfsafe.logging import get_logger
from pdfsafe.schemas.scan import ScanFilter
from pdfsafe.services.ingest import ingest_bytes
from pdfsafe.services.queries import get_scan, get_stats, list_scans
from pdfsafe.worker.tasks import enqueue_scan

logger = get_logger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "web" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["dashboard"], include_in_schema=False)

VERDICT_STYLES: dict[str, str] = {
    Verdict.CLEAN.value: "ok",
    Verdict.LOW_RISK.value: "low",
    Verdict.SUSPICIOUS.value: "warn",
    Verdict.MALICIOUS.value: "bad",
    Verdict.UNKNOWN.value: "muted",
}

templates.env.globals["verdict_styles"] = VERDICT_STYLES
templates.env.globals["app_version"] = __version__


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, session: DBSession) -> HTMLResponse:
    """Dashboard home: statistics plus the most recent scans."""
    stats = await get_stats(session)
    rows, total = await list_scans(session, ScanFilter(limit=25))
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "stats": stats,
            "scans": rows,
            "total": total,
            "verdicts": [v.value for v in Verdict],
            "statuses": [s.value for s in ScanStatus],
            "settings": _public_settings(),
        },
    )


@router.get("/scans", response_class=HTMLResponse)
async def scan_table(
    request: Request,
    session: DBSession,
    verdict: str | None = None,
    status: str | None = None,
    q: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> HTMLResponse:
    """HTMX partial: the filtered scan table."""
    filters = ScanFilter(
        verdict=Verdict(verdict) if verdict else None,
        status=ScanStatus(status) if status else None,
        filename_contains=q or None,
        limit=min(max(limit, 1), 200),
        offset=max(offset, 0),
    )
    rows, total = await list_scans(session, filters)
    return templates.TemplateResponse(
        request,
        "partials/scan_table.html",
        {"scans": rows, "total": total, "offset": filters.offset, "limit": filters.limit},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, session: DBSession, scan_id: uuid.UUID) -> HTMLResponse:
    scan = await get_scan(session, scan_id)
    return templates.TemplateResponse(
        request,
        "detail.html",
        {"scan": scan, "report": scan.report, "assessment": scan.latest_assessment},
    )


@router.get("/scans/{scan_id}/status", response_class=HTMLResponse)
async def scan_status(request: Request, session: DBSession, scan_id: uuid.UUID) -> HTMLResponse:
    """HTMX polling target: a single row that stops polling once terminal."""
    scan = await get_scan(session, scan_id, detail=False)
    return templates.TemplateResponse(request, "partials/scan_status.html", {"scan": scan})


@router.post("/upload", response_class=HTMLResponse)
async def upload(
    request: Request,
    session: DBSession,
    file: Annotated[UploadFile, File()],
    force_ai: Annotated[str | None, Form()] = None,
) -> HTMLResponse:
    """Dashboard upload form target."""
    from pdfsafe.enums import UploadSource

    settings = get_settings()
    data = await file.read(settings.max_upload_bytes + 1)

    try:
        result = await ingest_bytes(
            session,
            data,
            filename=file.filename or "upload.pdf",
            content_type=file.content_type,
            source=UploadSource.DASHBOARD,
            submitted_by="dashboard",
            client_ip=request.client.host if request.client else None,
            correlation_id=getattr(request.state, "correlation_id", None),
        )
    except PDFSafeError as exc:
        return templates.TemplateResponse(
            request, "partials/flash.html", {"level": "error", "message": exc.message}, status_code=200
        )

    if not result.is_duplicate:
        await session.commit()
        task_id = enqueue_scan(result.scan.id, force_ai=bool(force_ai))
        result.scan.task_id = task_id
        await session.commit()
        message = f"{result.scan.filename} queued for analysis."
    else:
        message = f"{result.scan.filename} was already scanned; showing the previous verdict."

    return templates.TemplateResponse(
        request,
        "partials/flash.html",
        {"level": "ok", "message": message, "scan": result.scan},
    )


@router.post("/scans/{scan_id}/rescan")
async def rescan(session: DBSession, scan_id: uuid.UUID) -> RedirectResponse:
    scan = await get_scan(session, scan_id, detail=False)
    scan.status = ScanStatus.PENDING
    await session.commit()
    enqueue_scan(scan.id, force_ai=True)
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


def _public_settings() -> dict[str, Any]:
    settings = get_settings()
    return {
        "env": str(settings.env),
        "ai_enabled": settings.ai_enabled,
        "ai_provider": settings.ai_provider.value,
        "escalate_min": settings.ai_escalate_min_score,
        "escalate_max": settings.ai_escalate_max_score,
        "max_upload_mb": round(settings.max_upload_bytes / (1024 * 1024), 1),
    }
