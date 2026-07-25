"""Liveness, readiness and metrics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Response
from sqlalchemy import text

from pdfsafe import __version__
from pdfsafe.ai.registry import get_provider
from pdfsafe.api.deps import DBSession
from pdfsafe.config import get_settings
from pdfsafe.logging import get_logger
from pdfsafe.metrics import render_metrics
from pdfsafe.schemas.scan import HealthResponse

logger = get_logger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health/live", response_model=HealthResponse, summary="Liveness probe")
async def live() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(status="ok", version=__version__, env=str(settings.env))


@router.get("/health/ready", response_model=HealthResponse, summary="Readiness probe")
async def ready(session: DBSession, response: Response) -> HealthResponse:
    settings = get_settings()
    checks: dict[str, str] = {}

    try:
        await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {type(exc).__name__}"

    checks["redis"] = _check_redis(settings.redis_url)
    checks["storage"] = _check_storage()

    provider = get_provider()
    checks["ai"] = "disabled" if provider.name == "null" else f"ok:{provider.name}"

    failed = [name for name, value in checks.items() if value.startswith("error")]
    if failed:
        response.status_code = 503
        status = "error" if "database" in failed else "degraded"
    else:
        status = "ok"

    return HealthResponse(status=status, version=__version__, env=str(settings.env), checks=checks)


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    settings = get_settings()
    if not settings.metrics_enabled:
        return Response(status_code=404)
    payload, content_type = render_metrics()
    return Response(content=payload, media_type=content_type)


def _check_redis(url: str) -> str:
    try:
        import redis

        client = redis.Redis.from_url(url, socket_timeout=1)
        client.ping()
        return "ok"
    except Exception as exc:
        return f"error: {type(exc).__name__}"


def _check_storage() -> str:
    try:
        from pdfsafe.storage import get_storage

        storage = get_storage()
        storage.exists("__healthcheck__")
        return f"ok:{storage.name}"
    except Exception as exc:
        return f"error: {type(exc).__name__}"
