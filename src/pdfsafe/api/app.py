"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from pdfsafe import __version__
from pdfsafe.api.errors import register_exception_handlers
from pdfsafe.api.middleware import MaxBodySizeMiddleware, RequestContextMiddleware
from pdfsafe.api.routes import dashboard_router, health_router, scans_router
from pdfsafe.config import Settings, get_settings
from pdfsafe.db.session import dispose_engine
from pdfsafe.logging import configure_logging, get_logger

logger = get_logger(__name__)

STATIC_DIR = Path(__file__).resolve().parents[1] / "web" / "static"

DESCRIPTION = """\
PDFSafe ingests PDF files, performs deep structural analysis, and escalates
ambiguous cases to an LLM for a final malware verdict.

**Pipeline**

1. Upload is validated, hashed and stored.
2. Static analysis extracts JavaScript, automatic actions, embedded files,
   URLs and YARA matches.
3. A heuristic engine scores the evidence 0-100.
4. Only files in the ambiguous score band are sent to the AI, which keeps token
   spend proportional to the number of genuinely uncertain files.
5. The verdicts are fused and persisted, with a full audit trail.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings)

    from pdfsafe.ai.registry import get_provider
    from pdfsafe.analysis.yara_engine import get_rules

    provider = get_provider()
    rules_loaded = get_rules() is not None

    logger.info(
        "application_startup",
        version=__version__,
        env=str(settings.env),
        storage=settings.storage_backend.value,
        ai_provider=provider.name,
        ai_enabled=settings.ai_enabled,
        yara=rules_loaded,
    )
    try:
        yield
    finally:
        await dispose_engine()
        logger.info("application_shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title="PDFSafe",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        contact={"name": "PDFSafe"},
    )

    app.add_middleware(RequestContextMiddleware, metrics_path=settings.metrics_path)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_upload_bytes)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
            expose_headers=["X-Correlation-ID"],
        )

    register_exception_handlers(app)

    app.include_router(health_router)
    app.include_router(scans_router)
    app.include_router(dashboard_router)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


app = create_app()
