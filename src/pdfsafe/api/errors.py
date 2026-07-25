"""Exception handlers mapping domain errors onto HTTP responses."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from pdfsafe.exceptions import PDFSafeError, RateLimitExceededError
from pdfsafe.logging import get_logger

logger = get_logger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(PDFSafeError)
    async def _domain_error(request: Request, exc: PDFSafeError) -> JSONResponse:
        payload = exc.to_dict()
        payload["correlation_id"] = getattr(request.state, "correlation_id", None)

        if exc.http_status >= 500:
            logger.error("request_failed", code=exc.code, message=exc.message, path=request.url.path)
        else:
            logger.info("request_rejected", code=exc.code, path=request.url.path)

        headers = {}
        if isinstance(exc, RateLimitExceededError):
            headers["Retry-After"] = str(exc.details.get("retry_after", 60))

        return JSONResponse(status_code=exc.http_status, content=payload, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message": "The request payload failed validation.",
                "details": {"errors": exc.errors()[:20]},
                "correlation_id": getattr(request.state, "correlation_id", None),
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "message": str(exc.detail),
                "correlation_id": getattr(request.state, "correlation_id", None),
            },
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_exception", path=request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": "An unexpected error occurred.",
                "correlation_id": getattr(request.state, "correlation_id", None),
            },
        )
