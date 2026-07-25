"""HTTP middleware: correlation ids, access logs, metrics and security headers."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from pdfsafe.logging import clear_context, get_logger, new_request_context
from pdfsafe.metrics import http_request_duration_seconds, http_requests_total

logger = get_logger(__name__)

CORRELATION_HEADER = "X-Correlation-ID"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

Handler = Callable[[Request], Awaitable[Response]]


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a correlation id, log the request and record metrics."""

    def __init__(self, app: ASGIApp, *, metrics_path: str = "/metrics") -> None:
        super().__init__(app)
        self.metrics_path = metrics_path

    async def dispatch(self, request: Request, call_next: Handler) -> Response:
        incoming = request.headers.get(CORRELATION_HEADER)
        correlation_id = new_request_context(
            correlation_id=incoming,
            method=request.method,
            path=request.url.path,
        )
        request.state.correlation_id = correlation_id

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            self._record(request, 500, time.perf_counter() - started)
            clear_context()
            raise

        elapsed = time.perf_counter() - started
        self._record(request, response.status_code, elapsed)

        response.headers[CORRELATION_HEADER] = correlation_id
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)

        if request.url.path != self.metrics_path:
            logger.info(
                "request_completed",
                status=response.status_code,
                duration_ms=int(elapsed * 1000),
            )
        clear_context()
        return response

    def _record(self, request: Request, status: int, elapsed: float) -> None:
        route = request.scope.get("route")
        path = getattr(route, "path", request.url.path)
        if path == self.metrics_path:
            return
        http_requests_total.labels(method=request.method, path=path, status=str(status)).inc()
        http_request_duration_seconds.labels(method=request.method, path=path).observe(elapsed)


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies before they are buffered into memory."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Handler) -> Response:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=413,
                content={
                    "error": "file_too_large",
                    "message": f"Request body exceeds {self.max_bytes} bytes.",
                },
            )
        return await call_next(request)
