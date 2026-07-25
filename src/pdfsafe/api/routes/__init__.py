"""API routers."""

from pdfsafe.api.routes.dashboard import router as dashboard_router
from pdfsafe.api.routes.health import router as health_router
from pdfsafe.api.routes.scans import router as scans_router

__all__ = ["dashboard_router", "health_router", "scans_router"]
