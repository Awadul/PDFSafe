"""Database package: declarative base, ORM models and session factories.

``pdfsafe.db.session`` pulls in SQLAlchemy's asyncio extension, which the
desktop build neither needs nor installs. It is therefore exposed lazily
through ``__getattr__`` so that importing this package does not drag async
machinery (and greenlet) into the frozen executable.
"""

from typing import Any

from pdfsafe.db.base import Base

__all__ = [
    "Base",
    "get_session",
    "get_sessionmaker",
    "session_scope",
    "sync_session_scope",
]

_LAZY = {
    "get_session",
    "get_sessionmaker",
    "session_scope",
    "sync_session_scope",
    "get_engine",
    "get_sync_engine",
    "dispose_engine",
}


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        from pdfsafe.db import session as _session

        return getattr(_session, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
