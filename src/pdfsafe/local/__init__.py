"""Single-machine runtime used by the desktop application.

Everything here replaces the server stack for a locally installed build:

===================  ==========================  ==========================
Concern              Desktop (this package)      Server (optional target)
===================  ==========================  ==========================
Database             SQLite (WAL)                PostgreSQL + Alembic
Queue                in-process thread pool      Celery + Redis
Isolation            spawned child process       container boundary
Secrets              OS credential manager       environment variables
===================  ==========================  ==========================

The analysis and AI packages are shared verbatim between both targets.
"""

from pdfsafe.local.database import LocalDatabase, get_database
from pdfsafe.local.engine import LocalScanEngine, ScanEvent, ScanEventKind
from pdfsafe.local.repository import ScanRepository

__all__ = [
    "LocalDatabase",
    "LocalScanEngine",
    "ScanEvent",
    "ScanEventKind",
    "ScanRepository",
    "get_database",
]
