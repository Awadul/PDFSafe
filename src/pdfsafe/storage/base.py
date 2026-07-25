"""Storage abstraction.

Implementations must be safe to call from both async request handlers and
synchronous Celery tasks, so the interface is deliberately blocking and callers
offload to a thread when needed (``anyio.to_thread`` / ``run_in_executor``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class StoredObject:
    """Metadata describing a persisted artifact."""

    key: str
    size: int
    sha256: str
    backend: str
    stored_at: datetime

    @staticmethod
    def now() -> datetime:
        return datetime.now(UTC)


class ObjectStorage(ABC):
    """Minimal blob-store interface used by the ingestion and worker layers."""

    name: str = "base"

    @abstractmethod
    def save(self, key: str, data: bytes) -> StoredObject:
        """Persist ``data`` under ``key`` and return its metadata."""

    @abstractmethod
    def load(self, key: str) -> bytes:
        """Return the bytes stored under ``key``."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove ``key``. Must not raise when the key is absent."""

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Return whether ``key`` is present."""

    @abstractmethod
    def local_path(self, key: str) -> Path:
        """Return a filesystem path for ``key``.

        Remote backends materialise the object into a temporary file; callers
        are responsible for cleaning that file up when the backend is not local.
        """

    def build_key(self, sha256: str, filename: str) -> str:
        """Content-addressed key with a sharded prefix to avoid huge directories."""
        suffix = Path(filename).suffix.lower() or ".pdf"
        if suffix not in {".pdf"}:
            suffix = ".pdf"
        return f"{sha256[:2]}/{sha256[2:4]}/{sha256}{suffix}"
