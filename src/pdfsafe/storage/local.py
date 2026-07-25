"""Filesystem storage backend."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path

from pdfsafe.exceptions import StorageError
from pdfsafe.logging import get_logger
from pdfsafe.storage.base import ObjectStorage, StoredObject

logger = get_logger(__name__)


class LocalStorage(ObjectStorage):
    """Stores objects under ``root``. Writes are atomic (temp file + rename)."""

    name = "local"

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------- helpers --
    def _resolve(self, key: str) -> Path:
        candidate = (self.root / key).resolve()
        if not candidate.is_relative_to(self.root):
            raise StorageError("Refusing to access a path outside the storage root", key=key)
        return candidate

    # ---------------------------------------------------------- operations --
    def save(self, key: str, data: bytes) -> StoredObject:
        target = self._resolve(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd, tmp_name = tempfile.mkstemp(dir=target.parent, suffix=".part")
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, target)
            os.chmod(target, 0o640)
        except OSError as exc:  # pragma: no cover - filesystem failure
            raise StorageError(f"Could not write {key}: {exc}") from exc

        logger.debug("stored_object", key=key, size=len(data), backend=self.name)
        return StoredObject(
            key=key,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            backend=self.name,
            stored_at=StoredObject.now(),
        )

    def load(self, key: str) -> bytes:
        target = self._resolve(key)
        try:
            return target.read_bytes()
        except FileNotFoundError as exc:
            raise StorageError(f"Object not found: {key}") from exc
        except OSError as exc:  # pragma: no cover
            raise StorageError(f"Could not read {key}: {exc}") from exc

    def delete(self, key: str) -> None:
        target = self._resolve(key)
        target.unlink(missing_ok=True)

    def exists(self, key: str) -> bool:
        return self._resolve(key).is_file()

    def local_path(self, key: str) -> Path:
        target = self._resolve(key)
        if not target.is_file():
            raise StorageError(f"Object not found: {key}")
        return target

    def quarantine(self, key: str, quarantine_root: Path) -> Path:
        """Move an object into an isolated directory (non-executable, 0600)."""
        source = self.local_path(key)
        destination = Path(quarantine_root).resolve() / key
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        os.chmod(destination, 0o600)
        logger.info("object_quarantined", key=key, path=str(destination))
        return destination
