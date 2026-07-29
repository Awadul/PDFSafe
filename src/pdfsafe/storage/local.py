"""Filesystem storage backend."""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import tempfile
from pathlib import Path

from pdfsafe.exceptions import StorageError
from pdfsafe.logging import get_logger
from pdfsafe.storage.base import ObjectStorage, StoredObject

logger = get_logger(__name__)

#: Appended to quarantined files so the operating system no longer treats them
#: as PDFs. Shared with the engine, which applies it to the user's own copy.
QUARANTINE_SUFFIX = ".quarantine"


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
        """Move the stored copy into the quarantine tree and defuse it.

        ``ab/cd/<sha>.pdf`` becomes ``ab/cd/<sha>.pdf.quarantine``. Losing the
        ``.pdf`` association is what actually prevents the file being opened by
        a double-click: on Windows ``os.chmod`` can only clear the write bit, it
        sets no ACL and cannot mark a file non-executable, so the read-only flag
        below is a speed bump rather than a control.
        """
        source = self.local_path(key)
        dest_key = key if key.endswith(QUARANTINE_SUFFIX) else f"{key}{QUARANTINE_SUFFIX}"
        destination = Path(quarantine_root).resolve() / dest_key
        destination.parent.mkdir(parents=True, exist_ok=True)

        # Re-quarantining the same content is normal: keys are content hashes, so
        # an existing entry holds identical bytes. It is also read-only from the
        # previous run, and Windows refuses to move onto a read-only file - clear
        # it first or the second quarantine of a file silently fails.
        if destination.exists():
            try:
                os.chmod(destination, 0o600)
                destination.unlink()
            except OSError as exc:
                raise StorageError(
                    f"Could not replace the existing quarantine entry for {key}: {exc}"
                ) from exc

        shutil.move(str(source), str(destination))

        try:
            os.chmod(destination, 0o400)
        except OSError as exc:  # pragma: no cover - unusual filesystem
            logger.warning("quarantine_chmod_failed", path=str(destination), error=str(exc))

        logger.info("object_quarantined", key=key, path=str(destination))
        return destination

    def release(self, quarantined_path: Path, key: str) -> Path:
        """Move a quarantined object back into normal storage.

        Used when an analyst overrides the verdict; without it "mark as safe"
        would clear the flag in the database while leaving the file locked away.
        """
        target = self._resolve(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(quarantined_path, 0o640)
        shutil.move(str(quarantined_path), str(target))
        logger.info("object_released", key=key)
        return target
