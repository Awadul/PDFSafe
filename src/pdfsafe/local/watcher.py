"""Folder watching.

Watches user-chosen folders (typically Downloads) and submits new PDFs.

The subtlety is that a file appears on disk before it is finished downloading.
Submitting immediately would analyse a truncated file and report a parse error,
so new paths are held in a pending set and only submitted once their size has
been stable across two consecutive checks.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pdfsafe.config import Settings, get_settings
from pdfsafe.enums import UploadSource
from pdfsafe.local.engine import LocalScanEngine
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

#: Suffixes browsers and download managers use for incomplete files.
PARTIAL_SUFFIXES = frozenset(
    {".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload", ".!ut"}
)

STABLE_CHECKS_REQUIRED = 2
MAX_SETTLE_SECONDS = 120


class FolderWatcher:
    """Polls configured folders and feeds new PDFs to the engine.

    Polling rather than filesystem events: it is a few lines instead of a
    platform matrix, it survives network drives where events are unreliable,
    and at a 15-second interval the cost is immeasurable.
    """

    def __init__(
        self,
        engine: LocalScanEngine,
        settings: Settings | None = None,
    ) -> None:
        self.engine = engine
        self.settings = settings or get_settings()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._seen: set[str] = set()
        self._pending: dict[str, tuple[int, int, float]] = {}
        self._lock = threading.Lock()

    # ---------------------------------------------------------- lifecycle --
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        folders = self.folders()
        if not folders:
            logger.info("watcher_not_started", reason="no folders configured")
            return

        # Treat everything already present as seen, so enabling the watcher
        # does not suddenly scan a decade of downloads.
        self._prime(folders)

        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="pdfsafe-watcher", daemon=True)
        self._thread.start()
        logger.info(
            "watcher_started",
            folders=[str(f) for f in folders],
            interval=self.settings.watch_poll_seconds,
            recursive=self.settings.watch_recursive,
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("watcher_stopped")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def refresh(self) -> None:
        """Restart with the current configuration (called after settings change)."""
        was_running = self.is_running
        self.stop()
        self.settings = get_settings()
        with self._lock:
            self._seen.clear()
            self._pending.clear()
        if was_running or self.settings.watch_enabled:
            self.start()

    # -------------------------------------------------------------- config --
    def folders(self) -> list[Path]:
        resolved: list[Path] = []
        for entry in self.settings.watch_folders:
            try:
                path = Path(entry).expanduser()
            except (OSError, ValueError):
                continue
            if path.is_dir():
                resolved.append(path)
            else:
                logger.warning("watch_folder_missing", folder=entry)
        return resolved

    # ---------------------------------------------------------------- loop --
    def _loop(self) -> None:
        interval = max(2, self.settings.watch_poll_seconds)
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # pragma: no cover - never kill the watcher
                logger.exception("watcher_tick_failed")
            self._stop.wait(interval)

    def _tick(self) -> None:
        for path in self._candidates(self.folders()):
            key = str(path)
            with self._lock:
                if key in self._seen:
                    continue

            if self._is_settled(path):
                with self._lock:
                    self._seen.add(key)
                    self._pending.pop(key, None)
                logger.info("watch_file_detected", path=key)
                self.engine.submit_file(path, source=UploadSource.WATCH_FOLDER)

    def _candidates(self, folders: Iterable[Path]) -> list[Path]:
        pattern = "**/*.pdf" if self.settings.watch_recursive else "*.pdf"
        found: list[Path] = []
        for folder in folders:
            try:
                for path in folder.glob(pattern):
                    if not path.is_file():
                        continue
                    if path.suffix.lower() in PARTIAL_SUFFIXES:
                        continue
                    if any(part.startswith(".") for part in path.parts[-2:]):
                        continue
                    found.append(path)
            except OSError as exc:  # pragma: no cover - permissions, unmounted drive
                logger.warning("watch_folder_unreadable", folder=str(folder), error=str(exc))
        return found

    def _is_settled(self, path: Path) -> bool:
        """True once the file's size has been unchanged for two checks."""
        key = str(path)
        try:
            size = path.stat().st_size
        except OSError:
            return False

        now = time.monotonic()
        with self._lock:
            previous = self._pending.get(key)
            if previous is None:
                self._pending[key] = (size, 0, now)
                return False

            last_size, stable_count, first_seen = previous

            if now - first_seen > MAX_SETTLE_SECONDS:
                logger.warning("watch_file_settle_timeout", path=key)
                return True

            if size != last_size or size == 0:
                self._pending[key] = (size, 0, first_seen)
                return False

            stable_count += 1
            self._pending[key] = (size, stable_count, first_seen)
            return stable_count >= STABLE_CHECKS_REQUIRED

    def _prime(self, folders: Iterable[Path]) -> None:
        with self._lock:
            for path in self._candidates(folders):
                self._seen.add(str(path))
        logger.debug("watcher_primed", known=len(self._seen))

    def forget(self, path: str | Path) -> None:
        """Allow a path to be picked up again (used after a manual delete)."""
        with self._lock:
            self._seen.discard(str(path))
            self._pending.pop(str(path), None)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.is_running,
                "folders": [str(f) for f in self.folders()],
                "known_files": len(self._seen),
                "settling": len(self._pending),
            }
