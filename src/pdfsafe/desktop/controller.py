"""Bridge between the engine and Qt.

The engine publishes events from worker threads. Qt widgets may only be touched
from the GUI thread, so every event is re-emitted as a Qt signal: emitting from
a non-GUI thread is safe, and Qt queues the delivery across the thread boundary
automatically. Nothing in the engine knows Qt exists.
"""

from __future__ import annotations

import uuid
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal

from pdfsafe.config import Settings, get_settings
from pdfsafe.enums import UploadSource, Verdict
from pdfsafe.local.engine import LocalScanEngine, ScanEvent, ScanEventKind
from pdfsafe.local.watcher import FolderWatcher
from pdfsafe.logging import get_logger

logger = get_logger(__name__)


class ScanController(QObject):
    """Qt-facing facade over :class:`LocalScanEngine`."""

    scanQueued = Signal(object)       # ScanEvent
    scanStarted = Signal(object)
    scanProgressed = Signal(object)
    scanCompleted = Signal(object)
    scanFailed = Signal(object)
    scanRejected = Signal(object)
    duplicateFound = Signal(object)
    queueChanged = Signal(int)
    historyChanged = Signal()

    def __init__(self, settings: Settings | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.settings = settings or get_settings()
        self.engine = LocalScanEngine(self.settings)
        self.watcher = FolderWatcher(self.engine, self.settings)
        self.engine.subscribe(self._on_engine_event)

    # ---------------------------------------------------------- lifecycle --
    def start(self) -> None:
        self.engine.start()
        if self.settings.watch_enabled:
            self.watcher.start()

    def shutdown(self, timeout: float = 8.0) -> None:
        self.watcher.stop()
        self.engine.stop(wait=True, timeout=timeout)

    def apply_settings(self, settings: Settings) -> None:
        """Adopt reloaded settings, restarting the parts that depend on them."""
        previous_workers = self.settings.analysis_workers
        self.settings = settings
        self.engine.settings = settings
        self.watcher.settings = settings

        if settings.analysis_workers != previous_workers:
            self.engine.stop(wait=True, timeout=5.0)
            self.engine.start()

        if settings.watch_enabled:
            self.watcher.refresh()
        else:
            self.watcher.stop()

    # ------------------------------------------------------------ actions --
    def scan_files(self, paths: list[str]) -> None:
        for path in paths:
            self.engine.submit_file(path, source=UploadSource.DASHBOARD)

    def scan_folder(self, folder: str, *, recursive: bool = False) -> int:
        return len(self.engine.submit_folder(folder, recursive=recursive))

    def rescan(self, scan_id: uuid.UUID, *, force_ai: bool = True) -> None:
        self.engine.rescan(scan_id, force_ai=force_ai)

    def delete(self, scan_id: uuid.UUID) -> None:
        from pdfsafe.local.repository import ScanRepository

        with self.engine.database.session() as session:
            ScanRepository(session).delete(scan_id)
        self.historyChanged.emit()

    def set_verdict(self, scan_id: uuid.UUID, verdict: Verdict, note: str = "") -> None:
        from pdfsafe.local.repository import ScanRepository

        with self.engine.database.session() as session:
            ScanRepository(session).set_review(scan_id, verdict, note)
        self.historyChanged.emit()

    # -------------------------------------------------------------- reads --
    def history(self, **kwargs: Any) -> list[Any]:
        return list(self.engine.history(**kwargs))

    def detail(self, scan_id: uuid.UUID) -> Any:
        return self.engine.detail(scan_id)

    def stats(self) -> Any:
        return self.engine.stats()

    @property
    def queue_depth(self) -> int:
        return self.engine.queue_depth

    # -------------------------------------------------------------- events --
    def _on_engine_event(self, event: ScanEvent) -> None:
        """Called on a worker thread; only emits signals."""
        try:
            match event.kind:
                case ScanEventKind.QUEUED:
                    self.scanQueued.emit(event)
                    self.historyChanged.emit()
                case ScanEventKind.STARTED | ScanEventKind.PARSING:
                    self.scanStarted.emit(event)
                case ScanEventKind.AI_REVIEW:
                    self.scanProgressed.emit(event)
                case ScanEventKind.COMPLETED:
                    self.scanCompleted.emit(event)
                    self.historyChanged.emit()
                case ScanEventKind.FAILED:
                    self.scanFailed.emit(event)
                    self.historyChanged.emit()
                case ScanEventKind.REJECTED:
                    self.scanRejected.emit(event)
                case ScanEventKind.DUPLICATE:
                    self.duplicateFound.emit(event)
                case ScanEventKind.IDLE:
                    pass
            self.queueChanged.emit(event.queue_depth)
        except RuntimeError:  # pragma: no cover - controller deleted during shutdown
            pass


class UpdateCheckThread(QThread):
    """Checks for updates without blocking the UI."""

    updateAvailable = Signal(object)   # UpdateInfo
    upToDate = Signal()
    checkFailed = Signal(str)

    def run(self) -> None:
        from pdfsafe.local import updater

        try:
            info = updater.check()
        except updater.UpdateError as exc:
            self.checkFailed.emit(str(exc))
            return
        except Exception as exc:  # pragma: no cover
            self.checkFailed.emit(f"Unexpected error: {exc}")
            return

        if info is None:
            self.upToDate.emit()
        else:
            self.updateAvailable.emit(info)


class UpdateDownloadThread(QThread):
    """Downloads and verifies an update installer."""

    progressed = Signal(int, int)      # downloaded, total
    finishedOk = Signal(str, bool, str)  # path, signature_trusted, signature_detail
    failed = Signal(str)

    def __init__(self, info: Any, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.info = info

    def run(self) -> None:
        from pdfsafe.local import updater

        try:
            path = updater.download(
                self.info, progress=lambda done, total: self.progressed.emit(done, total)
            )
        except updater.UpdateError as exc:
            self.failed.emit(str(exc))
            return
        except Exception as exc:  # pragma: no cover
            self.failed.emit(f"Unexpected error: {exc}")
            return

        trusted, detail = updater.verify_signature(path)
        self.finishedOk.emit(str(path), trusted, detail)
