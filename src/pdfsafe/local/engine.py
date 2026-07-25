"""In-process scan engine for the desktop build.

Replaces Celery + Redis with a bounded thread pool. Threads are the right tool
here because each scan is dominated by two waits the GIL does not hold:
sandboxed parsing in a child process, and the optional network call to the AI
provider.

Progress is published through :meth:`LocalScanEngine.subscribe`; the Qt layer
turns those callbacks into signals. The engine itself has no Qt dependency, so
it is usable from the CLI and the tests.
"""

from __future__ import annotations

import queue
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pdfsafe.ai.triage import TriageResult, triage
from pdfsafe.analysis.pipeline import looks_like_pdf, score_evidence
from pdfsafe.analysis.utils import md5_hex, sha256_hex
from pdfsafe.config import Settings, get_settings
from pdfsafe.enums import UploadSource, Verdict
from pdfsafe.exceptions import (
    FileTooLargeError,
    PDFSafeError,
    UnsupportedFileTypeError,
    ValidationError,
)
from pdfsafe.local.database import LocalDatabase, get_database
from pdfsafe.local.repository import ScanRepository
from pdfsafe.local.sandbox import extract_isolated
from pdfsafe.logging import bind_context, clear_context, get_logger
from pdfsafe.storage import get_storage
from pdfsafe.storage.local import LocalStorage

logger = get_logger(__name__)

#: Scans left running by a crash are failed on the next launch.
STALE_AFTER = timedelta(hours=2)


class ScanEventKind(StrEnum):
    """Lifecycle notifications published by the engine."""

    QUEUED = "queued"
    STARTED = "started"
    PARSING = "parsing"
    AI_REVIEW = "ai_review"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    IDLE = "idle"


@dataclass(slots=True)
class ScanEvent:
    """A single lifecycle notification."""

    kind: ScanEventKind
    scan_id: uuid.UUID | None = None
    filename: str = ""
    message: str = ""
    verdict: Verdict | None = None
    risk_score: int = 0
    queue_depth: int = 0
    payload: dict[str, Any] = field(default_factory=dict)


Subscriber = Callable[[ScanEvent], None]


class LocalScanEngine:
    """Owns the work queue, the worker threads and the scan lifecycle."""

    def __init__(
        self,
        settings: Settings | None = None,
        database: LocalDatabase | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.database = database or get_database(self.settings)
        self._queue: queue.Queue[uuid.UUID | None] = queue.Queue()
        self._workers: list[threading.Thread] = []
        self._subscribers: list[Subscriber] = []
        self._subscriber_lock = threading.Lock()
        self._running = threading.Event()
        self._active = 0
        self._active_lock = threading.Lock()
        #: Scan ids that must bypass the AI cost gate on their next run.
        self._force_ai: set[uuid.UUID] = set()

    # ---------------------------------------------------------- lifecycle --
    def start(self) -> None:
        """Start the worker threads and recover anything left mid-flight."""
        if self._running.is_set():
            return

        self._recover_interrupted()
        self._running.set()

        count = self.settings.analysis_workers
        for index in range(count):
            thread = threading.Thread(
                target=self._worker_loop, name=f"pdfsafe-scan-{index}", daemon=True
            )
            thread.start()
            self._workers.append(thread)

        logger.info(
            "engine_started",
            workers=count,
            isolation=self.settings.analysis_isolation.value,
            ai_enabled=self.settings.ai_enabled,
        )

    def stop(self, *, wait: bool = True, timeout: float = 10.0) -> None:
        """Signal the workers to finish and optionally wait for them."""
        if not self._running.is_set():
            return
        self._running.clear()

        for _ in self._workers:
            self._queue.put(None)

        if wait:
            deadline = time.monotonic() + timeout
            for thread in self._workers:
                remaining = max(0.0, deadline - time.monotonic())
                thread.join(timeout=remaining)

        self._workers.clear()
        logger.info("engine_stopped")

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def queue_depth(self) -> int:
        with self._active_lock:
            return self._queue.qsize() + self._active

    # --------------------------------------------------------- subscribers --
    def subscribe(self, callback: Subscriber) -> None:
        with self._subscriber_lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Subscriber) -> None:
        with self._subscriber_lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def _emit(self, event: ScanEvent) -> None:
        event.queue_depth = self.queue_depth
        with self._subscriber_lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:  # pragma: no cover - a bad listener must not stop scanning
                logger.exception("subscriber_failed", kind=event.kind.value)

    # ------------------------------------------------------------- submit --
    def submit_file(
        self,
        path: str | Path,
        *,
        source: UploadSource = UploadSource.DASHBOARD,
        deduplicate: bool = True,
    ) -> uuid.UUID | None:
        """Validate, store and queue a file.

        Returns the scan id, or ``None`` when the file was rejected or was a
        duplicate of an already-completed scan.
        """
        file_path = Path(path)
        try:
            data = self._read_and_validate(file_path)
        except PDFSafeError as exc:
            logger.info("submission_rejected", path=str(file_path), reason=exc.code)
            self._emit(
                ScanEvent(
                    kind=ScanEventKind.REJECTED,
                    filename=file_path.name,
                    message=exc.message,
                    payload={"code": exc.code},
                )
            )
            return None

        digest = sha256_hex(data)

        with self.database.session() as session:
            repository = ScanRepository(session)

            if deduplicate:
                existing = repository.find_completed_by_hash(digest)
                if existing is not None:
                    logger.info("submission_deduplicated", sha256=digest[:12])
                    self._emit(
                        ScanEvent(
                            kind=ScanEventKind.DUPLICATE,
                            scan_id=existing.id,
                            filename=file_path.name,
                            verdict=existing.verdict,
                            risk_score=existing.risk_score,
                            message="This file was scanned before; showing the previous result.",
                        )
                    )
                    return existing.id

            storage = get_storage()
            key = storage.build_key(digest, file_path.name)
            storage.save(key, data)

            scan = repository.create(
                filename=file_path.name,
                file_size=len(data),
                sha256=digest,
                md5=md5_hex(data),
                storage_key=key,
                source=source,
                origin_path=str(file_path),
            )
            scan_id = scan.id

        self._queue.put(scan_id)
        self._emit(
            ScanEvent(
                kind=ScanEventKind.QUEUED,
                scan_id=scan_id,
                filename=file_path.name,
                message="Queued for analysis",
            )
        )
        return scan_id

    def submit_files(
        self, paths: Iterable[str | Path], *, source: UploadSource = UploadSource.DASHBOARD
    ) -> list[uuid.UUID]:
        return [
            scan_id
            for path in paths
            if (scan_id := self.submit_file(path, source=source)) is not None
        ]

    def submit_folder(
        self, folder: str | Path, *, recursive: bool = False
    ) -> list[uuid.UUID]:
        root = Path(folder)
        pattern = "**/*.pdf" if recursive else "*.pdf"
        return self.submit_files(
            sorted(p for p in root.glob(pattern) if p.is_file()),
            source=UploadSource.WATCH_FOLDER,
        )

    def rescan(self, scan_id: uuid.UUID, *, force_ai: bool = True) -> None:
        """Re-run analysis for an existing scan."""
        with self.database.session() as session:
            ScanRepository(session).reset_for_rescan(scan_id)
        if force_ai:
            with self._active_lock:
                self._force_ai.add(scan_id)
        self._queue.put(scan_id)
        self._emit(ScanEvent(kind=ScanEventKind.QUEUED, scan_id=scan_id, message="Re-queued"))

    # -------------------------------------------------------------- worker --
    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None or not self._running.is_set():
                    return
                with self._active_lock:
                    self._active += 1
                try:
                    self._process(item)
                finally:
                    with self._active_lock:
                        self._active -= 1
            except Exception:  # pragma: no cover - loop must never die
                logger.exception("worker_loop_error")
            finally:
                self._queue.task_done()
                if self._queue.empty() and self.queue_depth == 0:
                    self._emit(ScanEvent(kind=ScanEventKind.IDLE))

    def _process(self, scan_id: uuid.UUID) -> None:
        bind_context(scan_id=str(scan_id))
        started = time.perf_counter()
        with self._active_lock:
            force_ai = scan_id in self._force_ai
            self._force_ai.discard(scan_id)

        try:
            with self.database.session() as session:
                repository = ScanRepository(session)
                scan = repository.get(scan_id)
                filename = scan.filename
                storage_key = scan.storage_key
                repository.mark_analyzing(scan_id)

            self._emit(
                ScanEvent(
                    kind=ScanEventKind.PARSING, scan_id=scan_id, filename=filename,
                    message="Analysing structure",
                )
            )

            storage = get_storage()
            local_path = storage.local_path(storage_key)

            result = extract_isolated(local_path, filename=filename, settings=self.settings)
            analysis = score_evidence(result)

            decision = self._decide(scan_id, analysis, filename, force_ai=force_ai)

            quarantined = self._maybe_quarantine(decision.verdict, storage_key)
            duration_ms = int((time.perf_counter() - started) * 1000)

            with self.database.session() as session:
                repository = ScanRepository(session)
                repository.save_result(
                    scan_id, analysis, decision, duration_ms=duration_ms, quarantined=quarantined
                )
                if self.settings.history_limit:
                    repository.prune(self.settings.history_limit)

            if not self.settings.keep_scanned_copies and not quarantined:
                self._discard_copy(storage_key)

            self._emit(
                ScanEvent(
                    kind=ScanEventKind.COMPLETED,
                    scan_id=scan_id,
                    filename=filename,
                    verdict=decision.verdict,
                    risk_score=decision.risk_score,
                    message=decision.summary,
                    payload={
                        "decided_by": decision.decided_by.value,
                        "used_ai": decision.used_ai,
                        "quarantined": quarantined,
                        "duration_ms": duration_ms,
                    },
                )
            )

        except Exception as exc:
            code = exc.code if isinstance(exc, PDFSafeError) else type(exc).__name__
            message = exc.message if isinstance(exc, PDFSafeError) else str(exc)
            logger.exception("scan_failed", scan_id=str(scan_id), code=code)
            try:
                with self.database.session() as session:
                    ScanRepository(session).mark_failed(scan_id, str(code), message)
            except Exception:  # pragma: no cover
                logger.exception("failure_not_recorded", scan_id=str(scan_id))

            self._emit(
                ScanEvent(
                    kind=ScanEventKind.FAILED,
                    scan_id=scan_id,
                    message=message,
                    payload={"code": str(code)},
                )
            )
        finally:
            clear_context()

    def _decide(
        self, scan_id: uuid.UUID, analysis: Any, filename: str, *, force_ai: bool
    ) -> TriageResult:
        """Run the escalation gate and, when it opens, the AI review."""
        from pdfsafe.ai.triage import should_escalate

        escalating = force_ai or should_escalate(analysis.outcome, self.settings).escalate
        if escalating:
            with self.database.session() as session:
                ScanRepository(session).mark_ai_review(scan_id)
            self._emit(
                ScanEvent(
                    kind=ScanEventKind.AI_REVIEW,
                    scan_id=scan_id,
                    filename=filename,
                    message="Consulting AI reviewer",
                )
            )

        return triage(
            analysis.result, analysis.outcome, settings=self.settings, force_ai=force_ai
        )

    # ---------------------------------------------------------- quarantine --
    def _maybe_quarantine(self, verdict: Verdict, storage_key: str) -> bool:
        if verdict is not Verdict.MALICIOUS or not self.settings.quarantine_enabled:
            return False

        storage = get_storage()
        if not isinstance(storage, LocalStorage):
            return False

        from pdfsafe import paths

        try:
            storage.quarantine(storage_key, paths.quarantine_dir())
            return True
        except Exception as exc:
            logger.warning("quarantine_failed", key=storage_key, error=str(exc))
            return False

    def _discard_copy(self, storage_key: str) -> None:
        try:
            get_storage().delete(storage_key)
        except Exception as exc:  # pragma: no cover
            logger.debug("copy_not_removed", key=storage_key, error=str(exc))

    # ------------------------------------------------------------ helpers --
    def _read_and_validate(self, path: Path) -> bytes:
        if not path.is_file():
            raise ValidationError(f"{path.name} is not a readable file.")

        size = path.stat().st_size
        if size == 0:
            raise ValidationError(f"{path.name} is empty.")
        if size > self.settings.max_upload_bytes:
            limit_mb = self.settings.max_upload_bytes / (1024 * 1024)
            raise FileTooLargeError(
                f"{path.name} is {size / (1024 * 1024):.1f} MB; the limit is {limit_mb:.0f} MB.",
                size=size,
            )

        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ValidationError(f"{path.name} could not be read: {exc}") from exc

        if not looks_like_pdf(data):
            raise UnsupportedFileTypeError(
                f"{path.name} does not look like a PDF (no %PDF- header)."
            )
        return data

    def _recover_interrupted(self) -> None:
        """Fail scans that a crash left in a non-terminal state."""
        try:
            with self.database.session() as session:
                failed = ScanRepository(session).fail_stale(STALE_AFTER)
            if failed:
                logger.info("interrupted_scans_recovered", count=failed)
        except Exception as exc:  # pragma: no cover
            logger.warning("recovery_failed", error=str(exc))

    # ---------------------------------------------------------- read paths --
    def stats(self) -> Any:
        with self.database.session() as session:
            return ScanRepository(session).stats()

    def history(self, **kwargs: Any) -> Sequence[Any]:
        with self.database.session() as session:
            rows = ScanRepository(session).recent(**kwargs)
            session.expunge_all()
            return rows

    def detail(self, scan_id: uuid.UUID) -> Any:
        with self.database.session() as session:
            scan = ScanRepository(session).get(scan_id, detail=True)
            session.expunge_all()
            return scan
