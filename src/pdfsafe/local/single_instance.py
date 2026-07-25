"""Single-instance enforcement.

Two copies of PDFSafe would fight over the SQLite database and the watch
folders, and double-clicking a PDF should reuse the running window rather than
launch a second one.

Windows uses a named mutex in the session namespace, so the lock is per user
session and is released automatically if the process is killed. Other platforms
fall back to an exclusively-created lock file containing the owning PID.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import TracebackType
from typing import Any

from pdfsafe import paths
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

MUTEX_NAME = "Local\\PDFSafe.SingleInstance"
_ERROR_ALREADY_EXISTS = 183


class SingleInstance:
    """Context manager that acquires the application-wide lock.

    Example::

        with SingleInstance() as lock:
            if not lock.acquired:
                show_already_running_message()
                return 1
            run_application()
    """

    def __init__(self, name: str = MUTEX_NAME) -> None:
        self.name = name
        self.acquired = False
        self._handle: Any = None
        self._lock_file: Path | None = None

    # -------------------------------------------------------------- enter --
    def acquire(self) -> bool:
        if sys.platform == "win32":
            self.acquired = self._acquire_windows()
        else:
            self.acquired = self._acquire_posix()
        return self.acquired

    def _acquire_windows(self) -> bool:
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [wintypes.LPCVOID, wintypes.BOOL, wintypes.LPCWSTR]
            kernel32.CreateMutexW.restype = wintypes.HANDLE

            handle = kernel32.CreateMutexW(None, True, self.name)
            last_error = ctypes.get_last_error()

            if not handle:
                logger.warning("mutex_creation_failed", error=last_error)
                return True  # fail open rather than block the user

            if last_error == _ERROR_ALREADY_EXISTS:
                kernel32.CloseHandle(handle)
                logger.info("another_instance_running")
                return False

            self._handle = handle
            return True
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("single_instance_check_failed", error=str(exc))
            return True

    def _acquire_posix(self) -> bool:
        lock_file = paths.local_dir() / "pdfsafe.lock"
        try:
            descriptor = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if self._stale(lock_file):
                lock_file.unlink(missing_ok=True)
                return self._acquire_posix()
            logger.info("another_instance_running", lock=str(lock_file))
            return False
        except OSError as exc:  # pragma: no cover
            logger.warning("lock_file_failed", error=str(exc))
            return True

        with os.fdopen(descriptor, "w") as handle:
            handle.write(str(os.getpid()))
        self._lock_file = lock_file
        return True

    @staticmethod
    def _stale(lock_file: Path) -> bool:
        """Whether the lock belongs to a process that no longer exists."""
        try:
            pid = int(lock_file.read_text().strip())
        except (OSError, ValueError):
            return True
        if pid == os.getpid():
            return True
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        except OSError:
            return True
        return False

    # --------------------------------------------------------------- exit --
    def release(self) -> None:
        if self._handle is not None:
            try:
                import ctypes

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.ReleaseMutex(self._handle)
                kernel32.CloseHandle(self._handle)
            except Exception:  # pragma: no cover
                pass
            self._handle = None

        if self._lock_file is not None:
            self._lock_file.unlink(missing_ok=True)
            self._lock_file = None

        self.acquired = False

    # ----------------------------------------------------- context manager --
    def __enter__(self) -> SingleInstance:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


# ---------------------------------------------------------------------------
# Handing files to an already-running instance
# ---------------------------------------------------------------------------
HANDOFF_DIR_NAME = "handoff"


def hand_off(file_paths: list[str]) -> bool:
    """Leave file paths for the running instance to pick up.

    A drop directory rather than a socket or window message: it needs no
    firewall exception, survives elevation differences between the two
    processes, and degrades to "nothing happens" instead of a crash.
    """
    if not file_paths:
        return False
    try:
        drop_dir = paths.local_dir() / HANDOFF_DIR_NAME
        drop_dir.mkdir(parents=True, exist_ok=True)
        import time
        import uuid

        target = drop_dir / f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}.txt"
        target.write_text("\n".join(file_paths), encoding="utf-8")
        return True
    except OSError as exc:  # pragma: no cover
        logger.warning("handoff_failed", error=str(exc))
        return False


def collect_handoffs() -> list[str]:
    """Read and remove any pending hand-off files."""
    drop_dir = paths.local_dir() / HANDOFF_DIR_NAME
    if not drop_dir.is_dir():
        return []

    collected: list[str] = []
    for entry in sorted(drop_dir.glob("*.txt")):
        try:
            collected.extend(
                line.strip() for line in entry.read_text(encoding="utf-8").splitlines() if line.strip()
            )
            entry.unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            continue
    return collected
