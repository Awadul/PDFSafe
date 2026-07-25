"""Process isolation for PDF parsing.

Parsing attacker-controlled structure is the one place where PDFSafe executes
complex native code (qpdf via pikepdf) against hostile input. In a desktop app
that runs with the user's full privileges, doing that in the UI process means a
parser bug is a crash at best and code execution at worst.

So :func:`extract_isolated` runs the parser in a disposable child process:

* a hang is bounded by a hard timeout and the child is killed
* a segfault kills the child, not the application
* memory growth is reclaimed when the child exits

The cost is process-spawn overhead per file (roughly 0.2-0.5s on Windows for a
frozen build). Set ``analysis_isolation = "in_process"`` to trade that safety
for speed.
"""

from __future__ import annotations

import multiprocessing
import sys
from multiprocessing.connection import Connection
from pathlib import Path

from pdfsafe.config import Isolation, Settings, get_settings
from pdfsafe.exceptions import AnalysisError, AnalysisTimeoutError
from pdfsafe.logging import get_logger
from pdfsafe.schemas.analysis import StaticAnalysisResult

logger = get_logger(__name__)

#: Extra grace period given to the child to shut down after a timeout.
_KILL_GRACE_SECONDS = 5.0


def _child_entry(connection: Connection, path: str, filename: str) -> None:
    """Child process body: parse one file and send the evidence back as JSON.

    Must stay importable at module level - ``spawn`` re-imports this module in
    the child, and a nested function could not be pickled.
    """
    try:
        from pdfsafe.analysis.pipeline import extract_evidence

        data = Path(path).read_bytes()
        result = extract_evidence(data, filename=filename)
        connection.send(("ok", result.model_dump_json()))
    except BaseException as exc:  # noqa: BLE001 - the point is to never escape
        connection.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        try:
            connection.close()
        except Exception:  # pragma: no cover
            pass


def extract_isolated(
    path: Path,
    *,
    filename: str | None = None,
    settings: Settings | None = None,
) -> StaticAnalysisResult:
    """Parse ``path`` in a child process and return the evidence.

    Raises:
        AnalysisTimeoutError: the child exceeded ``analysis_timeout_seconds``.
        AnalysisError: the child crashed or returned something unusable.
    """
    settings = settings or get_settings()
    filename = filename or path.name

    if settings.analysis_isolation is Isolation.IN_PROCESS:
        from pdfsafe.analysis.pipeline import extract_evidence

        return extract_evidence(path.read_bytes(), filename=filename)

    timeout = float(settings.analysis_timeout_seconds)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)

    process = context.Process(
        target=_child_entry,
        args=(sender, str(path), filename),
        name="pdfsafe-parser",
        daemon=True,
    )

    try:
        process.start()
    except Exception as exc:
        receiver.close()
        sender.close()
        logger.warning("sandbox_spawn_failed", error=str(exc), fallback="in_process")
        from pdfsafe.analysis.pipeline import extract_evidence

        return extract_evidence(path.read_bytes(), filename=filename)

    # The parent must close its copy of the write end, otherwise poll() will
    # never report EOF when the child dies.
    sender.close()

    try:
        if not receiver.poll(timeout):
            _terminate(process)
            raise AnalysisTimeoutError(
                f"Parsing exceeded {timeout:.0f}s and was aborted.",
                filename=filename,
                timeout_seconds=timeout,
            )

        try:
            status, payload = receiver.recv()
        except EOFError as exc:
            exit_code = process.exitcode
            raise AnalysisError(
                "The parser process exited without returning a result "
                f"(exit code {exit_code}). The file may be malformed enough to crash the parser.",
                filename=filename,
                exit_code=exit_code,
            ) from exc

        if status != "ok":
            raise AnalysisError(f"Parsing failed: {payload}", filename=filename)

        try:
            return StaticAnalysisResult.model_validate_json(payload)
        except Exception as exc:
            raise AnalysisError(f"Parser returned an unreadable result: {exc}") from exc

    finally:
        receiver.close()
        _terminate(process)


def _terminate(process: multiprocessing.process.BaseProcess) -> None:
    """Stop the child, escalating from terminate to kill."""
    if not process.is_alive():
        process.join(timeout=1)
        return

    process.terminate()
    process.join(timeout=_KILL_GRACE_SECONDS)

    if process.is_alive():  # pragma: no cover - stubborn child
        logger.warning("sandbox_kill_required", pid=process.pid)
        process.kill()
        process.join(timeout=_KILL_GRACE_SECONDS)


def install_freeze_support() -> None:
    """Required before spawning children from a PyInstaller build.

    Without this the child re-runs the application entry point instead of the
    worker body, which on Windows means the app launches itself repeatedly.
    Call it as the very first statement of every entry point.
    """
    multiprocessing.freeze_support()
    if sys.platform == "win32":
        multiprocessing.set_start_method("spawn", force=True)
