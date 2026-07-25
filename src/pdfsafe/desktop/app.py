"""Application entry point.

Startup order matters and is not arbitrary:

1. ``freeze_support`` before anything else, or a frozen build re-launches
   itself instead of spawning a parser child.
2. Logging to file, because a windowed build has no console.
3. The single-instance lock, before touching the SQLite database.
4. The crash handler, before any of our own code can raise.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from pdfsafe.local.sandbox import install_freeze_support

# Must run before Qt or multiprocessing are touched.
install_freeze_support()

from PySide6.QtCore import QTimer, Qt  # noqa: E402
from PySide6.QtGui import QAction  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QMenu,
    QMessageBox,
    QSystemTrayIcon,
)

from pdfsafe import __version__  # noqa: E402
from pdfsafe.config import get_settings  # noqa: E402
from pdfsafe.desktop import icons  # noqa: E402
from pdfsafe.desktop.controller import ScanController  # noqa: E402
from pdfsafe.desktop.main_window import MainWindow  # noqa: E402
from pdfsafe.desktop.theme import palette_for, stylesheet  # noqa: E402
from pdfsafe.enums import Verdict  # noqa: E402
from pdfsafe.local.engine import ScanEvent  # noqa: E402
from pdfsafe.local.single_instance import SingleInstance, collect_handoffs, hand_off  # noqa: E402
from pdfsafe.logging import configure_logging, get_logger  # noqa: E402

logger = get_logger(__name__)

HANDOFF_POLL_MS = 2000
UPDATE_DELAY_MS = 8000


class PDFSafeApplication(QApplication):
    """Owns the tray icon, the window and the engine lifecycle."""

    def __init__(self, argv: list[str]) -> None:
        super().__init__(argv)
        self.setApplicationName("PDFSafe")
        self.setApplicationDisplayName("PDFSafe")
        self.setApplicationVersion(__version__)
        self.setOrganizationName("PDFSafe")
        self.setQuitOnLastWindowClosed(False)

        self.settings = get_settings()
        self.palette_ = palette_for(self.settings.theme)
        self.setStyleSheet(stylesheet(self.palette_))
        self.setWindowIcon(icons.app_icon(self.palette_))

        self.controller = ScanController(self.settings)
        self.window = MainWindow(self.controller, self.palette_)
        self.window.quitRequested.connect(self.shutdown)

        self._tray: QSystemTrayIcon | None = None
        self._build_tray()

        self.controller.scanCompleted.connect(self._on_scan_completed)
        self.controller.queueChanged.connect(self._on_queue_changed)
        self.aboutToQuit.connect(self.shutdown)

        self.controller.start()

        # Files handed over by a second instance the user launched.
        self._handoff_timer = QTimer(self)
        self._handoff_timer.timeout.connect(self._drain_handoffs)
        self._handoff_timer.start(HANDOFF_POLL_MS)

        if self.settings.update_check_enabled:
            QTimer.singleShot(UPDATE_DELAY_MS, lambda: self.window.check_for_updates(silent=True))

    # --------------------------------------------------------------- tray --
    def _build_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            logger.info("tray_unavailable")
            return

        self._tray = QSystemTrayIcon(icons.tray_icon(self.palette_), self)
        self._tray.setToolTip("PDFSafe")

        menu = QMenu()

        open_action = QAction("Open PDFSafe", menu)
        open_action.triggered.connect(self.show_window)
        menu.addAction(open_action)

        scan_action = QAction("Scan files…", menu)
        scan_action.triggered.connect(self._scan_from_tray)
        menu.addAction(scan_action)

        menu.addSeparator()

        settings_action = QAction("Settings…", menu)
        settings_action.triggered.connect(self._settings_from_tray)
        menu.addAction(settings_action)

        updates_action = QAction("Check for updates…", menu)
        updates_action.triggered.connect(lambda: self.window.check_for_updates(silent=False))
        menu.addAction(updates_action)

        menu.addSeparator()

        quit_action = QAction("Quit PDFSafe", menu)
        quit_action.triggered.connect(self.shutdown)
        menu.addAction(quit_action)

        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.show_window()

    def _scan_from_tray(self) -> None:
        self.show_window()
        self.window.drop_zone.browse()

    def _settings_from_tray(self) -> None:
        self.show_window()
        self.window.open_settings()

    # ------------------------------------------------------------ windows --
    def show_window(self) -> None:
        self.window.showNormal()
        self.window.raise_()
        self.window.activateWindow()

    # ------------------------------------------------------------- events --
    def _on_scan_completed(self, event: ScanEvent) -> None:
        if self._tray is None or not self.settings.notify_on_verdict:
            return

        verdict = event.verdict or Verdict.UNKNOWN
        threshold = (
            {Verdict.MALICIOUS}
            if self.settings.notify_min_verdict == "malicious"
            else {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
        )
        if verdict not in threshold:
            return

        quarantined = bool(event.payload.get("quarantined"))
        title = "Malicious PDF blocked" if verdict is Verdict.MALICIOUS else "Suspicious PDF found"
        body = event.filename
        if quarantined:
            body += " was moved to quarantine."
        else:
            body += f" scored {event.risk_score}/100. Review before opening."

        self._tray.showMessage(
            title,
            body,
            QSystemTrayIcon.MessageIcon.Critical
            if verdict is Verdict.MALICIOUS
            else QSystemTrayIcon.MessageIcon.Warning,
            10_000,
        )
        self._tray.setIcon(icons.tray_icon(self.palette_, alert=True))
        QTimer.singleShot(30_000, self._reset_tray_icon)

    def _on_queue_changed(self, depth: int) -> None:
        if self._tray is None:
            return
        self._tray.setToolTip(
            f"PDFSafe — scanning ({depth} queued)" if depth else "PDFSafe — idle"
        )

    def _reset_tray_icon(self) -> None:
        if self._tray is not None:
            self._tray.setIcon(icons.tray_icon(self.palette_))

    def _drain_handoffs(self) -> None:
        paths = collect_handoffs()
        if paths:
            logger.info("handoff_received", count=len(paths))
            self.show_window()
            self.controller.scan_files(paths)

    # ---------------------------------------------------------- lifecycle --
    def scan_startup_files(self, paths: list[str]) -> None:
        if paths:
            self.controller.scan_files(paths)

    def shutdown(self) -> None:
        logger.info("application_shutting_down")
        try:
            self._handoff_timer.stop()
            self.controller.shutdown()
        except Exception:  # pragma: no cover
            logger.exception("shutdown_error")
        if self._tray is not None:
            self._tray.hide()
        self.quit()


# ---------------------------------------------------------------------------
# Crash handling
# ---------------------------------------------------------------------------
def _install_excepthook() -> None:
    """Log unhandled exceptions and tell the user where the log is.

    Without this a frozen build dies silently, which is indistinguishable from
    the app never having started.
    """

    def handler(exc_type: type[BaseException], exc: BaseException, traceback: Any) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, traceback)
            return

        logger.critical("unhandled_exception", exc_info=(exc_type, exc, traceback))

        try:
            from pdfsafe import paths

            QMessageBox.critical(
                None,
                "PDFSafe has hit an unexpected error",
                f"{exc_type.__name__}: {exc}\n\n"
                f"Details were written to:\n{paths.log_dir()}\n\n"
                "Please include that file if you report this.",
            )
        except Exception:  # pragma: no cover - Qt may already be gone
            pass

    sys.excepthook = handler


def _parse_arguments(argv: list[str]) -> tuple[list[str], bool]:
    """Split CLI arguments into (pdf paths, start_minimized)."""
    paths: list[str] = []
    minimized = False

    for argument in argv[1:]:
        if argument in ("--minimized", "/minimized", "-m"):
            minimized = True
            continue
        if argument.startswith("-"):
            continue
        candidate = Path(argument)
        if candidate.is_file() and candidate.suffix.lower() == ".pdf":
            paths.append(str(candidate.resolve()))

    return paths, minimized


def main() -> int:
    """Run the desktop application. Returns a process exit code."""
    configure_logging(to_file=True)

    file_arguments, minimized = _parse_arguments(sys.argv)

    lock = SingleInstance()
    if not lock.acquire():
        # Another copy owns the database; hand it our files and step aside.
        if file_arguments:
            hand_off(file_arguments)
        else:
            # Keep a reference: a garbage-collected QApplication takes the
            # message box down with it before the user can read it.
            _app = QApplication(sys.argv)
            QMessageBox.information(
                None,
                "PDFSafe is already running",
                "PDFSafe is already open. Look for its icon in the notification area.",
            )
        return 0

    try:
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeMenuBar, False)

        app = PDFSafeApplication(sys.argv)
        _install_excepthook()

        logger.info(
            "application_started",
            version=__version__,
            minimized=minimized,
            ai_enabled=app.settings.ai_enabled,
            files=len(file_arguments),
        )

        if not (minimized or app.settings.start_minimized):
            app.show_window()

        if file_arguments:
            app.scan_startup_files(file_arguments)

        return app.exec()
    finally:
        lock.release()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
