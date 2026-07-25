"""Update notification and download dialog."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from pdfsafe import __version__
from pdfsafe.desktop.controller import UpdateDownloadThread
from pdfsafe.logging import get_logger

logger = get_logger(__name__)


class UpdateDialog(QDialog):
    """Presents an available update, then downloads and verifies it."""

    def __init__(self, info: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.info = info
        self._thread: UpdateDownloadThread | None = None
        self._installer: Path | None = None

        self.setWindowTitle("Update available")
        self.setMinimumWidth(480)
        self.setModal(True)

        layout = QVBoxLayout(self)

        heading = QLabel(f"PDFSafe {info.version} is available")
        heading.setObjectName("Heading")
        layout.addWidget(heading)

        subtitle = QLabel(
            f"You have {__version__}."
            + (f" Download size {info.size_mb} MB." if info.size_mb else "")
            + (f" Released {info.released}." if info.released else "")
        )
        subtitle.setObjectName("Muted")
        layout.addWidget(subtitle)

        if info.notes:
            notes = QTextBrowser()
            notes.setMarkdown(info.notes)
            notes.setMaximumHeight(200)
            notes.setOpenExternalLinks(True)
            layout.addWidget(notes)

        self._status = QLabel()
        self._status.setObjectName("Muted")
        self._status.setWordWrap(True)
        layout.addWidget(self._status)

        self._progress = QProgressBar()
        self._progress.setVisible(False)
        layout.addWidget(self._progress)

        buttons = QHBoxLayout()
        buttons.addStretch()

        self._later = QPushButton("Later")
        self._later.setObjectName("secondary")
        self._later.clicked.connect(self.reject)
        self._later.setVisible(not info.mandatory)
        buttons.addWidget(self._later)

        self._action = QPushButton("Download and install")
        self._action.clicked.connect(self._start_download)
        buttons.addWidget(self._action)

        layout.addLayout(buttons)

        if info.mandatory:
            self._status.setText("This is a required security update.")

    # ----------------------------------------------------------- download --
    def _start_download(self) -> None:
        self._action.setEnabled(False)
        self._later.setEnabled(False)
        self._progress.setVisible(True)
        self._progress.setRange(0, 0)
        self._status.setText("Downloading…")

        self._thread = UpdateDownloadThread(self.info, self)
        self._thread.progressed.connect(self._on_progress)
        self._thread.finishedOk.connect(self._on_downloaded)
        self._thread.failed.connect(self._on_failed)
        self._thread.start()

    def _on_progress(self, downloaded: int, total: int) -> None:
        if total > 0:
            self._progress.setRange(0, total)
            self._progress.setValue(downloaded)
            self._status.setText(
                f"Downloading… {downloaded / 1_048_576:.1f} of {total / 1_048_576:.1f} MB"
            )

    def _on_downloaded(self, path: str, trusted: bool, detail: str) -> None:
        self._installer = Path(path)
        self._progress.setVisible(False)

        if not trusted:
            logger.warning("update_signature_rejected", detail=detail)
            answer = QMessageBox.warning(
                self,
                "The update is not signed by a trusted publisher",
                "The downloaded installer's digital signature could not be verified.\n\n"
                f"Verification result: {detail or 'unavailable'}\n\n"
                "This can happen with a development build, but it can also mean the file "
                "was tampered with. Installing it anyway is not recommended.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Ignore,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Ignore:
                self._installer.unlink(missing_ok=True)
                self.reject()
                return

        self._status.setText("Download verified. PDFSafe will close to finish installing.")
        self._action.setText("Install now")
        self._action.setEnabled(True)
        self._action.clicked.disconnect()
        self._action.clicked.connect(self._install)

    def _on_failed(self, message: str) -> None:
        self._progress.setVisible(False)
        self._status.setText(message)
        self._action.setText("Try again")
        self._action.setEnabled(True)
        self._later.setEnabled(True)

    def _install(self) -> None:
        from pdfsafe.local import updater

        if self._installer is None:
            return
        try:
            updater.launch_installer(self._installer)
        except updater.UpdateError as exc:
            QMessageBox.critical(self, "Could not start the installer", str(exc))
            return

        self.accept()
        from PySide6.QtWidgets import QApplication

        QApplication.quit()

    def closeEvent(self, event: Any) -> None:
        if self._thread is not None and self._thread.isRunning():
            self._thread.requestInterruption()
            self._thread.wait(2000)
        super().closeEvent(event)


__all__ = ["UpdateDialog"]
