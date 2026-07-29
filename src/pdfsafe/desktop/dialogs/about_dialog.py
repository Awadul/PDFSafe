"""About / diagnostics dialog."""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from pdfsafe import __version__, paths
from pdfsafe.config import get_settings


class AboutDialog(QDialog):
    """Version, privacy summary and the paths a bug report needs."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About PDFSafe")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)

        title = QLabel(f"PDFSafe {__version__}")
        title.setObjectName("Heading")
        layout.addWidget(title)

        description = QLabel(
            "Scans PDF documents for malicious structure — embedded scripts, automatic "
            "actions, attachments and links — before you open them."
        )
        description.setWordWrap(True)
        description.setObjectName("Muted")
        layout.addWidget(description)

        privacy = QLabel(self._privacy_text())
        privacy.setWordWrap(True)
        privacy.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(privacy)

        diagnostics = QPlainTextEdit(self._diagnostics_text())
        diagnostics.setReadOnly(True)
        diagnostics.setObjectName("Mono")
        diagnostics.setMaximumHeight(170)
        layout.addWidget(diagnostics)

        actions = QHBoxLayout()
        for label, target in (
            ("Open logs", paths.log_dir()),
            ("Open quarantine", paths.quarantine_dir()),
        ):
            button = QPushButton(label)
            button.setObjectName("secondary")
            button.clicked.connect(
                lambda _=False, path=target: QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
            )
            actions.addWidget(button)
        actions.addStretch()
        layout.addLayout(actions)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    @staticmethod
    def _privacy_text() -> str:
        settings = get_settings()
        if settings.ai_enabled:
            return (
                "<b>Privacy:</b> analysis runs on this computer. AI review is <b>on</b>, so for "
                "files that are neither clearly safe nor clearly malicious, a summary of what "
                f"was found is sent to {settings.ai_provider.value}. The document itself is "
                "never uploaded."
            )
        return (
            "<b>Privacy:</b> everything happens on this computer. No file, and no information "
            "about any file, leaves the machine. AI review is off."
        )

    @staticmethod
    def _diagnostics_text() -> str:
        import platform
        import sys

        settings = get_settings()
        ai_state = f"on - {settings.ai_provider.value}" if settings.ai_enabled else "off"
        lines = [
            f"Version:     {__version__}",
            f"Python:      {sys.version.split()[0]}",
            f"Platform:    {platform.platform()}",
            f"Frozen:      {paths.is_frozen()}",
            f"AI:          {ai_state}",
            f"Isolation:   {settings.analysis_isolation.value}",
            "",
        ]
        lines += [f"{name + ':':12} {value}" for name, value in paths.describe().items()]
        return "\n".join(lines)
