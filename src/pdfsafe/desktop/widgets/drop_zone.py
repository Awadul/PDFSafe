"""Drag-and-drop target for PDFs."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDropEvent, QMouseEvent
from PySide6.QtWidgets import QFileDialog, QLabel, QVBoxLayout, QWidget


class DropZone(QWidget):
    """Accepts dropped PDFs, or opens a file picker when clicked."""

    filesDropped = Signal(list)  # list[str]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(120)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("active", False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(4)
        layout.addStretch()

        self._title = QLabel("Drop PDF files here")
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title.setObjectName("Heading")
        layout.addWidget(self._title)

        self._hint = QLabel("or click to browse")
        self._hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hint.setObjectName("Muted")
        layout.addWidget(self._hint)

        layout.addStretch()

    # ----------------------------------------------------------- dragging --
    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if self._pdf_paths(event):
            event.acceptProposedAction()
            self._set_active(True)
        else:
            event.ignore()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self._set_active(False)
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = self._pdf_paths(event)
        self._set_active(False)
        if paths:
            event.acceptProposedAction()
            self.filesDropped.emit(paths)
        else:
            event.ignore()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.browse()
        super().mouseReleaseEvent(event)

    # ------------------------------------------------------------ helpers --
    def browse(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select PDF files to scan", "", "PDF documents (*.pdf);;All files (*.*)"
        )
        if paths:
            self.filesDropped.emit(paths)

    def set_message(self, title: str, hint: str = "") -> None:
        self._title.setText(title)
        self._hint.setText(hint)

    def _set_active(self, active: bool) -> None:
        self.setProperty("active", active)
        # Re-polish so the [active="true"] stylesheet rule takes effect.
        style = self.style()
        style.unpolish(self)
        style.polish(self)

    @staticmethod
    def _pdf_paths(event: QDragEnterEvent | QDropEvent) -> list[str]:
        mime = event.mimeData()
        if not mime.hasUrls():
            return []

        paths: list[str] = []
        for url in mime.urls():
            if not url.isLocalFile():
                continue
            path = Path(url.toLocalFile())
            if path.is_dir():
                paths.extend(str(p) for p in sorted(path.glob("*.pdf")) if p.is_file())
            elif path.suffix.lower() == ".pdf":
                paths.append(str(path))
        return paths
