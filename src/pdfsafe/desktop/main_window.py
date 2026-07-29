"""Main application window."""

from __future__ import annotations

import uuid
from typing import Any

from PySide6.QtCore import QSettings, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from pdfsafe import __version__
from pdfsafe.config import get_settings, reload_settings
from pdfsafe.desktop import icons
from pdfsafe.desktop.controller import ScanController, UpdateCheckThread
from pdfsafe.desktop.dialogs import AboutDialog, SettingsDialog, UpdateDialog
from pdfsafe.desktop.theme import Palette, palette_for, stylesheet, verdict_color
from pdfsafe.desktop.widgets import DetailPanel, DropZone, ScanTable
from pdfsafe.desktop.widgets.scan_table import ScanRow
from pdfsafe.enums import Verdict
from pdfsafe.local.engine import ScanEvent
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

REFRESH_DEBOUNCE_MS = 250


class MainWindow(QMainWindow):
    """Scan history, detail view and the actions that drive them."""

    quitRequested = Signal()

    def __init__(self, controller: ScanController, palette: Palette) -> None:
        super().__init__()
        self.controller = controller
        self.palette_ = palette
        self.settings = get_settings()
        self._force_quit = False
        self._update_thread: UpdateCheckThread | None = None

        self.setWindowTitle("PDFSafe")
        self.setMinimumSize(980, 620)
        self.setWindowIcon(icons.app_icon(palette))

        self._build_toolbar()
        self._build_central()
        self._build_statusbar()

        # Coalesce bursts of engine events into a single reload.
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(REFRESH_DEBOUNCE_MS)
        self._refresh_timer.timeout.connect(self.refresh)

        self._connect_controller()
        self._restore_geometry()
        self.refresh()

    # -------------------------------------------------------------- build --
    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(toolbar)

        self._action_scan_files = QAction(
            icons.glyph_icon(icons.GLYPHS["scan_files"], self.palette_), "Scan files…", self
        )
        self._action_scan_files.setShortcut("Ctrl+O")
        self._action_scan_files.triggered.connect(self._on_scan_files)
        toolbar.addAction(self._action_scan_files)

        self._action_scan_folder = QAction(
            icons.glyph_icon(icons.GLYPHS["scan_folder"], self.palette_), "Scan folder…", self
        )
        self._action_scan_folder.triggered.connect(self._on_scan_folder)
        toolbar.addAction(self._action_scan_folder)

        toolbar.addSeparator()

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by filename…")
        self._search.setClearButtonEnabled(True)
        self._search.setMaximumWidth(240)
        self._search.textChanged.connect(self._on_search)
        toolbar.addWidget(self._search)

        self._action_settings = QAction(
            icons.glyph_icon(icons.GLYPHS["settings"], self.palette_), "Settings", self
        )
        self._action_settings.setShortcut("Ctrl+,")
        self._action_settings.triggered.connect(self.open_settings)
        toolbar.addAction(self._action_settings)

        self._action_about = QAction(
            icons.glyph_icon(icons.GLYPHS["about"], self.palette_), "About", self
        )
        self._action_about.triggered.connect(self._on_about)
        toolbar.addAction(self._action_about)

    def _build_central(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 6, 12)
        left_layout.setSpacing(10)

        self.drop_zone = DropZone()
        self.drop_zone.filesDropped.connect(self.controller.scan_files)
        left_layout.addWidget(self.drop_zone)

        self.table = ScanTable(self.palette_)
        self.table.scanSelected.connect(self._on_scan_selected)
        self.table.customContextMenuRequested.connect(self._on_table_menu)
        left_layout.addWidget(self.table, stretch=1)

        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(6, 12, 12, 12)

        self.detail = DetailPanel(self.palette_)
        self.detail.rescanRequested.connect(self._on_rescan)
        self.detail.deleteRequested.connect(self._on_delete)
        self.detail.openFolderRequested.connect(self._on_open_folder)
        self.detail.verdictOverridden.connect(self._on_override)
        right_layout.addWidget(self.detail)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 4)
        splitter.setChildrenCollapsible(False)

        self._splitter = splitter
        self.setCentralWidget(splitter)

    def _build_statusbar(self) -> None:
        bar = QStatusBar()
        self.setStatusBar(bar)

        self._status_message = QLabel("Ready")
        bar.addWidget(self._status_message, stretch=1)

        self._status_ai = QLabel()
        bar.addPermanentWidget(self._status_ai)

        self._status_queue = QLabel()
        bar.addPermanentWidget(self._status_queue)

        self._update_status_indicators()

    def _connect_controller(self) -> None:
        self.controller.scanQueued.connect(self._on_queued)
        self.controller.scanStarted.connect(self._on_started)
        self.controller.scanProgressed.connect(self._on_progressed)
        self.controller.scanCompleted.connect(self._on_completed)
        self.controller.scanFailed.connect(self._on_failed)
        self.controller.scanRejected.connect(self._on_rejected)
        self.controller.duplicateFound.connect(self._on_duplicate)
        self.controller.queueChanged.connect(self._on_queue_changed)
        self.controller.historyChanged.connect(self._schedule_refresh)

    # -------------------------------------------------------------- data --
    def refresh(self) -> None:
        try:
            scans = self.controller.history(limit=self.settings.history_limit or 1000)
            rows = [ScanRow.from_orm(scan) for scan in scans]
        except Exception:
            logger.exception("history_load_failed")
            return

        self.table.set_rows(rows)

        if not rows:
            self.drop_zone.set_message("Drop PDF files here", "or click to browse")
            self.detail.clear()
        elif self.table.selected_scan_id() is None:
            self.table.select_first()

        self._update_status_indicators()

    def _schedule_refresh(self) -> None:
        self._refresh_timer.start()

    def _update_status_indicators(self) -> None:
        if self.settings.ai_enabled:
            self._status_ai.setText(f"AI: {self.settings.ai_provider.value}")
            self._status_ai.setToolTip(
                "Ambiguous files are sent to the AI reviewer as an evidence summary."
            )
        else:
            self._status_ai.setText("AI: off")
            self._status_ai.setToolTip(
                "Everything is analysed locally. Nothing leaves this computer."
            )

        depth = self.controller.queue_depth
        self._status_queue.setText(f"Queue: {depth}" if depth else "Idle")

    # ------------------------------------------------------------ actions --
    def _on_scan_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select PDF files to scan", "", "PDF documents (*.pdf);;All files (*.*)"
        )
        if paths:
            self.controller.scan_files(paths)

    def _on_scan_folder(self) -> None:
        from pdfsafe import paths as app_paths

        folder = QFileDialog.getExistingDirectory(
            self, "Select a folder to scan", str(app_paths.watch_default_dir())
        )
        if not folder:
            return
        count = self.controller.scan_folder(folder, recursive=False)
        self._status_message.setText(
            f"Queued {count} PDF{'s' if count != 1 else ''} from {folder}"
            if count
            else f"No PDFs found in {folder}"
        )

    def open_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec() != SettingsDialog.DialogCode.Accepted:
            return

        self.settings = reload_settings()
        self.controller.apply_settings(self.settings)
        self.apply_theme(palette_for(self.settings.theme))
        self._update_status_indicators()
        self._status_message.setText("Settings saved")

    def apply_theme(self, palette: Palette) -> None:
        self.palette_ = palette
        self.setStyleSheet(stylesheet(palette))
        self.table.update_palette(palette)
        self.detail.update_palette(palette)
        self.setWindowIcon(icons.app_icon(palette))

    def _on_about(self) -> None:
        AboutDialog(self).exec()

    def _on_search(self, text: str) -> None:
        self.table.set_filter(text)

    def _on_scan_selected(self, scan_id: uuid.UUID) -> None:
        try:
            scan = self.controller.detail(scan_id)
        except Exception:
            logger.exception("detail_load_failed", scan_id=str(scan_id))
            return
        self.detail.show_scan(scan)

    def _on_rescan(self, scan_id: uuid.UUID) -> None:
        if not self.settings.ai_enabled:
            answer = QMessageBox.question(
                self,
                "AI review is turned off",
                "Re-scanning will repeat the same local analysis and reach the same "
                "conclusion.\n\nTurn on AI review in Settings for a second opinion.\n\n"
                "Re-scan anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self.controller.rescan(scan_id, force_ai=self.settings.ai_enabled)
        self._status_message.setText("Re-scanning…")

    def _on_delete(self, scan_id: uuid.UUID) -> None:
        answer = QMessageBox.question(
            self,
            "Remove this scan?",
            "The scan record will be deleted from your history. The original file on "
            "disk is not affected.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.controller.delete(scan_id)
            self.detail.clear()

    def _on_override(self, scan_id: uuid.UUID, verdict: Verdict) -> None:
        answer = QMessageBox.question(
            self,
            "Mark this file as safe?",
            "This overrides the automated verdict and releases the file from quarantine "
            "if it was isolated.\n\nOnly do this if you know where the file came from.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.controller.set_verdict(scan_id, verdict, note="Marked safe by the user")

    def _on_open_folder(self, scan_id: uuid.UUID) -> None:
        try:
            scan = self.controller.detail(scan_id)
        except Exception:
            return

        origin = (scan.extra or {}).get("origin_path")
        if origin:
            from pathlib import Path

            parent = Path(origin).parent
            if parent.is_dir():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(parent)))
                return

        from pdfsafe import paths as app_paths

        target = app_paths.quarantine_dir() if scan.quarantined else app_paths.storage_dir()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))

    def _on_table_menu(self, position: Any) -> None:
        scan_id = self.table.selected_scan_id()
        if scan_id is None:
            return

        menu = QMenu(self)
        menu.addAction("Re-scan", lambda: self._on_rescan(scan_id))
        menu.addAction("Show file location", lambda: self._on_open_folder(scan_id))
        menu.addSeparator()
        menu.addAction("Mark as safe", lambda: self._on_override(scan_id, Verdict.CLEAN))
        menu.addAction("Remove from history", lambda: self._on_delete(scan_id))
        menu.exec(self.table.viewport().mapToGlobal(position))

    # ------------------------------------------------------------- events --
    def _on_queued(self, event: ScanEvent) -> None:
        self._status_message.setText(f"Queued {event.filename}")

    def _on_started(self, event: ScanEvent) -> None:
        self._status_message.setText(f"Analysing {event.filename}…")

    def _on_progressed(self, event: ScanEvent) -> None:
        self._status_message.setText(f"AI review: {event.filename}…")

    def _on_completed(self, event: ScanEvent) -> None:
        verdict = event.verdict or Verdict.UNKNOWN
        colour = verdict_color(verdict, self.palette_)
        self._status_message.setText(
            f"<span style='color:{colour}'>{verdict.value.replace('_', ' ')}</span> — "
            f"{event.filename} ({event.risk_score}/100)"
        )
        if event.scan_id is not None and self.table.selected_scan_id() == event.scan_id:
            self._on_scan_selected(event.scan_id)

    def _on_failed(self, event: ScanEvent) -> None:
        self._status_message.setText(f"Failed: {event.message}")

    def _on_rejected(self, event: ScanEvent) -> None:
        self._status_message.setText(event.message)
        QMessageBox.information(self, "File not scanned", event.message)

    def _on_duplicate(self, event: ScanEvent) -> None:
        self._status_message.setText(event.message)
        scan_id = event.scan_id
        if scan_id is not None:
            self._schedule_refresh()
            QTimer.singleShot(300, lambda: self.table.select_scan(scan_id))

    def _on_queue_changed(self, depth: int) -> None:
        self._status_queue.setText(f"Queue: {depth}" if depth else "Idle")

    # ------------------------------------------------------------ updates --
    def check_for_updates(self, *, silent: bool = True) -> None:
        if self._update_thread is not None and self._update_thread.isRunning():
            return

        self._update_thread = UpdateCheckThread(self)
        self._update_thread.updateAvailable.connect(self._on_update_available)
        if not silent:
            self._update_thread.upToDate.connect(
                lambda: QMessageBox.information(
                    self, "You are up to date", f"PDFSafe {__version__} is the latest version."
                )
            )
            self._update_thread.checkFailed.connect(
                lambda message: QMessageBox.warning(self, "Update check failed", message)
            )
        else:
            self._update_thread.checkFailed.connect(
                lambda message: logger.info("update_check_failed", error=message)
            )
        self._update_thread.start()

    def _on_update_available(self, info: Any) -> None:
        UpdateDialog(info, self).exec()

    # ---------------------------------------------------------- lifecycle --
    def _restore_geometry(self) -> None:
        store = QSettings("PDFSafe", "Desktop")
        geometry = store.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        splitter_state = store.value("window/splitter")
        if splitter_state is not None:
            self._splitter.restoreState(splitter_state)

    def _save_geometry(self) -> None:
        store = QSettings("PDFSafe", "Desktop")
        store.setValue("window/geometry", self.saveGeometry())
        store.setValue("window/splitter", self._splitter.saveState())

    def request_quit(self) -> None:
        """Quit for real, bypassing close-to-tray."""
        self._force_quit = True
        self.close()

    def closeEvent(self, event: QCloseEvent) -> None:
        self._save_geometry()

        if self._force_quit or not self.settings.close_to_tray:
            self.quitRequested.emit()
            event.accept()
            return

        event.ignore()
        self.hide()

    def show_scan(self, scan_id: uuid.UUID) -> None:
        """Bring the window forward with one scan selected."""
        self.showNormal()
        self.raise_()
        self.activateWindow()
        self.table.select_scan(scan_id)


__all__ = ["MainWindow"]
