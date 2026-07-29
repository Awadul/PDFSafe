"""Settings dialog.

Preferences are written to ``config.json``; the API key goes to the OS
credential manager and never touches that file.
"""

from __future__ import annotations

import contextlib
from typing import Any

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pdfsafe import credentials
from pdfsafe.config import Isolation, Settings, get_settings, save_user_settings
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

KEY_PLACEHOLDER = "•" * 24


class SettingsDialog(QDialog):
    """Edits the user-facing subset of :class:`~pdfsafe.config.Settings`."""

    def __init__(self, settings: Settings | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings or get_settings()
        self._key_touched = False

        self.setWindowTitle("PDFSafe Settings")
        self.setMinimumWidth(560)
        self.setModal(True)

        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        tabs.addTab(self._build_scanning_tab(), "Scanning")
        tabs.addTab(self._build_ai_tab(), "AI review")
        tabs.addTab(self._build_folders_tab(), "Watched folders")
        tabs.addTab(self._build_app_tab(), "Application")
        layout.addWidget(tabs)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._load()

    # -------------------------------------------------------------- build --
    def _build_scanning_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        engine_box = QGroupBox("Engine")
        form = QFormLayout(engine_box)

        self._workers = QSpinBox()
        self._workers.setRange(1, 8)
        self._workers.setToolTip("How many files are analysed at the same time.")
        form.addRow("Parallel scans", self._workers)

        self._timeout = QSpinBox()
        self._timeout.setRange(5, 600)
        self._timeout.setSuffix(" s")
        form.addRow("Timeout per file", self._timeout)

        self._isolation = QComboBox()
        self._isolation.addItem("Sandboxed child process (recommended)", Isolation.PROCESS.value)
        self._isolation.addItem("Same process (faster, less safe)", Isolation.IN_PROCESS.value)
        form.addRow("Parsing mode", self._isolation)

        isolation_note = QLabel(
            "Sandboxing runs the PDF parser in a separate process, so a malformed file "
            "that crashes or hangs the parser cannot take PDFSafe down with it."
        )
        isolation_note.setWordWrap(True)
        isolation_note.setObjectName("Muted")
        form.addRow("", isolation_note)

        self._max_size = QSpinBox()
        self._max_size.setRange(1, 2048)
        self._max_size.setSuffix(" MB")
        form.addRow("Maximum file size", self._max_size)

        self._yara = QCheckBox("Enable YARA signature rules")
        form.addRow("", self._yara)

        layout.addWidget(engine_box)

        handling_box = QGroupBox("File handling")
        handling_form = QFormLayout(handling_box)

        self._quarantine = QCheckBox("Move malicious files to quarantine")
        handling_form.addRow("", self._quarantine)

        self._keep_copies = QCheckBox("Keep a copy of every scanned file")
        self._keep_copies.setToolTip(
            "Copies let you re-scan later. Turn this off to save disk space; "
            "malicious files are still kept in quarantine."
        )
        handling_form.addRow("", self._keep_copies)

        self._history_limit = QSpinBox()
        self._history_limit.setRange(100, 100_000)
        self._history_limit.setSingleStep(500)
        handling_form.addRow("History entries to keep", self._history_limit)

        layout.addWidget(handling_box)
        layout.addStretch()
        return page

    def _build_ai_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        explanation = QLabel(
            "PDFSafe works entirely offline using its own rules. AI review is optional: "
            "when a file is ambiguous, a summary of what was found — never the file "
            "itself — can be sent to a language model for a second opinion.\n\n"
            "You supply your own API key. It is stored in Windows Credential Manager, "
            "not in PDFSafe's settings file."
        )
        explanation.setWordWrap(True)
        explanation.setObjectName("Muted")
        layout.addWidget(explanation)

        provider_box = QGroupBox("Provider")
        form = QFormLayout(provider_box)

        self._ai_enabled = QCheckBox("Enable AI review")
        form.addRow("", self._ai_enabled)

        self._ai_provider = QComboBox()
        self._ai_provider.addItem("Anthropic (Claude)", "anthropic")
        self._ai_provider.addItem("Custom endpoint (OpenAI-compatible)", "custom")
        form.addRow("Provider", self._ai_provider)

        key_row = QHBoxLayout()
        self._api_key = QLineEdit()
        self._api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key.setPlaceholderText("sk-ant-…")
        self._api_key.textEdited.connect(self._on_key_edited)
        key_row.addWidget(self._api_key, stretch=1)

        self._clear_key = QPushButton("Remove")
        self._clear_key.setObjectName("secondary")
        self._clear_key.clicked.connect(self._on_clear_key)
        key_row.addWidget(self._clear_key)

        key_widget = QWidget()
        key_widget.setLayout(key_row)
        form.addRow("API key", key_widget)

        self._key_status = QLabel()
        self._key_status.setObjectName("Muted")
        form.addRow("", self._key_status)

        self._model = QLineEdit()
        form.addRow("Model", self._model)

        self._custom_url = QLineEdit()
        self._custom_url.setPlaceholderText("https://your-gateway.example.com/v1")
        form.addRow("Custom base URL", self._custom_url)

        layout.addWidget(provider_box)

        gate_box = QGroupBox("When to ask the AI")
        gate_form = QFormLayout(gate_box)

        self._escalate_min = QSpinBox()
        self._escalate_min.setRange(0, 100)
        gate_form.addRow("Skip AI below risk score", self._escalate_min)

        self._escalate_max = QSpinBox()
        self._escalate_max.setRange(0, 100)
        gate_form.addRow("Skip AI at or above risk score", self._escalate_max)

        self._always_escalate = QCheckBox("Always ask the AI (ignores the range above)")
        gate_form.addRow("", self._always_escalate)

        gate_note = QLabel(
            "Files scoring below the first threshold are already clearly safe, and files "
            "at or above the second are already clearly malicious. Only the range between "
            "them is worth spending tokens on."
        )
        gate_note.setWordWrap(True)
        gate_note.setObjectName("Muted")
        gate_form.addRow("", gate_note)

        self._share_text = QCheckBox("Include a text excerpt from the document")
        self._share_text.setToolTip(
            "Helps detect phishing wording. Turn off if documents may contain sensitive text."
        )
        gate_form.addRow("", self._share_text)

        layout.addWidget(gate_box)
        layout.addStretch()

        self._ai_provider.currentIndexChanged.connect(self._sync_provider_fields)
        self._ai_enabled.toggled.connect(self._sync_provider_fields)
        return page

    def _build_folders_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        self._watch_enabled = QCheckBox("Automatically scan new PDFs in these folders")
        layout.addWidget(self._watch_enabled)

        self._folders = QListWidget()
        layout.addWidget(self._folders, stretch=1)

        buttons = QHBoxLayout()
        add = QPushButton("Add folder…")
        add.setObjectName("secondary")
        add.clicked.connect(self._on_add_folder)
        buttons.addWidget(add)

        remove = QPushButton("Remove")
        remove.setObjectName("secondary")
        remove.clicked.connect(self._on_remove_folder)
        buttons.addWidget(remove)
        buttons.addStretch()
        layout.addLayout(buttons)

        self._recursive = QCheckBox("Include subfolders")
        layout.addWidget(self._recursive)

        note = QLabel(
            "New files are scanned once they finish downloading. Files already present "
            "when a folder is added are left alone."
        )
        note.setWordWrap(True)
        note.setObjectName("Muted")
        layout.addWidget(note)
        return page

    def _build_app_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        behaviour = QGroupBox("Behaviour")
        form = QFormLayout(behaviour)

        self._autostart = QCheckBox("Start PDFSafe when I sign in")
        form.addRow("", self._autostart)

        self._start_minimized = QCheckBox("Start minimised to the notification area")
        form.addRow("", self._start_minimized)

        self._close_to_tray = QCheckBox("Keep running in the notification area when closed")
        form.addRow("", self._close_to_tray)

        self._notify = QCheckBox("Show a notification when a scan finishes")
        form.addRow("", self._notify)

        self._notify_level = QComboBox()
        self._notify_level.addItem("Suspicious and malicious", "suspicious")
        self._notify_level.addItem("Malicious only", "malicious")
        form.addRow("Notify for", self._notify_level)

        self._theme = QComboBox()
        for label, value in (("Follow Windows", "system"), ("Dark", "dark"), ("Light", "light")):
            self._theme.addItem(label, value)
        form.addRow("Appearance", self._theme)

        layout.addWidget(behaviour)

        updates = QGroupBox("Updates")
        update_form = QFormLayout(updates)

        self._update_check = QCheckBox("Check for updates automatically")
        update_form.addRow("", self._update_check)

        self._update_channel = QComboBox()
        self._update_channel.addItem("Stable", "stable")
        self._update_channel.addItem("Beta", "beta")
        update_form.addRow("Channel", self._update_channel)

        layout.addWidget(updates)

        diagnostics = QGroupBox("Diagnostics")
        diagnostics_form = QFormLayout(diagnostics)

        self._log_level = QComboBox()
        for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
            self._log_level.addItem(level, level)
        diagnostics_form.addRow("Log level", self._log_level)

        open_logs = QPushButton("Open log folder")
        open_logs.setObjectName("secondary")
        open_logs.clicked.connect(self._on_open_logs)
        diagnostics_form.addRow("", open_logs)

        layout.addWidget(diagnostics)
        layout.addStretch()
        return page

    # --------------------------------------------------------------- load --
    def _load(self) -> None:
        s = self.settings

        self._workers.setValue(s.analysis_workers)
        self._timeout.setValue(s.analysis_timeout_seconds)
        self._select_data(self._isolation, s.analysis_isolation.value)
        self._max_size.setValue(max(1, s.max_upload_bytes // (1024 * 1024)))
        self._yara.setChecked(s.enable_yara)
        self._quarantine.setChecked(s.quarantine_enabled)
        self._keep_copies.setChecked(s.keep_scanned_copies)
        self._history_limit.setValue(s.history_limit)

        self._ai_enabled.setChecked(s.ai_enabled)
        self._select_data(self._ai_provider, s.ai_provider.value)
        self._model.setText(
            s.custom_ai_model if s.ai_provider.value == "custom" else s.anthropic_model
        )
        self._custom_url.setText(s.custom_ai_base_url)
        self._escalate_min.setValue(s.ai_escalate_min_score)
        self._escalate_max.setValue(s.ai_escalate_max_score)
        self._always_escalate.setChecked(s.ai_always_escalate)
        self._share_text.setChecked(s.ai_share_text_excerpt)
        self._refresh_key_status()

        self._watch_enabled.setChecked(s.watch_enabled)
        self._folders.addItems(s.watch_folders)
        self._recursive.setChecked(s.watch_recursive)

        self._autostart.setChecked(s.autostart)
        self._start_minimized.setChecked(s.start_minimized)
        self._close_to_tray.setChecked(s.close_to_tray)
        self._notify.setChecked(s.notify_on_verdict)
        self._select_data(self._notify_level, s.notify_min_verdict)
        self._select_data(self._theme, s.theme)
        self._update_check.setChecked(s.update_check_enabled)
        self._select_data(self._update_channel, s.update_channel)
        self._select_data(self._log_level, s.log_level)

        self._sync_provider_fields()

    def _refresh_key_status(self) -> None:
        provider = self._ai_provider.currentData()
        if not credentials.is_available():
            self._key_status.setText(
                "No credential store is available on this system; the key cannot be saved securely."
            )
            self._api_key.setEnabled(False)
            return

        stored = credentials.get_api_key(provider)
        if stored:
            self._api_key.setText(KEY_PLACEHOLDER)
            self._key_status.setText(f"A key is saved ({credentials.masked(stored)}).")
            self._clear_key.setEnabled(True)
        else:
            self._api_key.clear()
            self._key_status.setText("No key saved. AI review stays disabled without one.")
            self._clear_key.setEnabled(False)
        self._key_touched = False

    # --------------------------------------------------------------- save --
    def _save(self) -> None:
        if self._escalate_min.value() > self._escalate_max.value():
            QMessageBox.warning(
                self,
                "Check the AI thresholds",
                "The lower threshold must not be greater than the upper threshold.",
            )
            return

        provider = self._ai_provider.currentData()

        if self._ai_enabled.isChecked():
            has_key = self._key_touched and self._api_key.text().strip()
            if not has_key and not credentials.has_api_key(provider):
                QMessageBox.warning(
                    self,
                    "An API key is required",
                    "AI review needs an API key for the selected provider. Add one, or "
                    "turn AI review off — static analysis works without it.",
                )
                return

        if self._key_touched:
            try:
                credentials.set_api_key(provider, self._api_key.text().strip())
            except credentials.CredentialStoreUnavailableError as exc:
                QMessageBox.critical(self, "Could not save the API key", str(exc))
                return

        values: dict[str, Any] = {
            "analysis_workers": self._workers.value(),
            "analysis_timeout_seconds": self._timeout.value(),
            "analysis_isolation": self._isolation.currentData(),
            "max_upload_bytes": self._max_size.value() * 1024 * 1024,
            "enable_yara": self._yara.isChecked(),
            "quarantine_enabled": self._quarantine.isChecked(),
            "keep_scanned_copies": self._keep_copies.isChecked(),
            "history_limit": self._history_limit.value(),
            "ai_enabled": self._ai_enabled.isChecked(),
            "ai_provider": provider,
            "ai_escalate_min_score": self._escalate_min.value(),
            "ai_escalate_max_score": self._escalate_max.value(),
            "ai_always_escalate": self._always_escalate.isChecked(),
            "ai_share_text_excerpt": self._share_text.isChecked(),
            "custom_ai_base_url": self._custom_url.text().strip(),
            "watch_enabled": self._watch_enabled.isChecked(),
            "watch_folders": [self._folders.item(i).text() for i in range(self._folders.count())],
            "watch_recursive": self._recursive.isChecked(),
            "autostart": self._autostart.isChecked(),
            "start_minimized": self._start_minimized.isChecked(),
            "close_to_tray": self._close_to_tray.isChecked(),
            "notify_on_verdict": self._notify.isChecked(),
            "notify_min_verdict": self._notify_level.currentData(),
            "theme": self._theme.currentData(),
            "update_check_enabled": self._update_check.isChecked(),
            "update_channel": self._update_channel.currentData(),
            "log_level": self._log_level.currentData(),
        }

        model = self._model.text().strip()
        if provider == "custom":
            values["custom_ai_model"] = model
        else:
            values["anthropic_model"] = model

        try:
            save_user_settings(values)
        except OSError as exc:
            QMessageBox.critical(
                self, "Could not save settings", f"Settings could not be written:\n\n{exc}"
            )
            return

        self._apply_autostart(self._autostart.isChecked())
        logger.info("settings_saved", ai_enabled=values["ai_enabled"], provider=provider)
        self.accept()

    def _apply_autostart(self, enabled: bool) -> None:
        """Register or remove the per-user Run entry (Windows only)."""
        import sys

        if sys.platform != "win32":
            return
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            )
            with key:
                if enabled:
                    target = f'"{sys.executable}" --minimized'
                    winreg.SetValueEx(key, "PDFSafe", 0, winreg.REG_SZ, target)
                else:
                    # Already absent is the desired end state, not an error.
                    with contextlib.suppress(FileNotFoundError):
                        winreg.DeleteValue(key, "PDFSafe")
        except OSError as exc:  # pragma: no cover
            logger.warning("autostart_update_failed", error=str(exc))

    # ------------------------------------------------------------ actions --
    def _on_key_edited(self, _: str) -> None:
        self._key_touched = True
        self._key_status.setText("The key will be saved when you press OK.")

    def _on_clear_key(self) -> None:
        provider = self._ai_provider.currentData()
        credentials.delete_api_key(provider)
        self._api_key.clear()
        self._key_touched = False
        self._refresh_key_status()

    def _on_add_folder(self) -> None:
        from pdfsafe import paths

        folder = QFileDialog.getExistingDirectory(
            self, "Choose a folder to watch", str(paths.watch_default_dir())
        )
        if not folder:
            return
        existing = {self._folders.item(i).text() for i in range(self._folders.count())}
        if folder not in existing:
            self._folders.addItem(folder)

    def _on_remove_folder(self) -> None:
        for item in self._folders.selectedItems():
            self._folders.takeItem(self._folders.row(item))

    def _on_open_logs(self) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        from pdfsafe import paths

        QDesktopServices.openUrl(QUrl.fromLocalFile(str(paths.log_dir())))

    # ------------------------------------------------------------ helpers --
    def _sync_provider_fields(self) -> None:
        is_custom = self._ai_provider.currentData() == "custom"
        enabled = self._ai_enabled.isChecked()

        self._custom_url.setVisible(is_custom)
        for widget in (
            self._ai_provider,
            self._api_key,
            self._model,
            self._custom_url,
            self._escalate_min,
            self._escalate_max,
            self._always_escalate,
            self._share_text,
            self._clear_key,
        ):
            widget.setEnabled(enabled)

        self._escalate_min.setEnabled(enabled and not self._always_escalate.isChecked())
        self._escalate_max.setEnabled(enabled and not self._always_escalate.isChecked())
        self._refresh_key_status()

    @staticmethod
    def _select_data(combo: QComboBox, value: Any) -> None:
        index = combo.findData(value)
        if index >= 0:
            combo.setCurrentIndex(index)


__all__ = ["SettingsDialog"]
