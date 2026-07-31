"""Detail panel: the verdict, why it was reached, and the underlying evidence."""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pdfsafe.desktop.theme import Palette, severity_color, verdict_color
from pdfsafe.enums import ScanStatus, Verdict

VERDICT_HEADLINES = {
    Verdict.CLEAN: "No threats found",
    Verdict.LOW_RISK: "Minor traits, likely benign",
    Verdict.SUSPICIOUS: "Suspicious — review before opening",
    Verdict.MALICIOUS: "Malicious — do not open",
    Verdict.UNKNOWN: "Inconclusive",
}


class DetailPanel(QWidget):
    """Shows everything known about one scan."""

    rescanRequested = Signal(object)
    deleteRequested = Signal(object)
    openFolderRequested = Signal(object)
    verdictOverridden = Signal(object, object)  # scan_id, Verdict

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.palette_ = palette
        self._scan: Any = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self._banner = _VerdictBanner(palette)
        layout.addWidget(self._banner)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_findings_tab(), "Findings")
        self._tabs.addTab(self._build_structure_tab(), "Structure")
        self._tabs.addTab(self._build_ai_tab(), "AI review")
        self._tabs.addTab(self._build_raw_tab(), "Raw")
        layout.addWidget(self._tabs, stretch=1)

        layout.addLayout(self._build_actions())

        self._placeholder = QLabel("Select a scan to see its report.")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder.setObjectName("Muted")
        layout.addWidget(self._placeholder)

        self.clear()

    # -------------------------------------------------------------- build --
    def _build_findings_tab(self) -> QWidget:
        container = QWidget()
        outer = QVBoxLayout(container)
        outer.setContentsMargins(0, 8, 0, 0)

        self._summary = QLabel()
        self._summary.setWordWrap(True)
        self._summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(self._summary)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self._indicator_host = QWidget()
        self._indicator_layout = QVBoxLayout(self._indicator_host)
        self._indicator_layout.setContentsMargins(0, 8, 0, 0)
        self._indicator_layout.setSpacing(8)
        self._indicator_layout.addStretch()

        scroll.setWidget(self._indicator_host)
        outer.addWidget(scroll, stretch=1)
        return container

    def _build_structure_tab(self) -> QWidget:
        self._structure_tree = QTreeWidget()
        self._structure_tree.setHeaderLabels(["Property", "Value"])
        self._structure_tree.setAlternatingRowColors(True)
        self._structure_tree.setColumnWidth(0, 220)
        return self._structure_tree

    def _build_ai_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 8, 0, 0)

        self._ai_header = QLabel()
        self._ai_header.setObjectName("Muted")
        self._ai_header.setWordWrap(True)
        layout.addWidget(self._ai_header)

        self._ai_body = QPlainTextEdit()
        self._ai_body.setReadOnly(True)
        layout.addWidget(self._ai_body, stretch=1)
        return container

    def _build_raw_tab(self) -> QWidget:
        self._raw = QPlainTextEdit()
        self._raw.setReadOnly(True)
        self._raw.setObjectName("Mono")
        self._raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        return self._raw

    def _build_actions(self) -> QHBoxLayout:
        row = QHBoxLayout()

        self._rescan_button = QPushButton("Re-scan with AI")
        self._rescan_button.setObjectName("secondary")
        self._rescan_button.clicked.connect(self._on_rescan_clicked)

        self._mark_safe_button = QPushButton("Mark as safe")
        self._mark_safe_button.setObjectName("secondary")
        self._mark_safe_button.clicked.connect(self._on_mark_safe_clicked)

        self._folder_button = QPushButton("Show file")
        self._folder_button.setObjectName("secondary")
        self._folder_button.clicked.connect(self._on_folder_clicked)

        self._delete_button = QPushButton("Remove")
        self._delete_button.setObjectName("secondary")
        self._delete_button.clicked.connect(self._on_delete_clicked)

        for button in (
            self._rescan_button,
            self._mark_safe_button,
            self._folder_button,
            self._delete_button,
        ):
            row.addWidget(button)
        row.addStretch()
        return row

    def _on_rescan_clicked(self) -> None:
        if self._scan:
            self.rescanRequested.emit(self._scan.id)

    def _on_mark_safe_clicked(self) -> None:
        if self._scan:
            self.verdictOverridden.emit(self._scan.id, Verdict.CLEAN)

    def _on_folder_clicked(self) -> None:
        if self._scan:
            self.openFolderRequested.emit(self._scan.id)

    def _on_delete_clicked(self) -> None:
        if self._scan:
            self.deleteRequested.emit(self._scan.id)

    # --------------------------------------------------------------- data --
    def clear(self) -> None:
        self._scan = None
        self._banner.setVisible(False)
        self._tabs.setVisible(False)
        self._set_actions_visible(False)
        self._placeholder.setVisible(True)

    def show_scan(self, scan: Any) -> None:
        """Populate from a detached ORM ``Scan`` with relations loaded."""
        self._scan = scan
        self._placeholder.setVisible(False)
        self._banner.setVisible(True)
        self._tabs.setVisible(True)
        self._set_actions_visible(True)

        self._banner.update_scan(scan)
        self._summary.setText(self._summary_text(scan))
        self._populate_indicators(scan)
        self._populate_structure(scan)
        self._populate_ai(scan)
        self._populate_raw(scan)

        self._mark_safe_button.setVisible(scan.verdict is not Verdict.CLEAN)
        self._rescan_button.setEnabled(scan.status.is_terminal)

    @staticmethod
    def _summary_text(scan: Any) -> str:
        """One line explaining the verdict, or why there isn't one."""
        if scan.summary:
            return str(scan.summary)
        if scan.status is ScanStatus.FAILED:
            return "PDFSafe could not analyse this file, so no verdict was reached."
        return "No summary available."

    def _set_actions_visible(self, visible: bool) -> None:
        for button in (
            self._rescan_button,
            self._mark_safe_button,
            self._folder_button,
            self._delete_button,
        ):
            button.setVisible(visible)

    def _populate_indicators(self, scan: Any) -> None:
        while self._indicator_layout.count() > 1:
            item = self._indicator_layout.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

        indicators = sorted(scan.indicators, key=lambda i: i.weight, reverse=True)
        if not indicators:
            # A scan that failed has no indicators for the same reason it has no
            # score: nothing was examined. Saying "nothing suspicious was found"
            # here would be read as "this file is fine", which is the one
            # conclusion the app has no basis for. Say so plainly instead.
            if scan.status is ScanStatus.FAILED:
                reason = (scan.error_message or "").strip().splitlines()
                text = (
                    "This file could not be analysed, so it has not been checked "
                    "for anything. Treat it as unknown rather than safe."
                )
                if reason:
                    text += f"\n\nReason: {reason[0]}"
            else:
                text = "No suspicious structures were detected in this document."

            empty = QLabel(text)
            empty.setObjectName("Muted")
            empty.setWordWrap(True)
            self._indicator_layout.insertWidget(0, empty)
            return

        for position, indicator in enumerate(indicators):
            self._indicator_layout.insertWidget(position, _IndicatorCard(indicator, self.palette_))

    def _populate_structure(self, scan: Any) -> None:
        self._structure_tree.clear()
        report = scan.report
        if report is None:
            return

        overview = QTreeWidgetItem(["Document", ""])
        for label, value in (
            ("PDF version", report.pdf_version),
            ("Pages", report.page_count),
            ("Objects", report.object_count),
            ("Streams", report.stream_count),
            ("Encrypted", "yes" if report.is_encrypted else "no"),
            ("Linearized", "yes" if report.is_linearized else "no"),
            ("Incremental updates", report.incremental_updates),
            ("Entropy", report.entropy),
            ("Analysis time", f"{report.analysis_ms} ms" if report.analysis_ms else None),
        ):
            if value is not None:
                overview.addChild(QTreeWidgetItem([label, str(value)]))
        self._structure_tree.addTopLevelItem(overview)

        self._add_list_branch("Embedded JavaScript", report.javascript, ("location", "length"))
        self._add_list_branch("Actions", report.actions, ("kind", "trigger", "target"))
        self._add_list_branch(
            "Embedded files", report.embedded_files, ("name", "size", "magic_bytes")
        )
        self._add_list_branch("URLs", report.urls, ("url", "source"))
        self._add_list_branch("YARA matches", report.yara_matches, ("rule",))

        metadata = report.document_metadata or {}
        if metadata:
            branch = QTreeWidgetItem(["Metadata", ""])
            for key, value in metadata.items():
                if value and key != "extra":
                    branch.addChild(QTreeWidgetItem([str(key), str(value)[:200]]))
            if branch.childCount():
                self._structure_tree.addTopLevelItem(branch)

        if report.parse_errors:
            branch = QTreeWidgetItem(["Parse notes", str(len(report.parse_errors))])
            for error in report.parse_errors[:20]:
                branch.addChild(QTreeWidgetItem([str(error)[:200], ""]))
            self._structure_tree.addTopLevelItem(branch)

        self._structure_tree.expandItem(overview)

    def _add_list_branch(self, title: str, rows: list[Any] | None, fields: tuple[str, ...]) -> None:
        if not rows:
            return
        branch = QTreeWidgetItem([title, str(len(rows))])
        for entry in rows[:100]:
            if not isinstance(entry, dict):
                branch.addChild(QTreeWidgetItem([str(entry)[:200], ""]))
                continue
            label = str(entry.get(fields[0], ""))[:120]
            detail = " · ".join(
                f"{key}={entry.get(key)}" for key in fields[1:] if entry.get(key) not in (None, "")
            )
            branch.addChild(QTreeWidgetItem([label, detail[:200]]))
        self._structure_tree.addTopLevelItem(branch)

    def _populate_ai(self, scan: Any) -> None:
        assessments = list(scan.ai_assessments or [])
        if not assessments:
            self._ai_header.setText(
                "This file was decided by static analysis alone — the AI reviewer was "
                "not consulted."
            )
            self._ai_body.setPlainText("")
            return

        assessment = assessments[-1]
        tokens = (assessment.prompt_tokens or 0) + (assessment.completion_tokens or 0)
        self._ai_header.setText(
            f"{assessment.provider} / {assessment.model} · "
            f"{assessment.latency_ms or 0} ms · {tokens} tokens"
        )

        if not assessment.succeeded:
            self._ai_body.setPlainText(f"The AI review failed:\n\n{assessment.error_message}")
            return

        sections = [
            f"Verdict: {assessment.verdict.value}  "
            f"(score {assessment.risk_score}, confidence {assessment.confidence})",
            f"Recommended action: {assessment.recommended_action}",
            "",
            assessment.summary or "",
        ]
        if assessment.reasoning:
            sections += ["", "Reasoning", assessment.reasoning]
        if assessment.attack_techniques:
            sections += ["", "Techniques", ", ".join(str(t) for t in assessment.attack_techniques)]
        self._ai_body.setPlainText("\n".join(sections))

    def _populate_raw(self, scan: Any) -> None:
        payload: dict[str, Any] = {
            "id": str(scan.id),
            "filename": scan.filename,
            "sha256": scan.sha256,
            "md5": scan.md5,
            "size": scan.file_size,
            "status": scan.status.value,
            "verdict": scan.verdict.value,
            "risk_score": scan.risk_score,
            "confidence": scan.confidence,
            "decided_by": scan.decided_by.value if scan.decided_by else None,
            "duration_ms": scan.duration_ms,
            "quarantined": scan.quarantined,
            "extra": scan.extra,
            "indicators": [
                {
                    "code": i.code,
                    "severity": i.severity.value,
                    "weight": i.weight,
                    "title": i.title,
                    "evidence": i.evidence,
                }
                for i in scan.indicators
            ],
        }
        self._raw.setPlainText(json.dumps(payload, indent=2, default=str))

    def update_palette(self, palette: Palette) -> None:
        self.palette_ = palette
        self._banner.palette_ = palette
        if self._scan is not None:
            self.show_scan(self._scan)


class _VerdictBanner(QFrame):
    """Coloured summary strip at the top of the panel."""

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.palette_ = palette
        self.setObjectName("VerdictBanner")
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)

        text_column = QVBoxLayout()
        text_column.setSpacing(2)

        self._headline = QLabel()
        self._headline.setObjectName("Heading")
        text_column.addWidget(self._headline)

        self._filename = QLabel()
        self._filename.setObjectName("Muted")
        text_column.addWidget(self._filename)

        layout.addLayout(text_column, stretch=1)

        self._score = QLabel()
        self._score.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self._score)

    def update_scan(self, scan: Any) -> None:
        colour = verdict_color(scan.verdict, self.palette_)

        if scan.status is ScanStatus.FAILED:
            headline = "Analysis failed"
            colour = self.palette_.muted
        elif not scan.status.is_terminal:
            headline = "Analysis in progress…"
            colour = self.palette_.muted
        else:
            headline = VERDICT_HEADLINES.get(scan.verdict, scan.verdict.value)

        self._headline.setText(headline)
        self._headline.setStyleSheet(f"color: {colour};")

        detail = f"{scan.filename} · {scan.file_size / 1024:.0f} KB"
        if scan.quarantined:
            detail += " · quarantined"
        self._filename.setText(detail)

        self._score.setText(
            f"<span style='font-size:26px;font-weight:600;color:{colour}'>"
            f"{scan.risk_score}</span>"
            f"<span style='color:{self.palette_.muted}'>/100</span>"
        )
        self.setStyleSheet(
            f"#VerdictBanner {{ background: {self.palette_.surface}; "
            f"border-left: 3px solid {colour}; }}"
        )


class _IndicatorCard(QFrame):
    """One finding, with its evidence collapsed behind a toggle."""

    def __init__(self, indicator: Any, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        colour = severity_color(indicator.severity, palette)
        self.setStyleSheet(
            f"QFrame {{ background: {palette.surface_alt}; border-radius: 8px; "
            f"border-left: 3px solid {colour}; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        header = QHBoxLayout()
        severity = QLabel(indicator.severity.value.upper())
        severity.setStyleSheet(f"color: {colour}; font-size: 11px; font-weight: 600;")
        header.addWidget(severity)

        title = QLabel(indicator.title)
        title.setStyleSheet("font-weight: 600;")
        title.setWordWrap(True)
        header.addWidget(title, stretch=1)

        weight = QLabel(f"w{indicator.weight}")
        weight.setObjectName("Muted")
        header.addWidget(weight)
        layout.addLayout(header)

        if indicator.description:
            description = QLabel(indicator.description)
            description.setWordWrap(True)
            description.setObjectName("Muted")
            layout.addWidget(description)

        if indicator.evidence:
            evidence = QPlainTextEdit(json.dumps(indicator.evidence, indent=2, default=str))
            evidence.setReadOnly(True)
            evidence.setObjectName("Mono")
            evidence.setMaximumHeight(140)
            evidence.setVisible(False)
            layout.addWidget(evidence)

            toggle = QPushButton("Show evidence")
            toggle.setObjectName("secondary")
            toggle.setCheckable(True)
            toggle.setMaximumWidth(140)

            def _toggle(checked: bool) -> None:
                evidence.setVisible(checked)
                toggle.setText("Hide evidence" if checked else "Show evidence")

            toggle.toggled.connect(_toggle)
            layout.addWidget(toggle)

        if indicator.mitre_technique:
            technique = QLabel(f"MITRE ATT&CK {indicator.mitre_technique}")
            technique.setObjectName("Muted")
            layout.addWidget(technique)


__all__ = ["DetailPanel"]
