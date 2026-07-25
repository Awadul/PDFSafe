"""Scan history table."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QWidget

from pdfsafe.desktop.theme import Palette, verdict_color
from pdfsafe.enums import ScanStatus, Verdict

COLUMN_FILE = 0
COLUMN_VERDICT = 1
COLUMN_SCORE = 2
COLUMN_STATUS = 3
COLUMN_WHEN = 4

HEADERS = ("File", "Verdict", "Risk", "Status", "Scanned")

#: Custom role carrying the scan id so views can act without re-querying.
SCAN_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 1


@dataclass(slots=True)
class ScanRow:
    """Flat, detached view of a scan - safe to hold after the session closes."""

    scan_id: uuid.UUID
    filename: str
    verdict: Verdict
    status: ScanStatus
    risk_score: int
    created_at: datetime
    decided_by: str
    summary: str
    quarantined: bool
    sha256: str
    file_size: int

    @classmethod
    def from_orm(cls, scan: Any) -> ScanRow:
        return cls(
            scan_id=scan.id,
            filename=scan.filename,
            verdict=scan.verdict,
            status=scan.status,
            risk_score=scan.risk_score,
            created_at=scan.created_at,
            decided_by=scan.decided_by.value if scan.decided_by else "",
            summary=scan.summary or "",
            quarantined=scan.quarantined,
            sha256=scan.sha256,
            file_size=scan.file_size,
        )


class ScanTableModel(QAbstractTableModel):
    """Table model over a list of :class:`ScanRow`."""

    def __init__(self, palette: Palette, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._rows: list[ScanRow] = []
        self._palette = palette

    # ------------------------------------------------------------- qt api --
    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        return HEADERS[section]

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()

        if role == SCAN_ID_ROLE:
            return row.scan_id

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, column)

        if role == Qt.ItemDataRole.ToolTipRole:
            parts = [row.filename, f"SHA-256: {row.sha256}"]
            if row.summary:
                parts.append(row.summary)
            if row.quarantined:
                parts.append("This file has been quarantined.")
            return "\n\n".join(parts)

        if role == Qt.ItemDataRole.ForegroundRole and column == COLUMN_VERDICT:
            return QColor(verdict_color(row.verdict, self._palette))

        if role == Qt.ItemDataRole.TextAlignmentRole and column in (COLUMN_SCORE, COLUMN_WHEN):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        # Sort on the underlying value, not the formatted string.
        if role == Qt.ItemDataRole.EditRole:
            return self._sort_value(row, column)

        return None

    # ------------------------------------------------------------ helpers --
    def _display(self, row: ScanRow, column: int) -> str:
        match column:
            case 0:
                return f"⚠ {row.filename}" if row.quarantined else row.filename
            case 1:
                return row.verdict.value.replace("_", " ")
            case 2:
                return "—" if row.status is ScanStatus.PENDING else str(row.risk_score)
            case 3:
                return row.status.value.replace("_", " ")
            case 4:
                return self._relative_time(row.created_at)
        return ""

    def _sort_value(self, row: ScanRow, column: int) -> Any:
        match column:
            case 0:
                return row.filename.lower()
            case 1:
                return row.verdict.value
            case 2:
                return row.risk_score
            case 3:
                return row.status.value
            case 4:
                return row.created_at.timestamp()
        return ""

    @staticmethod
    def _relative_time(when: datetime) -> str:
        from datetime import UTC

        now = datetime.now(UTC)
        moment = when if when.tzinfo else when.replace(tzinfo=UTC)
        seconds = (now - moment).total_seconds()

        if seconds < 60:
            return "just now"
        if seconds < 3600:
            return f"{int(seconds // 60)} min ago"
        if seconds < 86400:
            return f"{int(seconds // 3600)} h ago"
        if seconds < 604800:
            return f"{int(seconds // 86400)} d ago"
        return moment.astimezone().strftime("%Y-%m-%d")

    # --------------------------------------------------------------- data --
    def set_rows(self, rows: list[ScanRow]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def row_at(self, index: int) -> ScanRow | None:
        if 0 <= index < len(self._rows):
            return self._rows[index]
        return None

    def index_of(self, scan_id: uuid.UUID) -> int:
        for position, row in enumerate(self._rows):
            if row.scan_id == scan_id:
                return position
        return -1

    def update_palette(self, palette: Palette) -> None:
        self._palette = palette
        if self._rows:
            top = self.index(0, 0)
            bottom = self.index(len(self._rows) - 1, len(HEADERS) - 1)
            self.dataChanged.emit(top, bottom, [Qt.ItemDataRole.ForegroundRole])


class ScanTable(QTableView):
    """History view with sorting, filtering and a selection signal."""

    scanSelected = Signal(object)   # uuid.UUID
    scanActivated = Signal(object)  # uuid.UUID

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._model = ScanTableModel(palette, self)

        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setSortRole(Qt.ItemDataRole.EditRole)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setFilterKeyColumn(COLUMN_FILE)
        self.setModel(self._proxy)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(34)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        header = self.horizontalHeader()
        header.setSectionResizeMode(COLUMN_FILE, QHeaderView.ResizeMode.Stretch)
        for column in (COLUMN_VERDICT, COLUMN_SCORE, COLUMN_STATUS, COLUMN_WHEN):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setHighlightSections(False)

        self.sortByColumn(COLUMN_WHEN, Qt.SortOrder.DescendingOrder)
        self.selectionModel().selectionChanged.connect(self._emit_selection)
        self.doubleClicked.connect(self._emit_activation)

    # --------------------------------------------------------------- data --
    def set_rows(self, rows: list[ScanRow]) -> None:
        selected = self.selected_scan_id()
        self._model.set_rows(rows)
        if selected is not None:
            self.select_scan(selected)

    def set_filter(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)

    def selected_scan_id(self) -> uuid.UUID | None:
        indexes = self.selectionModel().selectedRows() if self.selectionModel() else []
        if not indexes:
            return None
        value = indexes[0].data(SCAN_ID_ROLE)
        return value if isinstance(value, uuid.UUID) else None

    def select_scan(self, scan_id: uuid.UUID) -> None:
        source_row = self._model.index_of(scan_id)
        if source_row < 0:
            return
        proxy_index = self._proxy.mapFromSource(self._model.index(source_row, 0))
        if proxy_index.isValid():
            self.selectRow(proxy_index.row())

    def select_first(self) -> None:
        if self._proxy.rowCount() > 0:
            self.selectRow(0)

    def update_palette(self, palette: Palette) -> None:
        self._model.update_palette(palette)

    # -------------------------------------------------------------- events --
    def _emit_selection(self) -> None:
        scan_id = self.selected_scan_id()
        if scan_id is not None:
            self.scanSelected.emit(scan_id)

    def _emit_activation(self, index: QModelIndex) -> None:
        value = index.data(SCAN_ID_ROLE)
        if isinstance(value, uuid.UUID):
            self.scanActivated.emit(value)
