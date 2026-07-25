"""Icons drawn at runtime with QPainter.

Deliberately no image assets: drawing the handful of icons the UI needs keeps
the repository free of binary blobs, makes them resolution-independent on
high-DPI displays, and lets the verdict colours follow the active theme. The
installer and the executable still need a real ``.ico``; ``tools/make_icons.py``
renders one from the same geometry at build time.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

from pdfsafe.desktop.theme import Palette, verdict_color
from pdfsafe.enums import Verdict


def _pixmap(size: int) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    return pixmap


def _shield_path(rect: QRectF) -> QPainterPath:
    """A rounded shield outline inside ``rect``."""
    w, h = rect.width(), rect.height()
    x, y = rect.x(), rect.y()

    path = QPainterPath()
    path.moveTo(x + w * 0.5, y)
    path.lineTo(x + w * 0.94, y + h * 0.18)
    path.lineTo(x + w * 0.94, y + h * 0.52)
    path.cubicTo(
        QPointF(x + w * 0.94, y + h * 0.80),
        QPointF(x + w * 0.72, y + h * 0.95),
        QPointF(x + w * 0.5, y + h),
    )
    path.cubicTo(
        QPointF(x + w * 0.28, y + h * 0.95),
        QPointF(x + w * 0.06, y + h * 0.80),
        QPointF(x + w * 0.06, y + h * 0.52),
    )
    path.lineTo(x + w * 0.06, y + h * 0.18)
    path.closeSubpath()
    return path


def app_icon(palette: Palette, size: int = 256) -> QIcon:
    """The application / window icon: a shield over a document."""
    icon = QIcon()
    for dimension in (16, 24, 32, 48, 64, 128, size):
        icon.addPixmap(_render_app(dimension, palette))
    return icon


def _render_app(size: int, palette: Palette) -> QPixmap:
    pixmap = _pixmap(size)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    margin = size * 0.08
    rect = QRectF(margin, margin, size - margin * 2, size - margin * 2)

    path = _shield_path(rect)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(QColor(palette.accent)))
    painter.drawPath(path)

    # A checkmark, but only when there is room for it to read clearly.
    if size >= 24:
        pen = QPen(QColor("#ffffff"))
        pen.setWidthF(max(1.6, size * 0.09))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        check = QPainterPath()
        check.moveTo(size * 0.34, size * 0.50)
        check.lineTo(size * 0.45, size * 0.62)
        check.lineTo(size * 0.68, size * 0.38)
        painter.drawPath(check)

    painter.end()
    return pixmap


def tray_icon(palette: Palette, *, alert: bool = False, busy: bool = False) -> QIcon:
    """Tray icon, optionally badged for a malicious finding or active work."""
    size = 64
    pixmap = _pixmap(size)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    colour = palette.bad if alert else (palette.warn if busy else palette.accent)
    margin = size * 0.1
    rect = QRectF(margin, margin, size - margin * 2, size - margin * 2)

    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(QColor(colour)))
    painter.drawPath(_shield_path(rect))

    if alert:
        painter.setPen(QPen(QColor("#ffffff"), size * 0.10, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawLine(QPointF(size * 0.5, size * 0.30), QPointF(size * 0.5, size * 0.58))
        painter.drawPoint(QPointF(size * 0.5, size * 0.72))

    painter.end()
    return QIcon(pixmap)


def verdict_dot(verdict: Verdict, palette: Palette, size: int = 12) -> QIcon:
    """A small filled circle in the verdict's colour, for table rows."""
    pixmap = _pixmap(size + 4)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(QColor(verdict_color(verdict, palette))))
    painter.drawEllipse(QRectF(2, 2, size, size))
    painter.end()
    return QIcon(pixmap)


def glyph_icon(character: str, palette: Palette, size: int = 20) -> QIcon:
    """Render a single character as a toolbar icon."""
    pixmap = _pixmap(size)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor(palette.text)))

    font = QFont()
    font.setPixelSize(int(size * 0.82))
    painter.setFont(font)
    painter.drawText(QRectF(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, character)
    painter.end()
    return QIcon(pixmap)


#: Toolbar glyphs, kept together so they are easy to swap for a real icon set.
GLYPHS = {
    "scan_files": "＋",
    "scan_folder": "🗀",
    "rescan": "↻",
    "delete": "🗑",
    "settings": "⚙",
    "update": "⭳",
    "about": "?",
    "open_folder": "↗",
}
