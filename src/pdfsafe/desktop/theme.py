"""Colour palette and stylesheet."""

from __future__ import annotations

from dataclasses import dataclass

from pdfsafe.enums import Severity, Verdict


@dataclass(frozen=True, slots=True)
class Palette:
    background: str
    surface: str
    surface_alt: str
    border: str
    text: str
    muted: str
    accent: str
    ok: str
    low: str
    warn: str
    bad: str


DARK = Palette(
    background="#0f1115",
    surface="#171a21",
    surface_alt="#1d212a",
    border="#262b36",
    text="#e6e8ec",
    muted="#8b93a3",
    accent="#5b8cff",
    ok="#3ecf8e",
    low="#8bc34a",
    warn="#f5a623",
    bad="#ff5d5d",
)

LIGHT = Palette(
    background="#f6f7f9",
    surface="#ffffff",
    surface_alt="#eef1f5",
    border="#dfe3ea",
    text="#171a21",
    muted="#667085",
    accent="#2f6fed",
    ok="#12855c",
    low="#5c8a1f",
    warn="#b26a00",
    bad="#c92a2a",
)


def palette_for(theme: str) -> Palette:
    if theme == "light":
        return LIGHT
    if theme == "dark":
        return DARK
    return DARK if _system_prefers_dark() else LIGHT


def _system_prefers_dark() -> bool:
    """Read the Windows apps-theme preference; default to dark elsewhere."""
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        )
        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return int(value) == 0
    except Exception:
        return True


def verdict_color(verdict: Verdict, palette: Palette) -> str:
    return {
        Verdict.CLEAN: palette.ok,
        Verdict.LOW_RISK: palette.low,
        Verdict.SUSPICIOUS: palette.warn,
        Verdict.MALICIOUS: palette.bad,
        Verdict.UNKNOWN: palette.muted,
    }.get(verdict, palette.muted)


def severity_color(severity: Severity, palette: Palette) -> str:
    return {
        Severity.CRITICAL: palette.bad,
        Severity.HIGH: "#ff8a5d",
        Severity.MEDIUM: palette.warn,
        Severity.LOW: palette.low,
        Severity.INFO: palette.muted,
    }.get(severity, palette.muted)


def stylesheet(palette: Palette) -> str:
    """Qt stylesheet for the whole application."""
    p = palette
    return f"""
QWidget {{
    background: {p.background};
    color: {p.text};
    font-family: "Segoe UI", -apple-system, Roboto, sans-serif;
    font-size: 13px;
}}

QMainWindow, QDialog {{ background: {p.background}; }}

QToolBar {{
    background: {p.surface};
    border: 0;
    border-bottom: 1px solid {p.border};
    padding: 6px 8px;
    spacing: 6px;
}}
QToolButton {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 6px 12px;
    color: {p.text};
}}
QToolButton:hover {{ background: {p.surface_alt}; border-color: {p.border}; }}
QToolButton:pressed {{ background: {p.border}; }}
QToolButton:disabled {{ color: {p.muted}; }}

QPushButton {{
    background: {p.accent};
    color: #ffffff;
    border: 0;
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: 600;
}}
QPushButton:hover {{ background: {p.accent}; }}
QPushButton:disabled {{ background: {p.surface_alt}; color: {p.muted}; }}
QPushButton[flat="true"], QPushButton#secondary {{
    background: {p.surface_alt};
    color: {p.text};
    border: 1px solid {p.border};
}}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit, QListWidget {{
    background: {p.surface_alt};
    border: 1px solid {p.border};
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: {p.accent};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {p.accent}; }}
QComboBox::drop-down {{ border: 0; width: 18px; }}
QComboBox QAbstractItemView {{
    background: {p.surface};
    border: 1px solid {p.border};
    selection-background-color: {p.accent};
}}

QTableView {{
    background: {p.surface};
    alternate-background-color: {p.surface_alt};
    border: 1px solid {p.border};
    border-radius: 8px;
    gridline-color: transparent;
    selection-background-color: {p.accent};
    selection-color: #ffffff;
}}
QHeaderView::section {{
    background: {p.surface};
    color: {p.muted};
    border: 0;
    border-bottom: 1px solid {p.border};
    padding: 8px 10px;
    font-weight: 500;
}}
QTableView::item {{ padding: 6px 10px; border: 0; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {p.muted}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {p.border}; border-radius: 5px; min-width: 30px; }}

QGroupBox {{
    border: 1px solid {p.border};
    border-radius: 8px;
    margin-top: 14px;
    padding: 12px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: {p.muted};
}}

QTabWidget::pane {{ border: 1px solid {p.border}; border-radius: 8px; top: -1px; }}
QTabBar::tab {{
    background: transparent;
    color: {p.muted};
    padding: 8px 16px;
    border: 0;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{ color: {p.text}; border-bottom-color: {p.accent}; }}

QStatusBar {{ background: {p.surface}; border-top: 1px solid {p.border}; color: {p.muted}; }}
QStatusBar::item {{ border: 0; }}

QProgressBar {{
    background: {p.surface_alt};
    border: 0;
    border-radius: 4px;
    height: 6px;
    text-align: center;
}}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 4px; }}

QCheckBox, QRadioButton {{ spacing: 8px; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {p.border};
    border-radius: 4px;
    background: {p.surface_alt};
}}
QCheckBox::indicator:checked {{ background: {p.accent}; border-color: {p.accent}; }}
QRadioButton::indicator {{ border-radius: 8px; }}

QSplitter::handle {{ background: {p.border}; width: 1px; }}
QToolTip {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border};
    padding: 6px;
}}
QMenu {{ background: {p.surface}; border: 1px solid {p.border}; padding: 4px; }}
QMenu::item {{ padding: 6px 24px 6px 12px; border-radius: 4px; }}
QMenu::item:selected {{ background: {p.surface_alt}; }}
QMenu::separator {{ height: 1px; background: {p.border}; margin: 4px 8px; }}

#DropZone {{
    background: {p.surface};
    border: 2px dashed {p.border};
    border-radius: 12px;
    color: {p.muted};
}}
#DropZone[active="true"] {{ border-color: {p.accent}; background: {p.surface_alt}; }}

#VerdictBanner {{ border-radius: 10px; padding: 14px; }}
#Mono {{ font-family: "Cascadia Mono", Consolas, monospace; font-size: 12px; }}
#Muted {{ color: {p.muted}; }}
#Heading {{ font-size: 15px; font-weight: 600; }}
"""
