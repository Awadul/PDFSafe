# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build specification for PDFSafe.

Build with:

    pyinstaller packaging/pdfsafe.spec --noconfirm

One-*dir* rather than one-file, deliberately:

* one-file unpacks ~100 MB to %TEMP% on every launch, which is slow and trips
  antivirus heuristics far more often than a normal program directory;
* the parser sandbox spawns child processes, and re-extracting the bundle per
  child would make that unusably slow;
* differential updates are possible when files sit on disk.

The Inno Setup script packages the resulting directory into a single installer,
so the user still downloads exactly one file.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_dynamic_libs, collect_submodules

SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent
SRC = PROJECT_ROOT / "src"

APP_NAME = "PDFSafe"
ENTRY_POINT = str(SRC / "pdfsafe" / "desktop" / "app.py")
ICON = SPEC_DIR / "assets" / "pdfsafe.ico"
VERSION_FILE = SPEC_DIR / "version_info.txt"

# ---------------------------------------------------------------------------
# Data files
# ---------------------------------------------------------------------------
datas = [
    # YARA rules are loaded from pdfsafe/analysis/rules at runtime; the layout
    # must match what paths.resource() expects inside the bundle.
    (str(SRC / "pdfsafe" / "analysis" / "rules"), "pdfsafe/analysis/rules"),
]

# ---------------------------------------------------------------------------
# Binaries: pikepdf and yara-python ship compiled extensions that PyInstaller's
# static analysis does not always find.
# ---------------------------------------------------------------------------
binaries = []
for package in ("pikepdf", "yara"):
    try:
        binaries += collect_dynamic_libs(package)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Hidden imports
# ---------------------------------------------------------------------------
hiddenimports = [
    "pdfsafe.local.sandbox",       # re-imported by spawned parser children
    "pdfsafe.analysis.heuristics",  # rules register via import side effects
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.sql.default_comparator",
    "keyring.backends.Windows",
    "keyring.backends.SecretService",
    "keyring.backends.macOS",
    "anthropic",
    "httpx",
    "pypdf",
]
hiddenimports += collect_submodules("pdfsafe.analysis")

# ---------------------------------------------------------------------------
# Exclusions: the server target's dependencies must never reach the desktop
# build. Without these the bundle roughly doubles in size.
# ---------------------------------------------------------------------------
excludes = [
    # server stack
    "fastapi", "starlette", "uvicorn", "celery", "kombu", "billiard", "amqp",
    "redis", "alembic", "asyncpg", "psycopg", "psycopg2", "boto3", "botocore",
    "jinja2", "aiosqlite",
    # scientific / plotting stacks pulled in transitively
    "numpy", "pandas", "scipy", "matplotlib", "IPython", "notebook",
    # dev tooling
    "pytest", "mypy", "ruff", "setuptools", "pip", "wheel",
    # Qt modules the UI does not use
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtQuick",
    "PySide6.QtQml", "PySide6.Qt3DCore", "PySide6.QtCharts", "PySide6.QtMultimedia",
    "PySide6.QtBluetooth", "PySide6.QtNetworkAuth", "PySide6.QtPositioning",
    "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtDesigner",
    "tkinter", "test", "unittest",
]


a = Analysis(
    [ENTRY_POINT],
    pathex=[str(SRC)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX compression is a reliable way to get flagged as malware
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON) if ICON.exists() else None,
    version=str(VERSION_FILE) if VERSION_FILE.exists() else None,
    uac_admin=False,  # per-user install; never prompt for elevation
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=APP_NAME,
)
