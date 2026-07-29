"""Filesystem locations for the installed application.

Everything PDFSafe writes lives under the current user's profile, so the app
installs and runs without administrator rights:

``%APPDATA%\\PDFSafe``          roaming - settings the user would want on a new machine
``%LOCALAPPDATA%\\PDFSafe``     local   - database, quarantine, logs, cached downloads

This module must not import :mod:`pdfsafe.config`; configuration depends on it,
not the other way round.
"""

from __future__ import annotations

import contextlib
import os
import sys
from functools import lru_cache
from pathlib import Path

APP_NAME = "PDFSafe"
APP_AUTHOR = "PDFSafe"


def is_frozen() -> bool:
    """Whether we are running from a PyInstaller bundle."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def bundle_dir() -> Path:
    """Directory containing bundled read-only resources."""
    if is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


def executable_dir() -> Path:
    """Directory containing the running executable (or the source tree in dev)."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def roaming_dir() -> Path:
    """Per-user configuration directory."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return _ensure(Path(base) / APP_NAME)


@lru_cache(maxsize=1)
def local_dir() -> Path:
    """Per-user data directory (not synced by roaming profiles)."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return _ensure(Path(base) / APP_NAME)


def config_file() -> Path:
    """User settings, written by the settings dialog."""
    return roaming_dir() / "config.json"


def database_file() -> Path:
    """SQLite database holding scan history."""
    return _ensure(local_dir() / "data") / "pdfsafe.sqlite3"


def storage_dir() -> Path:
    """Content-addressed copies of scanned files."""
    return _ensure(local_dir() / "files")


def quarantine_dir() -> Path:
    """Isolated storage for files judged malicious."""
    return _ensure(local_dir() / "quarantine")


def log_dir() -> Path:
    """Rotating application logs."""
    return _ensure(local_dir() / "logs")


def cache_dir() -> Path:
    """Downloaded updates and other disposable artefacts."""
    return _ensure(local_dir() / "cache")


def watch_default_dir() -> Path:
    """Sensible default folder to offer for automatic scanning."""
    downloads = Path.home() / "Downloads"
    return downloads if downloads.is_dir() else Path.home()


def resource(*parts: str) -> Path:
    """Resolve a bundled read-only resource.

    Works both from source (``src/pdfsafe/...``) and from a frozen bundle,
    where PyInstaller places data files under ``_MEIPASS/pdfsafe/...``.
    """
    if is_frozen():
        return bundle_dir().joinpath("pdfsafe", *parts)
    return Path(__file__).resolve().parent.joinpath(*parts)


def _ensure(path: Path) -> Path:
    # A read-only or missing profile must not stop the process from starting;
    # the caller finds out when it tries to write.
    with contextlib.suppress(OSError):
        path.mkdir(parents=True, exist_ok=True)
    return path


def describe() -> dict[str, str]:
    """All resolved locations, for the About dialog and bug reports."""
    return {
        "settings": str(config_file()),
        "database": str(database_file()),
        "files": str(storage_dir()),
        "quarantine": str(quarantine_dir()),
        "logs": str(log_dir()),
        "frozen": str(is_frozen()),
    }
