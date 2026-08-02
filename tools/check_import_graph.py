"""Guard the desktop import graph.

PDFSafe used to ship an optional FastAPI/Celery/PostgreSQL server alongside the
desktop app. That target is gone, and this check keeps it gone: if any of those
libraries reappear in the import graph the PyInstaller bundle would silently
grow by tens of megabytes, and the exclusion list in ``packaging/pdfsafe.spec``
would be quietly wrong.

Run in CI, or by hand:

    python tools/check_import_graph.py
"""

from __future__ import annotations

import importlib
import sys

#: Everything the desktop application must be able to start without.
FORBIDDEN = frozenset(
    {
        "fastapi",
        "starlette",
        "uvicorn",
        "celery",
        "kombu",
        "redis",
        "alembic",
        "asyncpg",
        "psycopg",
        "boto3",
        "botocore",
        "jinja2",
        "aiosqlite",
    }
)

#: Importing these must pull in the whole runtime the shipped app needs.
ENTRY_POINTS = (
    "pdfsafe.cli",
    "pdfsafe.local.engine",
    "pdfsafe.local.database",
    "pdfsafe.local.sandbox",
    "pdfsafe.ai.triage",
    "pdfsafe.analysis.pipeline",
)

#: Qt is desktop-only; the CLI and engine must not drag it in.
QT_MODULES = frozenset({"PySide6", "PySide6.QtWidgets", "PySide6.QtCore"})


def main() -> int:
    for module in ENTRY_POINTS:
        try:
            importlib.import_module(module)
        except ImportError as exc:
            print(f"FAIL: {module} could not be imported: {exc}", file=sys.stderr)
            return 1

    loaded = set(sys.modules)

    leaked = sorted(FORBIDDEN & loaded)
    if leaked:
        print(
            "FAIL: server dependencies leaked into the desktop import graph: " + ", ".join(leaked),
            file=sys.stderr,
        )
        return 1

    qt_leaked = sorted(QT_MODULES & loaded)
    if qt_leaked:
        print(
            "FAIL: Qt was imported by non-desktop code: " + ", ".join(qt_leaked),
            file=sys.stderr,
        )
        print(
            "      Only pdfsafe.desktop.* may import PySide6 - see CONTRIBUTING.md.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {len(ENTRY_POINTS)} entry points import cleanly, no forbidden modules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
