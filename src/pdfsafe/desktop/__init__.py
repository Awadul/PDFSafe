"""PySide6 desktop application.

Layering: this package may import from :mod:`pdfsafe.local`, but nothing
outside it may import Qt. That keeps the engine testable headlessly and keeps
the CLI free of a GUI dependency.
"""

__all__ = ["main"]


def main() -> int:
    """Entry point for the ``pdfsafe-desktop`` script and the frozen build."""
    from pdfsafe.desktop.app import main as _main

    return _main()
