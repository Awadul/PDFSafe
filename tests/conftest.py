"""Shared pytest fixtures.

The suite must never touch the developer's real profile: PDFSafe reads
``%APPDATA%\\PDFSafe\\config.json`` at import time, so those environment
variables are redirected to a temporary directory *before* anything from
``pdfsafe`` is imported. Nothing at module scope here may import the package.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Isolate the user profile before pdfsafe.paths is imported and cached.
# ---------------------------------------------------------------------------
_PROFILE = Path(tempfile.mkdtemp(prefix="pdfsafe-tests-"))
os.environ["APPDATA"] = str(_PROFILE / "Roaming")
os.environ["LOCALAPPDATA"] = str(_PROFILE / "Local")
os.environ["XDG_CONFIG_HOME"] = str(_PROFILE / "config")
os.environ["XDG_DATA_HOME"] = str(_PROFILE / "data")

os.environ.setdefault("PDFSAFE_ENV", "test")
os.environ.setdefault("PDFSAFE_AI_ENABLED", "false")
os.environ.setdefault("PDFSAFE_ENABLE_YARA", "false")
os.environ.setdefault("PDFSAFE_LOG_JSON", "false")
os.environ.setdefault("PDFSAFE_LOG_LEVEL", "WARNING")
os.environ.setdefault("PDFSAFE_SECRET_KEY", "test-secret")
os.environ.setdefault("PDFSAFE_RATE_LIMIT_PER_MINUTE", "0")
os.environ.setdefault("PDFSAFE_UPDATE_CHECK_ENABLED", "false")
os.environ.setdefault("PDFSAFE_ANALYSIS_ISOLATION", "in_process")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip GUI tests when Qt is not installed.

    The engine and analysis suites run without PySide6, which keeps the fast
    feedback loop free of a 77 MB dependency.
    """
    try:
        import PySide6  # noqa: F401

        has_qt = True
    except ImportError:
        has_qt = False

    if has_qt:
        return

    skip_qt = pytest.mark.skip(reason="PySide6 not installed (pip install '.[desktop]')")
    for item in items:
        if "gui" in item.keywords:
            item.add_marker(skip_qt)


@pytest.fixture(scope="session", autouse=True)
def _session_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Point storage and the database at a temporary location."""
    root = tmp_path_factory.mktemp("pdfsafe")
    os.environ["PDFSAFE_STORAGE_LOCAL_PATH"] = str(root / "uploads")
    os.environ["PDFSAFE_DATABASE_URL"] = f"sqlite:///{root / 'pdfsafe.db'}"
    os.environ["PDFSAFE_WATCH_DIR"] = str(root / "watch")
    yield


@pytest.fixture
def settings(_session_env: None) -> Any:
    from pdfsafe.config import get_settings

    get_settings.cache_clear()
    return get_settings()


@pytest.fixture
def storage_root(settings: Any) -> Path:
    path = Path(settings.storage_local_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Sample documents
# ---------------------------------------------------------------------------
@pytest.fixture
def pdfs() -> Any:
    from tests.fixtures import pdf_builder

    return pdf_builder


# ---------------------------------------------------------------------------
# AI stubs
# ---------------------------------------------------------------------------
class StubProvider:
    """Deterministic provider used instead of a real LLM."""

    name = "stub"

    def __init__(self, verdict: str = "malicious", risk_score: int = 90) -> None:
        self.model = "stub-model"
        self.calls: list[Any] = []
        self._verdict = verdict
        self._risk_score = risk_score

    def is_configured(self) -> bool:
        return True

    def assess(self, evidence: Any) -> Any:
        from pdfsafe.schemas.ai import AICallResult, AIVerdict

        self.calls.append(evidence)
        return AICallResult(
            verdict=AIVerdict(
                verdict=self._verdict,
                risk_score=self._risk_score,
                confidence=0.9,
                summary="Stub verdict for testing.",
                reasoning="Deterministic stub.",
                recommended_action="quarantine",
            ),
            provider=self.name,
            model=self.model,
            succeeded=True,
            prompt_tokens=1000,
            completion_tokens=200,
            latency_ms=42,
        )


@pytest.fixture
def stub_provider(monkeypatch: pytest.MonkeyPatch) -> StubProvider:
    """Replace the provider registry with a deterministic stub."""
    import sys

    import pdfsafe.ai.triage  # noqa: F401
    from pdfsafe.ai import budget, registry

    triage_mod = sys.modules["pdfsafe.ai.triage"]
    provider = StubProvider()
    monkeypatch.setattr(registry, "get_provider", lambda name=None: provider)
    monkeypatch.setattr(triage_mod, "get_provider", lambda name=None: provider)
    monkeypatch.setattr(budget, "has_budget", lambda: True)
    monkeypatch.setattr(budget, "record_usage", lambda tokens: None)
    return provider


@pytest.fixture
def ai_enabled(monkeypatch: pytest.MonkeyPatch, settings: Any) -> Any:
    """Turn the AI layer on for a single test."""
    monkeypatch.setattr(settings, "ai_enabled", True)
    return settings


@pytest.fixture(scope="session", autouse=True)
def _cleanup_profile() -> Iterator[None]:
    """Remove the temporary profile at the end of the session."""
    yield
    import shutil

    if sys.platform != "win32":  # Windows may still hold SQLite handles
        shutil.rmtree(_PROFILE, ignore_errors=True)
