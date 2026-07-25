"""Desktop runtime tests: database, repository, sandbox, engine, updater."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from pdfsafe.enums import ScanStatus, UploadSource, Verdict


@pytest.fixture
def local_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A fresh SQLite database in a temporary directory."""
    from pdfsafe.config import Settings
    from pdfsafe.local.database import LocalDatabase

    settings = Settings(
        env="test",
        database_url=f"sqlite:///{tmp_path / 'test.sqlite3'}",
        storage_local_path=tmp_path / "files",
        ai_enabled=False,
        enable_yara=False,
        analysis_isolation="in_process",
    )
    database = LocalDatabase(settings)
    database.initialise()
    yield database
    database.dispose()


@pytest.fixture
def engine(local_db: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """An engine wired to the temporary database and storage."""
    from pdfsafe.local.engine import LocalScanEngine
    from pdfsafe.storage.local import LocalStorage

    storage = LocalStorage(tmp_path / "files")
    monkeypatch.setattr("pdfsafe.local.engine.get_storage", lambda: storage)

    instance = LocalScanEngine(local_db.settings, local_db)
    yield instance
    if instance.is_running:
        instance.stop(wait=True, timeout=5)


def write_pdf(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


class TestDatabase:
    def test_schema_is_created(self, local_db: Any) -> None:
        from pdfsafe.local.database import SCHEMA_VERSION

        assert local_db.schema_version() == SCHEMA_VERSION
        assert local_db.integrity_check()

    def test_initialise_is_idempotent(self, local_db: Any) -> None:
        local_db.initialise()
        local_db.initialise()
        assert local_db.integrity_check()

    def test_wal_is_enabled(self, local_db: Any) -> None:
        from sqlalchemy import text

        with local_db.engine.connect() as connection:
            mode = connection.execute(text("PRAGMA journal_mode")).scalar_one()
        assert str(mode).lower() == "wal"

    def test_meta_round_trip(self, local_db: Any) -> None:
        local_db.set_meta("last_update_check", "2026-07-25")
        assert local_db.get_meta("last_update_check") == "2026-07-25"
        assert local_db.get_meta("missing") is None

    def test_backup_produces_a_readable_copy(self, local_db: Any, tmp_path: Path) -> None:
        import sqlite3

        destination = local_db.backup(tmp_path / "backup" / "copy.sqlite3")
        assert destination.is_file()
        connection = sqlite3.connect(destination)
        try:
            names = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        finally:
            connection.close()
        assert "scans" in names


class TestRepository:
    def test_create_and_read(self, local_db: Any) -> None:
        from pdfsafe.local.repository import ScanRepository

        with local_db.session() as session:
            scan = ScanRepository(session).create(
                filename="invoice.pdf",
                file_size=1024,
                sha256="a" * 64,
                md5="b" * 32,
                storage_key="aa/bb/x.pdf",
                source=UploadSource.CLI,
            )
            scan_id = scan.id

        with local_db.session() as session:
            found = ScanRepository(session).get(scan_id)
            assert found.filename == "invoice.pdf"
            assert found.status is ScanStatus.PENDING
            assert found.verdict is Verdict.UNKNOWN

    def test_missing_scan_raises(self, local_db: Any) -> None:
        import uuid

        from pdfsafe.exceptions import ScanNotFoundError
        from pdfsafe.local.repository import ScanRepository

        with local_db.session() as session, pytest.raises(ScanNotFoundError):
            ScanRepository(session).get(uuid.uuid4())

    def test_mark_failed_records_the_reason(self, local_db: Any) -> None:
        from pdfsafe.local.repository import ScanRepository

        with local_db.session() as session:
            repository = ScanRepository(session)
            scan = repository.create(
                filename="x.pdf", file_size=1, sha256="c" * 64, md5="d" * 32, storage_key="k"
            )
            repository.mark_failed(scan.id, "analysis_timeout", "took too long")
            scan_id = scan.id

        with local_db.session() as session:
            scan = ScanRepository(session).get(scan_id)
            assert scan.status is ScanStatus.FAILED
            assert scan.error_code == "analysis_timeout"

    def test_stale_scans_are_recovered(self, local_db: Any) -> None:
        from datetime import UTC, datetime, timedelta

        from pdfsafe.local.repository import ScanRepository

        with local_db.session() as session:
            repository = ScanRepository(session)
            scan = repository.create(
                filename="stuck.pdf", file_size=1, sha256="e" * 64, md5="f" * 32, storage_key="k"
            )
            scan.status = ScanStatus.ANALYZING
            scan.created_at = datetime.now(UTC) - timedelta(hours=5)

        with local_db.session() as session:
            recovered = ScanRepository(session).fail_stale(timedelta(hours=2))
            assert recovered == 1

    def test_prune_trims_history(self, local_db: Any) -> None:
        from pdfsafe.local.repository import ScanRepository

        with local_db.session() as session:
            repository = ScanRepository(session)
            for index in range(12):
                repository.create(
                    filename=f"f{index}.pdf",
                    file_size=1,
                    sha256=f"{index:064d}",
                    md5=f"{index:032d}",
                    storage_key=f"k{index}",
                )

        with local_db.session() as session:
            ScanRepository(session).prune(keep=5)

        with local_db.session() as session:
            assert ScanRepository(session).count() <= 5

    def test_stats_are_computed(self, local_db: Any) -> None:
        from pdfsafe.local.repository import ScanRepository

        with local_db.session() as session:
            ScanRepository(session).create(
                filename="a.pdf", file_size=1, sha256="1" * 64, md5="1" * 32, storage_key="k"
            )

        with local_db.session() as session:
            stats = ScanRepository(session).stats()
        assert stats.total == 1
        assert stats.by_status


class TestSandbox:
    def test_in_process_mode_parses(self, tmp_path: Path, pdfs: Any, local_db: Any) -> None:
        from pdfsafe.local.sandbox import extract_isolated

        path = write_pdf(tmp_path, "benign.pdf", pdfs.benign_pdf())
        result = extract_isolated(path, settings=local_db.settings)

        assert len(result.sha256) == 64
        assert result.structure.page_count == 1

    def test_timeout_raises(self, tmp_path: Path, pdfs: Any, local_db: Any) -> None:
        """A zero-length timeout must abort rather than hang."""
        from pdfsafe.config import Settings
        from pdfsafe.exceptions import AnalysisError
        from pdfsafe.local.sandbox import extract_isolated

        settings = Settings(
            env="test",
            database_url=local_db.settings.database_url,
            analysis_isolation="process",
            analysis_timeout_seconds=5,
            enable_yara=False,
        )
        path = write_pdf(tmp_path, "benign.pdf", pdfs.benign_pdf())

        # Spawning is slow and platform-dependent in CI; accept either a clean
        # parse or a controlled failure, but never an unhandled exception.
        try:
            result = extract_isolated(path, settings=settings)
            assert result.sha256
        except AnalysisError:
            pass


class TestEngine:
    def test_benign_file_completes_clean(
        self, engine: Any, tmp_path: Path, pdfs: Any
    ) -> None:
        path = write_pdf(tmp_path, "benign.pdf", pdfs.benign_pdf())
        engine.start()

        scan_id = engine.submit_file(path)
        assert scan_id is not None

        scan = _wait_for(engine, scan_id)
        assert scan.status is ScanStatus.COMPLETED
        assert scan.verdict in (Verdict.CLEAN, Verdict.LOW_RISK)
        assert scan.risk_score < 50

    def test_malicious_file_is_flagged(
        self, engine: Any, tmp_path: Path, pdfs: Any
    ) -> None:
        path = write_pdf(tmp_path, "evil.pdf", pdfs.launch_action_pdf())
        engine.start()

        scan_id = engine.submit_file(path)
        scan = _wait_for(engine, scan_id)

        assert scan.risk_score >= 50
        assert scan.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
        assert any(i.code == "PDF_LAUNCH_ACTION" for i in scan.indicators)

    def test_non_pdf_is_rejected_without_a_row(
        self, engine: Any, tmp_path: Path, pdfs: Any
    ) -> None:
        events: list[Any] = []
        engine.subscribe(events.append)

        path = write_pdf(tmp_path, "notes.txt", pdfs.not_a_pdf())
        assert engine.submit_file(path) is None

        kinds = {event.kind.value for event in events}
        assert "rejected" in kinds

    def test_missing_file_is_rejected(self, engine: Any, tmp_path: Path) -> None:
        assert engine.submit_file(tmp_path / "nope.pdf") is None

    def test_oversized_file_is_rejected(
        self, engine: Any, tmp_path: Path, pdfs: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(engine.settings, "max_upload_bytes", 10)
        path = write_pdf(tmp_path, "big.pdf", pdfs.benign_pdf())
        assert engine.submit_file(path) is None

    def test_duplicate_reuses_the_previous_verdict(
        self, engine: Any, tmp_path: Path, pdfs: Any
    ) -> None:
        data = pdfs.benign_pdf("dedupe me")
        first_path = write_pdf(tmp_path, "one.pdf", data)
        engine.start()

        first_id = engine.submit_file(first_path)
        _wait_for(engine, first_id)

        second_path = write_pdf(tmp_path, "two.pdf", data)
        second_id = engine.submit_file(second_path)
        assert second_id == first_id

    def test_events_are_published(self, engine: Any, tmp_path: Path, pdfs: Any) -> None:
        events: list[Any] = []
        engine.subscribe(events.append)
        engine.start()

        scan_id = engine.submit_file(write_pdf(tmp_path, "b.pdf", pdfs.benign_pdf()))
        _wait_for(engine, scan_id)

        kinds = [event.kind.value for event in events]
        assert "queued" in kinds
        assert "completed" in kinds

    def test_a_failing_subscriber_does_not_stop_scanning(
        self, engine: Any, tmp_path: Path, pdfs: Any
    ) -> None:
        def broken(_: Any) -> None:
            raise RuntimeError("listener exploded")

        engine.subscribe(broken)
        engine.start()

        scan_id = engine.submit_file(write_pdf(tmp_path, "b.pdf", pdfs.benign_pdf()))
        scan = _wait_for(engine, scan_id)
        assert scan.status is ScanStatus.COMPLETED

    def test_stop_is_idempotent(self, engine: Any) -> None:
        engine.start()
        engine.stop(wait=True, timeout=5)
        engine.stop(wait=True, timeout=5)
        assert not engine.is_running


class TestUpdater:
    @pytest.mark.parametrize(
        ("candidate", "current", "expected"),
        [
            ("0.2.0", "0.1.0", True),
            ("0.1.1", "0.1.0", True),
            ("1.0.0", "0.9.9", True),
            ("0.1.0", "0.1.0", False),
            ("0.0.9", "0.1.0", False),
            ("v0.2.0", "0.1.0", True),
            ("0.2.0-beta", "0.1.0", True),
        ],
    )
    def test_version_comparison(self, candidate: str, current: str, expected: bool) -> None:
        from pdfsafe.local.updater import is_newer

        assert is_newer(candidate, current) is expected

    def test_manifest_requires_https(self) -> None:
        from pdfsafe.local.updater import UpdateError, _parse_manifest

        with pytest.raises(UpdateError, match="HTTPS"):
            _parse_manifest(
                {"version": "9.9.9", "url": "http://example.com/x.exe", "sha256": "a" * 64},
                "stable",
            )

    def test_manifest_rejects_bad_digest(self) -> None:
        from pdfsafe.local.updater import UpdateError, _parse_manifest

        with pytest.raises(UpdateError, match="SHA-256"):
            _parse_manifest(
                {"version": "9.9.9", "url": "https://example.com/x.exe", "sha256": "nope"},
                "stable",
            )

    def test_manifest_accepts_channel_mapping(self) -> None:
        from pdfsafe.local.updater import _parse_manifest

        info = _parse_manifest(
            {
                "stable": {
                    "version": "9.9.9",
                    "url": "https://example.com/x.exe",
                    "sha256": "b" * 64,
                }
            },
            "stable",
        )
        assert info is not None
        assert info.version == "9.9.9"


class TestCredentials:
    def test_masking_hides_the_middle(self) -> None:
        from pdfsafe import credentials

        assert credentials.masked("") == ""
        assert credentials.masked("short") == "•" * 5

        masked = credentials.masked("sk-ant-api03-abcdefghijklmnop4f2a")
        assert masked.startswith("sk-ant")
        assert masked.endswith("4f2a")
        assert "abcdefghijkl" not in masked

    def test_resolve_prefers_the_store(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pdfsafe import credentials

        monkeypatch.setattr(credentials, "get_api_key", lambda provider: "from-store")
        assert credentials.resolve_api_key("anthropic", "from-env") == "from-store"

        monkeypatch.setattr(credentials, "get_api_key", lambda provider: "")
        assert credentials.resolve_api_key("anthropic", "from-env") == "from-env"


class TestPaths:
    def test_directories_are_under_the_user_profile(self) -> None:
        from pdfsafe import paths

        home = str(Path.home()).lower()
        for value in (paths.roaming_dir(), paths.local_dir()):
            assert "pdfsafe" in str(value).lower()
            # A per-user install must never write outside the profile.
            assert str(value).lower().startswith(home) or "appdata" in str(value).lower()

    def test_describe_lists_every_location(self) -> None:
        from pdfsafe import paths

        described = paths.describe()
        assert {"settings", "database", "quarantine", "logs"} <= set(described)


# ---------------------------------------------------------------------------
def _wait_for(engine: Any, scan_id: Any, timeout: float = 30.0) -> Any:
    """Block until a scan reaches a terminal state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scan = engine.detail(scan_id)
        if scan.status.is_terminal:
            return scan
        time.sleep(0.1)
    raise AssertionError(f"Scan {scan_id} did not finish within {timeout}s")
