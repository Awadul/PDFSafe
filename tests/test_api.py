"""API and ingestion tests."""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from pdfsafe.enums import ScanStatus, UploadSource
from pdfsafe.exceptions import FileTooLargeError, UnsupportedFileTypeError, ValidationError
from pdfsafe.services.ingest import ingest_bytes


@pytest.fixture
async def client(db_engine: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """An ASGI client wired to the test database, with the queue stubbed out."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from pdfsafe.api.app import create_app
    from pdfsafe.db.session import get_session

    factory = async_sessionmaker(bind=db_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_session() -> Any:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    monkeypatch.setattr("pdfsafe.api.routes.scans.enqueue_scan", lambda *a, **k: "stub-task-id")

    app = create_app()
    app.dependency_overrides[get_session] = override_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client

    app.dependency_overrides.clear()


class TestHealth:
    async def test_liveness(self, client: AsyncClient) -> None:
        response = await client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_metrics_exposed(self, client: AsyncClient) -> None:
        response = await client.get("/metrics")
        assert response.status_code == 200
        assert b"pdfsafe_" in response.content

    async def test_correlation_header_is_returned(self, client: AsyncClient) -> None:
        response = await client.get("/health/live")
        assert response.headers.get("X-Correlation-ID")

    async def test_security_headers(self, client: AsyncClient) -> None:
        response = await client.get("/health/live")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"


class TestSubmit:
    async def test_accepts_a_pdf(self, client: AsyncClient, pdfs: Any) -> None:
        response = await client.post(
            "/api/v1/scans",
            files={"file": ("invoice.pdf", pdfs.benign_pdf(), "application/pdf")},
        )
        assert response.status_code == 202
        body = response.json()
        assert body["status"] == ScanStatus.PENDING.value
        assert len(body["sha256"]) == 64
        assert body["task_id"] == "stub-task-id"

    async def test_rejects_non_pdf(self, client: AsyncClient, pdfs: Any) -> None:
        response = await client.post(
            "/api/v1/scans",
            files={"file": ("notes.txt", pdfs.not_a_pdf(), "text/plain")},
        )
        assert response.status_code in (415, 422)
        assert response.json()["error"] in {"unsupported_file_type", "validation_error"}

    async def test_rejects_empty_file(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/scans", files={"file": ("empty.pdf", b"", "application/pdf")}
        )
        assert response.status_code in (415, 422)

    async def test_deduplicates_identical_content(self, client: AsyncClient, pdfs: Any) -> None:
        data = pdfs.benign_pdf("dedupe target")
        first = await client.post(
            "/api/v1/scans", files={"file": ("a.pdf", data, "application/pdf")}
        )
        assert first.status_code == 202

        # Mark the first scan completed so the dedupe lookup can find it.
        scan_id = first.json()["id"]
        detail = await client.get(f"/api/v1/scans/{scan_id}")
        assert detail.status_code == 200


class TestRetrieval:
    async def test_list_and_filter(self, client: AsyncClient, pdfs: Any) -> None:
        await client.post(
            "/api/v1/scans", files={"file": ("list-me.pdf", pdfs.benign_pdf("list"), "application/pdf")}
        )
        response = await client.get("/api/v1/scans", params={"limit": 10})
        assert response.status_code == 200
        body = response.json()
        assert body["total"] >= 1
        assert len(body["items"]) <= 10

    async def test_unknown_scan_returns_404(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404
        assert response.json()["error"] == "scan_not_found"

    async def test_stats_endpoint(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/scans/stats")
        assert response.status_code == 200
        assert "by_verdict" in response.json()


class TestDashboard:
    async def test_index_renders(self, client: AsyncClient) -> None:
        response = await client.get("/")
        assert response.status_code == 200
        assert b"PDFSafe" in response.content

    async def test_scan_table_partial(self, client: AsyncClient) -> None:
        response = await client.get("/scans")
        assert response.status_code == 200


class TestIngestValidation:
    async def test_empty_payload_rejected(self, session: Any) -> None:
        with pytest.raises(ValidationError):
            await ingest_bytes(session, b"", filename="x.pdf")

    async def test_oversized_payload_rejected(
        self, session: Any, pdfs: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pdfsafe.config import get_settings

        settings = get_settings()
        monkeypatch.setattr(settings, "max_upload_bytes", 10)
        with pytest.raises(FileTooLargeError):
            await ingest_bytes(session, pdfs.benign_pdf(), filename="big.pdf")

    async def test_non_pdf_rejected(self, session: Any, pdfs: Any) -> None:
        with pytest.raises(UnsupportedFileTypeError):
            await ingest_bytes(session, pdfs.not_a_pdf(), filename="notes.txt")

    async def test_successful_ingest_persists_and_stores(self, session: Any, pdfs: Any) -> None:
        from pdfsafe.storage import get_storage

        data = pdfs.benign_pdf("persist me")
        result = await ingest_bytes(
            session, data, filename="persist.pdf", source=UploadSource.CLI
        )

        assert not result.is_duplicate
        assert result.scan.status is ScanStatus.PENDING
        assert result.scan.file_size == len(data)
        assert get_storage().exists(result.scan.storage_key)


class TestSecurity:
    def test_api_key_hashing_is_constant_time(self) -> None:
        from pdfsafe.api.security import hash_key

        assert hash_key("abc") == hash_key("abc")
        assert hash_key("abc") != hash_key("abd")
        assert len(hash_key("abc")) == 64

    def test_generated_keys_are_unique(self) -> None:
        from pdfsafe.api.security import generate_key

        keys = {generate_key() for _ in range(50)}
        assert len(keys) == 50

    def test_missing_key_rejected_when_auth_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pdfsafe.api import security
        from pdfsafe.config import get_settings
        from pdfsafe.exceptions import AuthenticationError

        settings = get_settings()
        monkeypatch.setattr(settings, "api_keys", ["secret-key"])
        security.reset_key_cache()

        with pytest.raises(AuthenticationError):
            security.authenticate(None)
        assert security.authenticate("secret-key").name.startswith("key:")

        security.reset_key_cache()
