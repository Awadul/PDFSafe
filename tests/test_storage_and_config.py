"""Storage backend and configuration tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pdfsafe.exceptions import StorageError
from pdfsafe.storage.local import LocalStorage


class TestLocalStorage:
    def test_round_trip(self, tmp_path: Path) -> None:
        storage = LocalStorage(tmp_path)
        key = storage.build_key("a" * 64, "doc.pdf")
        stored = storage.save(key, b"hello world")

        assert stored.size == 11
        assert storage.exists(key)
        assert storage.load(key) == b"hello world"
        assert storage.local_path(key).is_file()

    def test_key_is_sharded(self, tmp_path: Path) -> None:
        storage = LocalStorage(tmp_path)
        digest = "abcdef" + "0" * 58
        assert storage.build_key(digest, "x.pdf") == f"ab/cd/{digest}.pdf"

    def test_extension_is_normalised(self, tmp_path: Path) -> None:
        storage = LocalStorage(tmp_path)
        assert storage.build_key("a" * 64, "payload.exe").endswith(".pdf")

    def test_path_traversal_is_blocked(self, tmp_path: Path) -> None:
        storage = LocalStorage(tmp_path)
        with pytest.raises(StorageError):
            storage.save("../../escape.pdf", b"nope")

    def test_missing_object_raises(self, tmp_path: Path) -> None:
        storage = LocalStorage(tmp_path)
        with pytest.raises(StorageError):
            storage.load("de/ad/beef.pdf")

    def test_delete_is_idempotent(self, tmp_path: Path) -> None:
        storage = LocalStorage(tmp_path)
        storage.delete("no/such/key.pdf")  # must not raise

    def test_writes_are_atomic(self, tmp_path: Path) -> None:
        """No .part files should survive a successful write."""
        storage = LocalStorage(tmp_path)
        key = storage.build_key("b" * 64, "doc.pdf")
        storage.save(key, b"x" * 1000)
        assert not list(tmp_path.rglob("*.part"))

    def test_quarantine_moves_the_file(self, tmp_path: Path) -> None:
        storage = LocalStorage(tmp_path / "uploads")
        key = storage.build_key("c" * 64, "bad.pdf")
        storage.save(key, b"malicious")

        destination = storage.quarantine(key, tmp_path / "quarantine")
        assert destination.is_file()
        assert not storage.exists(key)


class TestSettings:
    def test_escalation_thresholds_must_be_ordered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pdfsafe.config import Settings

        monkeypatch.setenv("PDFSAFE_AI_ESCALATE_MIN_SCORE", "90")
        monkeypatch.setenv("PDFSAFE_AI_ESCALATE_MAX_SCORE", "10")
        with pytest.raises(ValueError, match="ai_escalate_min_score"):
            Settings()

    def test_a_fresh_install_makes_no_network_connection(self) -> None:
        """The README promises this, so something has to enforce it.

        Both outbound features must be opt-in. Flipping either default to True
        for convenience would quietly turn a scanner that works offline into one
        that phones home on first launch.

        This reads the declared field defaults rather than instantiating
        Settings, because conftest.py forces both variables off for the suite -
        an instantiated Settings would pass this test no matter what the shipped
        default was.
        """
        from pdfsafe.config import Settings

        assert Settings.model_fields["ai_enabled"].default is False
        assert Settings.model_fields["update_check_enabled"].default is False

    def test_update_feed_default_is_https(self) -> None:
        # The updater refuses plaintext at runtime; the shipped default should
        # never be the thing that has to be caught there.
        from pdfsafe.config import Settings

        assert Settings.model_fields["update_feed_url"].default.startswith("https://")


class TestProviderRegistry:
    def test_builtin_providers_are_registered(self) -> None:
        from pdfsafe.ai.registry import available_providers

        assert {"anthropic", "custom", "null"} <= set(available_providers())

    def test_unconfigured_provider_falls_back_to_null(
        self, monkeypatch: pytest.MonkeyPatch, settings: Any
    ) -> None:
        from pydantic import SecretStr

        from pdfsafe import credentials
        from pdfsafe.ai import registry

        registry.reset()
        monkeypatch.setattr(settings, "ai_enabled", True)
        monkeypatch.setattr(settings, "anthropic_api_key", SecretStr(""))
        # The credential store must be stubbed, or a key saved on the
        # developer's own machine would leak into the test result.
        monkeypatch.setattr(credentials, "get_api_key", lambda provider: "")

        provider = registry.get_provider("anthropic")
        assert provider.name == "null"
        registry.reset()

    def test_custom_provider_can_be_registered(self) -> None:
        from pdfsafe.ai import registry
        from pdfsafe.ai.base import NullProvider

        registry.register_provider("my-gateway", NullProvider, override=True)
        assert "my-gateway" in registry.available_providers()


class TestCustomProviderParsing:
    def test_parses_tool_call(self) -> None:
        from pdfsafe.ai.custom_provider import CustomOpenAICompatibleProvider

        payload = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "submit_pdf_verdict",
                                    "arguments": '{"verdict": "clean", "risk_score": 3, '
                                    '"confidence": 0.9, "summary": "fine"}',
                                }
                            }
                        ]
                    }
                }
            ]
        }
        parsed = CustomOpenAICompatibleProvider._extract_payload(payload)
        assert parsed["verdict"] == "clean"

    def test_parses_fenced_json_content(self) -> None:
        from pdfsafe.ai.custom_provider import CustomOpenAICompatibleProvider

        payload = {
            "choices": [
                {
                    "message": {
                        "content": '```json\n{"verdict": "malicious", "risk_score": 91, '
                        '"confidence": 0.8, "summary": "bad"}\n```'
                    }
                }
            ]
        }
        parsed = CustomOpenAICompatibleProvider._extract_payload(payload)
        assert parsed["risk_score"] == 91

    def test_rejects_unusable_response(self) -> None:
        from pdfsafe.ai.custom_provider import CustomOpenAICompatibleProvider
        from pdfsafe.exceptions import AIResponseError

        with pytest.raises(AIResponseError):
            CustomOpenAICompatibleProvider._extract_payload({"choices": [{"message": {}}]})
