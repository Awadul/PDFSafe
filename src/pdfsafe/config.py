"""Application configuration.

Settings are resolved from four sources, highest priority first:

1. explicit keyword arguments (tests)
2. environment variables prefixed ``PDFSAFE_``
3. the user's ``config.json`` (written by the desktop settings dialog)
4. a ``.env`` file, then the declared defaults

The defaults are chosen so that a freshly installed desktop build runs with no
configuration at all: SQLite under ``%LOCALAPPDATA%``, local file storage, AI
disabled until the user supplies their own key.
"""

from __future__ import annotations

import json
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from pdfsafe import paths


class Environment(StrEnum):
    DESKTOP = "desktop"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"


class StorageBackend(StrEnum):
    LOCAL = "local"
    S3 = "s3"


class AIProviderName(StrEnum):
    ANTHROPIC = "anthropic"
    CUSTOM = "custom"
    NULL = "null"


class Isolation(StrEnum):
    """How hostile files are parsed."""

    PROCESS = "process"
    IN_PROCESS = "in_process"


CommaList = Annotated[list[str] | str, Field(default_factory=list)]


class JsonConfigSource(PydanticBaseSettingsSource):
    """Reads the user's ``config.json``. Missing or corrupt files are ignored."""

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        path = paths.config_file()
        try:
            if not path.is_file():
                return {}
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        # Accept both "ai_enabled" and "PDFSAFE_AI_ENABLED" spellings.
        return {
            str(key).lower().removeprefix("pdfsafe_"): value
            for key, value in data.items()
            if not str(key).startswith("_")
        }


class Settings(BaseSettings):
    """Typed application settings."""

    model_config = SettingsConfigDict(
        env_prefix="PDFSAFE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------------------------------------------------------------- app ---
    env: Environment = Environment.DESKTOP
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_json: bool = False
    log_retention_days: int = 14
    secret_key: SecretStr = SecretStr("insecure-development-secret-key")
    app_name: str = "PDFSafe"

    # ------------------------------------------------------------ desktop ---
    start_minimized: bool = False
    close_to_tray: bool = True
    autostart: bool = False
    notify_on_verdict: bool = True
    notify_min_verdict: Literal["suspicious", "malicious"] = "suspicious"
    theme: Literal["dark", "light", "system"] = "system"
    history_limit: int = 5000

    # ---------------------------------------------------------- ingestion ---
    max_upload_bytes: int = 100 * 1024 * 1024
    allowed_content_types: CommaList = Field(
        default_factory=lambda: ["application/pdf", "application/x-pdf", "application/octet-stream"]
    )
    watch_enabled: bool = False
    watch_folders: CommaList = Field(default_factory=list)
    watch_poll_seconds: int = 15
    watch_recursive: bool = False

    # ----------------------------------------------------------- analysis ---
    analysis_workers: int = 2
    analysis_timeout_seconds: int = 60
    analysis_isolation: Isolation = Isolation.PROCESS
    enable_yara: bool = True
    yara_rules_dir: Path | None = None
    extract_max_objects: int = 20_000
    extract_max_js_chars: int = 200_000
    extract_max_urls: int = 500
    keep_scanned_copies: bool = True
    quarantine_enabled: bool = True

    # ----------------------------------------------------------------- ai ---
    ai_enabled: bool = False
    ai_provider: AIProviderName = AIProviderName.ANTHROPIC
    ai_escalate_min_score: int = 25
    ai_escalate_max_score: int = 85
    ai_always_escalate: bool = False
    ai_max_evidence_chars: int = 24_000
    ai_timeout_seconds: int = 60
    ai_max_retries: int = 3
    ai_daily_token_budget: int = 0
    ai_share_text_excerpt: bool = True

    anthropic_api_key: SecretStr = SecretStr("")
    anthropic_model: str = "claude-sonnet-5"
    anthropic_max_tokens: int = 2048

    custom_ai_base_url: str = ""
    custom_ai_api_key: SecretStr = SecretStr("")
    custom_ai_model: str = ""
    custom_ai_max_tokens: int = 2048

    # ------------------------------------------------------------ updates ---
    update_check_enabled: bool = True
    update_check_interval_hours: int = 24
    update_feed_url: str = "https://updates.pdfsafe.app/desktop/latest.json"
    update_channel: Literal["stable", "beta"] = "stable"

    # ------------------------------------------------------------ storage ---
    storage_backend: StorageBackend = StorageBackend.LOCAL
    storage_local_path: Path = Field(default_factory=paths.storage_dir)
    s3_bucket: str = ""
    s3_endpoint_url: str = ""
    s3_region: str = "us-east-1"
    s3_access_key_id: SecretStr = SecretStr("")
    s3_secret_access_key: SecretStr = SecretStr("")

    # ----------------------------------------------------------- database ---
    database_url: str = ""
    database_echo: bool = False
    database_pool_size: int = 5
    database_max_overflow: int = 10

    # ---------------------------------------------- server target (opt-in) ---
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_keys: CommaList = Field(default_factory=list)
    cors_origins: CommaList = Field(default_factory=list)
    rate_limit_per_minute: int = 60
    docs_enabled: bool = True
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    celery_task_time_limit: int = 300
    celery_task_soft_time_limit: int = 270
    watch_dir: Path = Field(default_factory=paths.watch_default_dir)
    metrics_enabled: bool = False
    metrics_path: str = "/metrics"

    # ------------------------------------------------------- validators ----
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            JsonConfigSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )

    @field_validator(
        "api_keys", "cors_origins", "allowed_content_types", "watch_folders", mode="before"
    )
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("yara_rules_dir", mode="before")
    @classmethod
    def _empty_path_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("analysis_workers")
    @classmethod
    def _sane_worker_count(cls, value: int) -> int:
        return max(1, min(value, 8))

    @model_validator(mode="after")
    def _validate_consistency(self) -> Settings:
        if not self.database_url:
            self.database_url = f"sqlite:///{paths.database_file()}"

        if self.ai_escalate_min_score > self.ai_escalate_max_score:
            raise ValueError("ai_escalate_min_score must be <= ai_escalate_max_score")

        if self.storage_backend is StorageBackend.S3 and not self.s3_bucket:
            raise ValueError("s3_bucket is required when storage_backend='s3'")

        if (
            self.ai_enabled
            and self.ai_provider is AIProviderName.CUSTOM
            and (not self.custom_ai_base_url or not self.custom_ai_model)
        ):
            raise ValueError(
                "custom_ai_base_url and custom_ai_model are required for the custom provider"
            )

        if self.is_server_deployment:
            if self.secret_key.get_secret_value() == "insecure-development-secret-key":
                raise ValueError("PDFSAFE_SECRET_KEY must be set for a production server")
            if not self.api_keys:
                raise ValueError("PDFSAFE_API_KEYS must be set for a production server")

        return self

    # ------------------------------------------------------- convenience ----
    @property
    def is_desktop(self) -> bool:
        return self.env is Environment.DESKTOP

    @property
    def is_server_deployment(self) -> bool:
        return self.env is Environment.PRODUCTION

    @property
    def is_testing(self) -> bool:
        return self.env is Environment.TEST

    @property
    def uses_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def sync_database_url(self) -> str:
        """Synchronous driver URL (desktop, Celery workers, Alembic)."""
        if self.uses_sqlite:
            return self.database_url.replace("+aiosqlite", "")
        return self.database_url.replace("+asyncpg", "+psycopg").replace(
            "postgresql://", "postgresql+psycopg://"
        )

    @property
    def auth_required(self) -> bool:
        return bool(self.api_keys)

    # ------------------------------------------------------------ writing ---
    #: Fields the settings dialog is allowed to persist to config.json.
    USER_EDITABLE: ClassVar[tuple[str, ...]] = (
        "ai_enabled",
        "ai_provider",
        "ai_escalate_min_score",
        "ai_escalate_max_score",
        "ai_always_escalate",
        "ai_share_text_excerpt",
        "anthropic_model",
        "custom_ai_base_url",
        "custom_ai_model",
        "analysis_workers",
        "analysis_timeout_seconds",
        "analysis_isolation",
        "enable_yara",
        "keep_scanned_copies",
        "quarantine_enabled",
        "watch_enabled",
        "watch_folders",
        "watch_recursive",
        "start_minimized",
        "close_to_tray",
        "autostart",
        "notify_on_verdict",
        "notify_min_verdict",
        "theme",
        "history_limit",
        "log_level",
        "update_check_enabled",
        "update_channel",
        "max_upload_bytes",
    )

    def user_values(self) -> dict[str, Any]:
        """Current values of the user-editable fields, JSON-ready."""
        dumped = self.model_dump(mode="json", include=set(self.USER_EDITABLE))
        return dict(sorted(dumped.items()))


def save_user_settings(values: dict[str, Any]) -> Path:
    """Merge ``values`` into ``config.json`` and reload the cached settings.

    Secrets are never written here - API keys live in the OS credential store.
    """
    path = paths.config_file()
    current: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                current = loaded
        except (OSError, ValueError):
            current = {}

    allowed = set(Settings.USER_EDITABLE)
    current.update({k: v for k, v in values.items() if k in allowed})
    current["_comment"] = "Written by PDFSafe. Secrets are stored in the OS credential manager."

    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)

    reload_settings()
    return path


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings.

    Always call this rather than instantiating :class:`Settings` directly - the
    cache is what lets the settings dialog and the tests swap configuration.
    """
    return Settings()


def reload_settings() -> Settings:
    """Drop the cache and re-read every source."""
    get_settings.cache_clear()
    return get_settings()
