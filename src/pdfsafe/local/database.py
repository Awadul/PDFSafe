"""SQLite persistence for the desktop build.

Alembic is retained for the PostgreSQL server target, but a consumer
application cannot ask the user to run migrations. Instead the schema is
created from the ORM metadata on first launch and a ``pdfsafe_meta`` table
records the schema version, so a future release can upgrade in place.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from pdfsafe.config import Settings, get_settings
from pdfsafe.db import models  # noqa: F401  (importing registers the tables)
from pdfsafe.db.base import Base
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

#: Bump when the ORM schema changes in a way that needs an upgrade step.
SCHEMA_VERSION = 1

_META_TABLE = "pdfsafe_meta"


class LocalDatabase:
    """Owns the SQLite engine, schema lifecycle and session factory."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._engine: Engine | None = None
        self._factory: sessionmaker[Session] | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------- engine --
    @property
    def engine(self) -> Engine:
        if self._engine is None:
            with self._lock:
                if self._engine is None:
                    self._engine = self._create_engine()
        return self._engine

    def _create_engine(self) -> Engine:
        url = self.settings.sync_database_url
        if url.startswith("sqlite"):
            engine = create_engine(
                url,
                echo=self.settings.database_echo,
                future=True,
                poolclass=NullPool,
                connect_args={"check_same_thread": False, "timeout": 30},
            )
            _install_sqlite_pragmas(engine)
        else:  # pragma: no cover - server target
            engine = create_engine(
                url,
                echo=self.settings.database_echo,
                pool_size=self.settings.database_pool_size,
                max_overflow=self.settings.database_max_overflow,
                pool_pre_ping=True,
                future=True,
            )
        return engine

    @property
    def session_factory(self) -> sessionmaker[Session]:
        if self._factory is None:
            self._factory = sessionmaker(bind=self.engine, expire_on_commit=False, autoflush=False)
        return self._factory

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional scope; commits on success, rolls back on error."""
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------- schema --
    def initialise(self) -> None:
        """Create or upgrade the schema. Safe to call on every launch."""
        Base.metadata.create_all(self.engine)
        self._ensure_meta_table()

        current = self.schema_version()
        if current == 0:
            self.set_meta("schema_version", str(SCHEMA_VERSION))
            logger.info("database_created", version=SCHEMA_VERSION, path=self.path)
        elif current < SCHEMA_VERSION:
            self._upgrade(current)
        elif current > SCHEMA_VERSION:
            logger.warning(
                "database_newer_than_app",
                database_version=current,
                app_version=SCHEMA_VERSION,
            )

    def _ensure_meta_table(self) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    f"CREATE TABLE IF NOT EXISTS {_META_TABLE} "
                    "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            )

    def _upgrade(self, from_version: int) -> None:
        """Apply forward-only upgrade steps.

        ``create_all`` already adds new tables, so steps are only needed for
        changes it cannot express (renames, backfills, type changes).
        """
        logger.info("database_upgrading", from_version=from_version, to_version=SCHEMA_VERSION)
        for step in range(from_version + 1, SCHEMA_VERSION + 1):
            handler = _UPGRADES.get(step)
            if handler is not None:
                with self.engine.begin() as connection:
                    handler(connection)
            self.set_meta("schema_version", str(step))
        logger.info("database_upgraded", version=SCHEMA_VERSION)

    def schema_version(self) -> int:
        value = self.get_meta("schema_version")
        try:
            return int(value) if value else 0
        except ValueError:  # pragma: no cover
            return 0

    # --------------------------------------------------------------- meta --
    # The f-strings below interpolate _META_TABLE, a module constant, never
    # anything derived from input. Both the key and the value are bound
    # parameters. A table name cannot be a bind parameter in SQL, which is why
    # the interpolation exists at all - hence the noqa rather than a rewrite.
    def get_meta(self, key: str) -> str | None:
        try:
            with self.engine.connect() as connection:
                row = connection.execute(
                    text(f"SELECT value FROM {_META_TABLE} WHERE key = :key"),  # noqa: S608
                    {"key": key},
                ).first()
        except Exception:  # pragma: no cover - table not created yet
            return None
        return str(row[0]) if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    f"INSERT INTO {_META_TABLE} (key, value) VALUES (:key, :value) "  # noqa: S608
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
                ),
                {"key": key, "value": value},
            )

    # ---------------------------------------------------------- lifecycle --
    @property
    def path(self) -> str:
        url = self.settings.sync_database_url
        return url.split("///", 1)[-1] if "///" in url else url

    def vacuum(self) -> None:
        """Compact the database. Cheap enough to run at shutdown occasionally."""
        try:
            with self.engine.connect() as connection:
                connection.execute(text("VACUUM"))
        except Exception as exc:  # pragma: no cover
            logger.warning("vacuum_failed", error=str(exc))

    def integrity_check(self) -> bool:
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text("PRAGMA integrity_check")).scalar_one()
            return str(result).lower() == "ok"
        except Exception as exc:
            logger.error("integrity_check_failed", error=str(exc))
            return False

    def backup(self, destination: Path) -> Path:
        """Consistent copy of the database, safe to take while running."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = sqlite3.connect(self.path)
        target = sqlite3.connect(str(destination))
        try:
            with target:
                source.backup(target)
        finally:
            source.close()
            target.close()
        logger.info("database_backed_up", destination=str(destination))
        return destination

    def dispose(self) -> None:
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._factory = None


def _install_sqlite_pragmas(engine: Engine) -> None:
    """WAL journaling, enforced foreign keys and a sane sync level.

    WAL matters here: the UI thread reads scan history while worker threads
    write results, and without it SQLite would serialise them behind a global
    write lock and make the window feel stalled.
    """

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection: Any, _: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA temp_store=MEMORY")
        finally:
            cursor.close()


#: Upgrade steps keyed by target schema version.
_UPGRADES: dict[int, Any] = {}


_DATABASE: LocalDatabase | None = None
_DATABASE_LOCK = threading.Lock()


def get_database(settings: Settings | None = None) -> LocalDatabase:
    """Return the process-wide database, initialising it on first use."""
    global _DATABASE
    if _DATABASE is None:
        with _DATABASE_LOCK:
            if _DATABASE is None:
                database = LocalDatabase(settings)
                database.initialise()
                _DATABASE = database
    return _DATABASE


def reset_database() -> None:
    """Drop the cached database (tests and settings changes)."""
    global _DATABASE
    with _DATABASE_LOCK:
        if _DATABASE is not None:
            _DATABASE.dispose()
        _DATABASE = None


__all__ = ["SCHEMA_VERSION", "LocalDatabase", "get_database", "reset_database"]
