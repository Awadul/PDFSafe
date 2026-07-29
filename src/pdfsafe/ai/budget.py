"""Daily token budget.

Counts are kept in the application's own SQLite database, in the same
``pdfsafe_meta`` key/value table the schema version uses. Keys are namespaced by
UTC date so the budget rolls over at midnight and old rows are trivially
identifiable.

This used to be a Redis counter, inherited from the server deployment. On a
desktop install Redis is neither present nor installable, so the soft import
always failed and the budget silently never applied - a configured limit that
could not do anything. SQLite is already open, already durable, and already
per-user.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from pdfsafe.config import get_settings
from pdfsafe.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover
    from pdfsafe.local.database import LocalDatabase

logger = get_logger(__name__)

KEY_PREFIX = "ai_tokens"
#: Counters older than this are pruned on write.
RETENTION_DAYS = 7


def _database() -> LocalDatabase | None:
    """Resolve the database lazily.

    Imported inside the function so the AI package does not depend on the
    desktop runtime at module level, and so a database problem degrades to
    "no budget tracking" rather than an import error.
    """
    try:
        from pdfsafe.local.database import get_database

        return get_database()
    except Exception as exc:  # pragma: no cover - unwritable profile, locked db
        logger.warning("budget_database_unavailable", error=str(exc))
        return None


def _key(when: datetime | None = None) -> str:
    day = (when or datetime.now(UTC)).strftime("%Y-%m-%d")
    return f"{KEY_PREFIX}:{day}"


def tokens_used_today() -> int:
    """Tokens consumed since midnight UTC."""
    database = _database()
    if database is None:
        return 0
    try:
        raw = database.get_meta(_key())
        return int(raw) if raw else 0
    except (ValueError, TypeError):
        return 0
    except Exception as exc:  # pragma: no cover
        logger.warning("budget_read_failed", error=str(exc))
        return 0


def record_usage(tokens: int) -> None:
    """Add ``tokens`` to today's counter."""
    if tokens <= 0:
        return
    database = _database()
    if database is None:
        return
    try:
        database.set_meta(_key(), str(tokens_used_today() + tokens))
        _prune(database)
    except Exception as exc:  # pragma: no cover
        logger.warning("budget_write_failed", error=str(exc))


def has_budget() -> bool:
    """Whether another LLM call is allowed under today's budget."""
    limit = get_settings().ai_daily_token_budget
    if limit <= 0:
        return True

    used = tokens_used_today()
    if used >= limit:
        logger.warning("ai_budget_exhausted", used=used, limit=limit)
        return False
    return True


def remaining() -> int | None:
    """Tokens left today, or ``None`` when the budget is unlimited."""
    limit = get_settings().ai_daily_token_budget
    if limit <= 0:
        return None
    return max(0, limit - tokens_used_today())


def reset_today() -> None:
    """Clear today's counter (used by the settings dialog and by tests)."""
    database = _database()
    if database is not None:
        try:
            database.set_meta(_key(), "0")
        except Exception as exc:  # pragma: no cover
            logger.warning("budget_reset_failed", error=str(exc))


def _prune(database: LocalDatabase, keep_days: int = RETENTION_DAYS) -> None:
    """Drop counters older than the retention window."""
    from sqlalchemy import text

    cutoff = (datetime.now(UTC) - timedelta(days=keep_days)).strftime("%Y-%m-%d")
    try:
        with database.engine.begin() as connection:
            connection.execute(
                text("DELETE FROM pdfsafe_meta WHERE key LIKE :prefix AND key < :cutoff"),
                {"prefix": f"{KEY_PREFIX}:%", "cutoff": f"{KEY_PREFIX}:{cutoff}"},
            )
    except Exception:  # pragma: no cover - pruning is housekeeping only
        return
