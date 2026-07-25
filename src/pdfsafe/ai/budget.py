"""Daily token budget enforcement.

A Redis counter keyed by UTC date. When Redis is unavailable the budget check
fails *open* (analysis continues) but logs loudly - a metrics outage should not
stop malware triage.
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from pdfsafe.config import get_settings
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

_KEY_PREFIX = "pdfsafe:ai:tokens"
_TTL_SECONDS = 60 * 60 * 48


@lru_cache(maxsize=1)
def _redis() -> Any | None:
    try:
        import redis
    except ImportError:  # pragma: no cover
        logger.warning("redis_unavailable", reason="redis package not installed")
        return None
    try:
        client = redis.Redis.from_url(get_settings().redis_url, socket_timeout=2)
        client.ping()
        return client
    except Exception as exc:
        logger.warning("redis_connect_failed", error=str(exc))
        return None


def _key(when: datetime | None = None) -> str:
    day = (when or datetime.now(UTC)).strftime("%Y-%m-%d")
    return f"{_KEY_PREFIX}:{day}"


def tokens_used_today() -> int:
    client = _redis()
    if client is None:
        return 0
    try:
        value = client.get(_key())
        return int(value or 0)
    except Exception as exc:  # pragma: no cover
        logger.warning("budget_read_failed", error=str(exc))
        return 0


def record_usage(tokens: int) -> None:
    """Add ``tokens`` to today's counter."""
    if tokens <= 0:
        return
    client = _redis()
    if client is None:
        return
    try:
        key = _key()
        pipe = client.pipeline()
        pipe.incrby(key, tokens)
        pipe.expire(key, _TTL_SECONDS)
        pipe.execute()
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


def reset_cache() -> None:
    _redis.cache_clear()
