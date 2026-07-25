"""API-key authentication and a Redis-backed sliding-window rate limiter."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from fastapi import Request
from fastapi.security import APIKeyHeader

from pdfsafe.config import get_settings
from pdfsafe.exceptions import AuthenticationError, RateLimitExceededError
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

API_KEY_HEADER = "X-API-Key"
api_key_scheme = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    key_id: str
    name: str
    is_anonymous: bool = False

    @classmethod
    def anonymous(cls) -> Principal:
        return cls(key_id="anonymous", name="anonymous", is_anonymous=True)


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_key(prefix: str = "pdfsafe") -> str:
    """Generate a new API key. Store only its hash."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


@lru_cache(maxsize=1)
def _configured_hashes() -> dict[str, str]:
    """Map hash -> display name for keys supplied via configuration."""
    return {hash_key(key): f"key:{key[:6]}…" for key in get_settings().api_keys}


def authenticate(raw_key: str | None) -> Principal:
    """Validate an API key using a constant-time comparison."""
    settings = get_settings()
    if not settings.auth_required:
        return Principal.anonymous()

    if not raw_key:
        raise AuthenticationError(f"Missing {API_KEY_HEADER} header.")

    candidate = hash_key(raw_key)
    for known_hash, name in _configured_hashes().items():
        if hmac.compare_digest(candidate, known_hash):
            return Principal(key_id=candidate[:16], name=name)

    logger.warning("auth_failed", key_prefix=raw_key[:6])
    raise AuthenticationError("The supplied API key is not recognised.")


def reset_key_cache() -> None:
    _configured_hashes.cache_clear()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class RateLimiter:
    """Fixed-window limiter backed by Redis, with an in-process fallback.

    The fallback is per-worker rather than global, so it is a safety net for
    single-node development, not a substitute for Redis in production.
    """

    def __init__(self, limit_per_minute: int) -> None:
        self.limit = limit_per_minute
        self._local: dict[str, tuple[int, float]] = {}

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def check(self, identity: str) -> None:
        if not self.enabled:
            return
        window = int(time.time() // 60)
        key = f"pdfsafe:ratelimit:{identity}:{window}"

        client = _redis_client()
        if client is not None:
            try:
                pipe = client.pipeline()
                pipe.incr(key)
                pipe.expire(key, 120)
                count = int(pipe.execute()[0])
            except Exception as exc:  # pragma: no cover - redis blip
                logger.warning("rate_limit_backend_failed", error=str(exc))
                count = self._local_incr(key)
        else:
            count = self._local_incr(key)

        if count > self.limit:
            raise RateLimitExceededError(
                f"Rate limit of {self.limit} requests per minute exceeded.",
                limit=self.limit,
                retry_after=60 - int(time.time() % 60),
            )

    def _local_incr(self, key: str) -> int:
        now = time.time()
        self._local = {k: v for k, v in self._local.items() if v[1] > now - 120}
        count, _ = self._local.get(key, (0, now))
        count += 1
        self._local[key] = (count, now)
        return count


@lru_cache(maxsize=1)
def _redis_client() -> Any | None:
    try:
        import redis
    except ImportError:  # pragma: no cover
        return None
    try:
        client = redis.Redis.from_url(get_settings().redis_url, socket_timeout=1)
        client.ping()
        return client
    except Exception as exc:
        logger.warning("rate_limit_redis_unavailable", error=str(exc))
        return None


@lru_cache(maxsize=1)
def get_rate_limiter() -> RateLimiter:
    return RateLimiter(get_settings().rate_limit_per_minute)


def client_identity(request: Request, principal: Principal) -> str:
    """Rate-limit key: API key when present, otherwise client IP."""
    if not principal.is_anonymous:
        return principal.key_id
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
