"""Provider registry.

Third-party providers can be plugged in at runtime::

    from pdfsafe.ai import register_provider

    register_provider("my-gateway", lambda: MyProvider(...))

and selected with ``PDFSAFE_AI_PROVIDER=my-gateway``.
"""

from __future__ import annotations

from collections.abc import Callable
from threading import Lock

from pdfsafe.ai.base import LLMProvider, NullProvider
from pdfsafe.config import AIProviderName, get_settings
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

ProviderFactory = Callable[[], LLMProvider]

_FACTORIES: dict[str, ProviderFactory] = {}
_INSTANCES: dict[str, LLMProvider] = {}
_LOCK = Lock()


def register_provider(name: str, factory: ProviderFactory, *, override: bool = False) -> None:
    """Register a provider factory under ``name``."""
    key = name.strip().lower()
    with _LOCK:
        if key in _FACTORIES and not override:
            raise ValueError(
                f"Provider '{key}' is already registered; pass override=True to replace"
            )
        _FACTORIES[key] = factory
        _INSTANCES.pop(key, None)
    logger.debug("ai_provider_registered", provider=key)


def available_providers() -> list[str]:
    _bootstrap()
    return sorted(_FACTORIES)


def get_provider(name: str | None = None) -> LLMProvider:
    """Return the configured provider (cached per process).

    Falls back to :class:`NullProvider` when AI is disabled or the selected
    provider is not usable, so callers never have to branch on configuration.
    """
    _bootstrap()
    settings = get_settings()

    if not settings.ai_enabled:
        return _instance("null")

    key = (name or settings.ai_provider.value).strip().lower()
    if key not in _FACTORIES:
        logger.warning("ai_provider_unknown", requested=key, available=sorted(_FACTORIES))
        return _instance("null")

    provider = _instance(key)
    if not provider.is_configured():
        logger.warning("ai_provider_unconfigured", provider=key)
        return _instance("null")
    return provider


def _instance(key: str) -> LLMProvider:
    with _LOCK:
        cached = _INSTANCES.get(key)
        if cached is None:
            cached = _FACTORIES[key]()
            _INSTANCES[key] = cached
        return cached


def reset() -> None:
    """Drop cached instances (used by tests and config reloads)."""
    with _LOCK:
        _INSTANCES.clear()


def _bootstrap() -> None:
    """Register the built-in providers exactly once."""
    if _FACTORIES:
        return

    from pdfsafe.ai.anthropic_provider import build_from_settings as build_anthropic
    from pdfsafe.ai.custom_provider import build_from_settings as build_custom

    with _LOCK:
        if _FACTORIES:  # pragma: no cover - double-checked locking
            return
        _FACTORIES[AIProviderName.ANTHROPIC.value] = build_anthropic
        _FACTORIES[AIProviderName.CUSTOM.value] = build_custom
        _FACTORIES[AIProviderName.NULL.value] = NullProvider
