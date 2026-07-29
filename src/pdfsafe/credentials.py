"""API key storage backed by the operating system credential manager.

A key shipped inside an .exe is extractable in minutes, so PDFSafe never
contains one. The user supplies their own through the settings dialog and it is
written to:

* Windows - Credential Manager (DPAPI-encrypted against the user account)
* macOS   - Keychain
* Linux   - Secret Service / KWallet

Resolution order when the engine needs a key: credential store, then the
``PDFSAFE_*_API_KEY`` environment variable (useful for the server target and
for CI). Keys are never written to ``config.json`` or to the logs.
"""

from __future__ import annotations

from typing import Final

from pdfsafe.logging import get_logger

logger = get_logger(__name__)

SERVICE_NAME: Final = "PDFSafe"

#: Credential-store entry names, keyed by provider.
ENTRY_NAMES: Final[dict[str, str]] = {
    "anthropic": "anthropic_api_key",
    "custom": "custom_api_key",
}


class CredentialStoreUnavailableError(RuntimeError):
    """The platform credential store could not be reached."""


def _keyring() -> object | None:
    try:
        import keyring
    except ImportError:  # pragma: no cover - keyring is a core dependency
        logger.warning("keyring_unavailable", reason="package not installed")
        return None
    return keyring


def is_available() -> bool:
    """Whether a usable credential backend is present."""
    keyring = _keyring()
    if keyring is None:
        return False
    try:
        backend = keyring.get_keyring()  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover
        logger.warning("keyring_backend_failed", error=str(exc))
        return False
    name = type(backend).__name__
    if "Fail" in name:
        logger.warning("keyring_backend_unusable", backend=name)
        return False
    return True


def set_api_key(provider: str, key: str) -> None:
    """Store (or clear, when ``key`` is empty) the API key for ``provider``."""
    entry = ENTRY_NAMES.get(provider, f"{provider}_api_key")
    keyring = _keyring()
    if keyring is None:
        raise CredentialStoreUnavailableError("No credential backend is available on this system.")

    if not key.strip():
        delete_api_key(provider)
        return

    try:
        keyring.set_password(SERVICE_NAME, entry, key.strip())  # type: ignore[attr-defined]
    except Exception as exc:
        raise CredentialStoreUnavailableError(f"Could not save the key: {exc}") from exc

    logger.info("api_key_stored", provider=provider, length=len(key.strip()))


def get_api_key(provider: str) -> str:
    """Return the stored key for ``provider``, or an empty string."""
    entry = ENTRY_NAMES.get(provider, f"{provider}_api_key")
    keyring = _keyring()
    if keyring is None:
        return ""
    try:
        value = keyring.get_password(SERVICE_NAME, entry)  # type: ignore[attr-defined]
    except Exception as exc:
        logger.warning("api_key_read_failed", provider=provider, error=str(exc))
        return ""
    return (value or "").strip()


def delete_api_key(provider: str) -> None:
    """Remove the stored key for ``provider``. Missing entries are ignored."""
    entry = ENTRY_NAMES.get(provider, f"{provider}_api_key")
    keyring = _keyring()
    if keyring is None:
        return
    try:
        keyring.delete_password(SERVICE_NAME, entry)  # type: ignore[attr-defined]
        logger.info("api_key_deleted", provider=provider)
    except Exception:
        return


def has_api_key(provider: str) -> bool:
    return bool(get_api_key(provider))


def resolve_api_key(provider: str, fallback: str = "") -> str:
    """Credential store first, then the caller-supplied fallback (env/config)."""
    return get_api_key(provider) or (fallback or "").strip()


def masked(key: str) -> str:
    """Render a key for display: ``sk-ant…4f2a``."""
    stripped = key.strip()
    if not stripped:
        return ""
    if len(stripped) <= 12:
        return "•" * len(stripped)
    return f"{stripped[:6]}…{stripped[-4:]}"
