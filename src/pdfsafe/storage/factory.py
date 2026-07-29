"""Storage backend selection."""

from __future__ import annotations

from functools import lru_cache

from pdfsafe.config import Settings, get_settings
from pdfsafe.storage.base import ObjectStorage
from pdfsafe.storage.local import LocalStorage


def build_storage(settings: Settings) -> ObjectStorage:
    return LocalStorage(settings.storage_local_path)


@lru_cache(maxsize=1)
def get_storage() -> ObjectStorage:
    """Return the process-wide storage backend."""
    return build_storage(get_settings())
