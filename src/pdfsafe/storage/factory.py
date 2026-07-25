"""Storage backend selection."""

from __future__ import annotations

from functools import lru_cache

from pdfsafe.config import Settings, StorageBackend, get_settings
from pdfsafe.storage.base import ObjectStorage
from pdfsafe.storage.local import LocalStorage
from pdfsafe.storage.s3 import S3Storage


def build_storage(settings: Settings) -> ObjectStorage:
    if settings.storage_backend is StorageBackend.S3:
        return S3Storage(
            bucket=settings.s3_bucket,
            region=settings.s3_region,
            endpoint_url=settings.s3_endpoint_url or None,
            access_key_id=settings.s3_access_key_id.get_secret_value() or None,
            secret_access_key=settings.s3_secret_access_key.get_secret_value() or None,
        )
    return LocalStorage(settings.storage_local_path)


@lru_cache(maxsize=1)
def get_storage() -> ObjectStorage:
    """Return the process-wide storage backend."""
    return build_storage(get_settings())
