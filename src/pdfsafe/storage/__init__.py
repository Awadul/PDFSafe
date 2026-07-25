"""Pluggable object storage for uploaded PDFs."""

from pdfsafe.storage.base import ObjectStorage, StoredObject
from pdfsafe.storage.factory import get_storage

__all__ = ["ObjectStorage", "StoredObject", "get_storage"]
