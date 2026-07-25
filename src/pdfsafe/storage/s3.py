"""S3 / S3-compatible storage backend (MinIO, R2, Wasabi, ...)."""

from __future__ import annotations

import hashlib
import tempfile
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pdfsafe.exceptions import StorageError
from pdfsafe.logging import get_logger
from pdfsafe.storage.base import ObjectStorage, StoredObject

if TYPE_CHECKING:  # pragma: no cover
    pass

logger = get_logger(__name__)


class S3Storage(ObjectStorage):
    """Server-side-encrypted object storage."""

    name = "s3"

    def __init__(
        self,
        bucket: str,
        *,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        prefix: str = "pdfsafe",
    ) -> None:
        self.bucket = bucket
        self.region = region
        self.endpoint_url = endpoint_url or None
        self.prefix = prefix.strip("/")
        self._access_key_id = access_key_id or None
        self._secret_access_key = secret_access_key or None

    @cached_property
    def _client(self) -> Any:
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover
            raise StorageError("boto3 is required for the s3 storage backend") from exc

        return boto3.client(
            "s3",
            region_name=self.region,
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self._access_key_id,
            aws_secret_access_key=self._secret_access_key,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}, signature_version="s3v4"),
        )

    def _full_key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    # ---------------------------------------------------------- operations --
    def save(self, key: str, data: bytes) -> StoredObject:
        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=self._full_key(key),
                Body=data,
                ContentType="application/pdf",
                ServerSideEncryption="AES256",
                Metadata={"sha256": hashlib.sha256(data).hexdigest()},
            )
        except Exception as exc:  # pragma: no cover - network failure
            raise StorageError(f"Could not upload {key}: {exc}") from exc

        logger.debug("stored_object", key=key, size=len(data), backend=self.name)
        return StoredObject(
            key=key,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            backend=self.name,
            stored_at=StoredObject.now(),
        )

    def load(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self.bucket, Key=self._full_key(key))
            body: bytes = response["Body"].read()
            return body
        except Exception as exc:
            raise StorageError(f"Could not download {key}: {exc}") from exc

    def delete(self, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self.bucket, Key=self._full_key(key))
        except Exception as exc:  # pragma: no cover
            logger.warning("s3_delete_failed", key=key, error=str(exc))

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=self._full_key(key))
            return True
        except Exception:
            return False

    def local_path(self, key: str) -> Path:
        """Materialise the object into a temp file. Caller must delete it."""
        data = self.load(key)
        fd, name = tempfile.mkstemp(suffix=".pdf", prefix="pdfsafe-")
        with open(fd, "wb") as handle:
            handle.write(data)
        return Path(name)
