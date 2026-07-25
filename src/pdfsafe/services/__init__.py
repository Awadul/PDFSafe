"""Application services: ingestion, processing and queries."""

from pdfsafe.services.ingest import IngestResult, ingest_bytes
from pdfsafe.services.processing import process_scan
from pdfsafe.services.queries import get_scan, get_stats, list_scans

__all__ = [
    "IngestResult",
    "get_scan",
    "get_stats",
    "ingest_bytes",
    "list_scans",
    "process_scan",
]
