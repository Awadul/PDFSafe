"""Pydantic contracts shared across the API, worker and AI layers."""

from pdfsafe.schemas.ai import AIVerdict, EvidenceBundle
from pdfsafe.schemas.analysis import (
    ActionFinding,
    DocumentMetadata,
    EmbeddedFileFinding,
    IndicatorResult,
    JavaScriptFinding,
    StaticAnalysisResult,
    StructureSummary,
    URLFinding,
    YaraMatch,
)
from pdfsafe.schemas.scan import (
    HealthResponse,
    PaginatedScans,
    ScanDetail,
    ScanStats,
    ScanSubmitResponse,
    ScanSummary,
)

__all__ = [
    "AIVerdict",
    "ActionFinding",
    "DocumentMetadata",
    "EmbeddedFileFinding",
    "EvidenceBundle",
    "HealthResponse",
    "IndicatorResult",
    "JavaScriptFinding",
    "PaginatedScans",
    "ScanDetail",
    "ScanStats",
    "ScanSubmitResponse",
    "ScanSummary",
    "StaticAnalysisResult",
    "StructureSummary",
    "URLFinding",
    "YaraMatch",
]
