"""Pydantic contracts shared across the analysis, AI and desktop layers."""

from pdfsafe.schemas.ai import AICallResult, AIVerdict, EvidenceBundle
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
from pdfsafe.schemas.scan import ScanStats

__all__ = [
    "AICallResult",
    "AIVerdict",
    "ActionFinding",
    "DocumentMetadata",
    "EmbeddedFileFinding",
    "EvidenceBundle",
    "IndicatorResult",
    "JavaScriptFinding",
    "ScanStats",
    "StaticAnalysisResult",
    "StructureSummary",
    "URLFinding",
    "YaraMatch",
]
