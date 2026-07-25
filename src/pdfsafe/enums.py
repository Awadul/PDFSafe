"""Shared domain enumerations used by the DB models, schemas and services."""

from __future__ import annotations

from enum import StrEnum


class ScanStatus(StrEnum):
    """Lifecycle of a submitted file."""

    PENDING = "pending"
    ANALYZING = "analyzing"
    AI_REVIEW = "ai_review"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"

    @property
    def is_terminal(self) -> bool:
        return self in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.QUARANTINED}


class Verdict(StrEnum):
    """Final judgement for a scanned file."""

    CLEAN = "clean"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

    @property
    def is_blocking(self) -> bool:
        return self in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}


class Severity(StrEnum):
    """Severity of an individual indicator."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionSource(StrEnum):
    """Which layer produced the final verdict."""

    HEURISTICS = "heuristics"
    AI = "ai"
    HYBRID = "hybrid"
    MANUAL = "manual"
    ERROR = "error"


class UploadSource(StrEnum):
    """How the file entered the system."""

    API = "api"
    DASHBOARD = "dashboard"
    WATCH_FOLDER = "watch_folder"
    CLI = "cli"


# Ordering helpers -----------------------------------------------------------
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

VERDICT_ORDER: dict[Verdict, int] = {
    Verdict.CLEAN: 0,
    Verdict.LOW_RISK: 1,
    Verdict.UNKNOWN: 2,
    Verdict.SUSPICIOUS: 3,
    Verdict.MALICIOUS: 4,
}


def max_severity(values: list[Severity]) -> Severity:
    """Return the highest severity in ``values`` (INFO when empty)."""
    if not values:
        return Severity.INFO
    return max(values, key=lambda s: SEVERITY_ORDER[s])


def worst_verdict(a: Verdict, b: Verdict) -> Verdict:
    """Return the more severe of two verdicts."""
    return a if VERDICT_ORDER[a] >= VERDICT_ORDER[b] else b
