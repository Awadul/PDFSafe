"""API request/response contracts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from pdfsafe.enums import DecisionSource, ScanStatus, Severity, UploadSource, Verdict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ScanSubmitResponse(ORMModel):
    """Returned immediately after an upload is accepted."""

    id: uuid.UUID
    status: ScanStatus
    filename: str
    sha256: str
    file_size: int
    duplicate_of: uuid.UUID | None = Field(
        default=None, description="Set when this content was already scanned."
    )
    task_id: str | None = None
    created_at: datetime


class IndicatorOut(ORMModel):
    code: str
    title: str
    description: str | None = None
    severity: Severity
    weight: int
    category: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_technique: str | None = None


class AIAssessmentOut(ORMModel):
    provider: str
    model: str
    verdict: Verdict
    confidence: float | None = None
    risk_score: int | None = None
    summary: str | None = None
    reasoning: str | None = None
    attack_techniques: list[Any] = Field(default_factory=list)
    recommended_action: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int | None = None
    succeeded: bool = True
    created_at: datetime


class AnalysisReportOut(ORMModel):
    pdf_version: str | None = None
    page_count: int | None = None
    object_count: int | None = None
    stream_count: int | None = None
    is_encrypted: bool = False
    is_linearized: bool = False
    incremental_updates: int = 0
    entropy: float | None = None
    keyword_counts: dict[str, Any] = Field(default_factory=dict)
    javascript: list[Any] = Field(default_factory=list)
    actions: list[Any] = Field(default_factory=list)
    embedded_files: list[Any] = Field(default_factory=list)
    urls: list[Any] = Field(default_factory=list)
    yara_matches: list[Any] = Field(default_factory=list)
    document_metadata: dict[str, Any] = Field(default_factory=dict)
    structure: dict[str, Any] = Field(default_factory=dict)
    parse_errors: list[Any] = Field(default_factory=list)
    analysis_ms: int | None = None


class ScanSummary(ORMModel):
    """Compact representation used in list views."""

    id: uuid.UUID
    filename: str
    file_size: int
    sha256: str
    status: ScanStatus
    verdict: Verdict
    risk_score: int
    confidence: float | None = None
    decided_by: DecisionSource | None = None
    source: UploadSource
    summary: str | None = None
    quarantined: bool = False
    created_at: datetime
    completed_at: datetime | None = None
    duration_ms: int | None = None


class ScanDetail(ScanSummary):
    """Full scan record including analysis and AI output."""

    content_type: str | None = None
    md5: str | None = None
    submitted_by: str | None = None
    correlation_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    reviewed: bool = False
    review_note: str | None = None
    indicators: list[IndicatorOut] = Field(default_factory=list)
    ai_assessments: list[AIAssessmentOut] = Field(default_factory=list)
    report: AnalysisReportOut | None = None


class PaginatedScans(BaseModel):
    items: list[ScanSummary]
    total: int
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


class ScanFilter(BaseModel):
    """Query parameters for listing scans."""

    status: ScanStatus | None = None
    verdict: Verdict | None = None
    sha256: str | None = Field(default=None, min_length=64, max_length=64)
    filename_contains: str | None = Field(default=None, max_length=255)
    min_risk_score: int | None = Field(default=None, ge=0, le=100)
    created_after: datetime | None = None
    created_before: datetime | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
    order_by: Literal["created_at", "risk_score"] = "created_at"
    order_dir: Literal["asc", "desc"] = "desc"


class ScanReviewRequest(BaseModel):
    """Manual analyst override."""

    verdict: Verdict
    note: str = Field(default="", max_length=2000)
    quarantine: bool | None = None


class ScanStats(BaseModel):
    """Dashboard aggregates."""

    total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_verdict: dict[str, int] = Field(default_factory=dict)
    malicious_last_24h: int = 0
    scanned_last_24h: int = 0
    avg_duration_ms: float | None = None
    ai_calls_last_24h: int = 0


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "error"] = "ok"
    version: str
    env: str
    checks: dict[str, str] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: str
    message: str
    details: dict[str, Any] | None = None
    correlation_id: str | None = None
