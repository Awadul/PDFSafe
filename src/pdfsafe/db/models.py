"""ORM models.

Schema overview::

    scans            one row per submitted file (lifecycle + final verdict)
     +- analysis_reports   1:1  raw static-analysis output
     +- indicators         1:N  individual findings with weights
     +- ai_assessments     1:N  each LLM consultation (retries kept for audit)
     +- audit_events       1:N  append-only lifecycle trail
    api_clients      API keys (hashed) and their quotas
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pdfsafe.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from pdfsafe.enums import (
    DecisionSource,
    ScanStatus,
    Severity,
    UploadSource,
    Verdict,
)


def _enum(python_enum: type, name: str) -> SAEnum:
    """Build a native PG enum that stores the *value* of a StrEnum."""
    return SAEnum(
        python_enum,
        name=name,
        native_enum=True,
        values_callable=lambda e: [member.value for member in e],
        validate_strings=True,
    )


class Scan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single submitted PDF and its triage outcome."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_status_created_at", "status", "created_at"),
        Index("ix_scans_verdict_created_at", "verdict", "created_at"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
        CheckConstraint("file_size >= 0", name="file_size_non_negative"),
    )

    # --- file identity ---
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(128))
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    md5: Mapped[str | None] = mapped_column(String(32), index=True)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)

    # --- provenance ---
    source: Mapped[UploadSource] = mapped_column(
        _enum(UploadSource, "upload_source"), default=UploadSource.DASHBOARD, nullable=False
    )
    submitted_by: Mapped[str | None] = mapped_column(String(255))
    client_ip: Mapped[str | None] = mapped_column(String(64))
    correlation_id: Mapped[str | None] = mapped_column(String(64), index=True)

    # --- lifecycle ---
    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"), default=ScanStatus.PENDING, nullable=False, index=True
    )
    verdict: Mapped[Verdict] = mapped_column(
        _enum(Verdict, "verdict"), default=Verdict.UNKNOWN, nullable=False, index=True
    )
    decided_by: Mapped[DecisionSource | None] = mapped_column(
        _enum(DecisionSource, "decision_source")
    )
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float)
    summary: Mapped[str | None] = mapped_column(Text)

    # --- timings ---
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    # --- failure handling ---
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    task_id: Mapped[str | None] = mapped_column(String(64), index=True)

    # --- flags ---
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    review_note: Mapped[str | None] = mapped_column(Text)

    extra: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    # --- relationships ---
    report: Mapped[AnalysisReport | None] = relationship(
        back_populates="scan", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )
    indicators: Mapped[list[Indicator]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="desc(Indicator.weight)",
    )
    ai_assessments: Mapped[list[AIAssessment]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="AIAssessment.created_at",
    )
    events: Mapped[list[AuditEvent]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="AuditEvent.created_at"
    )

    @property
    def latest_assessment(self) -> AIAssessment | None:
        return self.ai_assessments[-1] if self.ai_assessments else None


class AnalysisReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Raw structural analysis output for a scan (1:1)."""

    __tablename__ = "analysis_reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )

    pdf_version: Mapped[str | None] = mapped_column(String(16))
    page_count: Mapped[int | None] = mapped_column(Integer)
    object_count: Mapped[int | None] = mapped_column(Integer)
    stream_count: Mapped[int | None] = mapped_column(Integer)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_linearized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    has_xref_stream: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    incremental_updates: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    entropy: Mapped[float | None] = mapped_column(Float)
    parse_errors: Mapped[list[Any]] = mapped_column(default=list, nullable=False)

    # Structured payloads (see pdfsafe.schemas.analysis for the shapes).
    keyword_counts: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    javascript: Mapped[list[Any]] = mapped_column(default=list, nullable=False)
    actions: Mapped[list[Any]] = mapped_column(default=list, nullable=False)
    embedded_files: Mapped[list[Any]] = mapped_column(default=list, nullable=False)
    urls: Mapped[list[Any]] = mapped_column(default=list, nullable=False)
    yara_matches: Mapped[list[Any]] = mapped_column(default=list, nullable=False)
    document_metadata: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    structure: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    text_excerpt: Mapped[str | None] = mapped_column(Text)
    analysis_ms: Mapped[int | None] = mapped_column(Integer)
    analyzer_version: Mapped[str | None] = mapped_column(String(32))

    scan: Mapped[Scan] = relationship(back_populates="report")


class Indicator(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single suspicious trait found during static analysis."""

    __tablename__ = "indicators"
    __table_args__ = (
        Index("ix_indicators_scan_severity", "scan_id", "severity"),
        UniqueConstraint("scan_id", "code", name="uq_indicators_scan_code"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False)
    weight: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    category: Mapped[str | None] = mapped_column(String(64), index=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    mitre_technique: Mapped[str | None] = mapped_column(String(32))

    scan: Mapped[Scan] = relationship(back_populates="indicators")


class AIAssessment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One LLM consultation for a scan."""

    __tablename__ = "ai_assessments"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    verdict: Mapped[Verdict] = mapped_column(_enum(Verdict, "verdict"), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    summary: Mapped[str | None] = mapped_column(Text)
    reasoning: Mapped[str | None] = mapped_column(Text)
    attack_techniques: Mapped[list[Any]] = mapped_column(default=list, nullable=False)
    recommended_action: Mapped[str | None] = mapped_column(String(64))
    raw_response: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[float | None] = mapped_column(Float)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="ai_assessments")


class AuditEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Append-only lifecycle trail for compliance and debugging."""

    __tablename__ = "audit_events"

    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    event: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[str | None] = mapped_column(String(255))
    message: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    scan: Mapped[Scan | None] = relationship(back_populates="events")


__all__ = [
    "AIAssessment",
    "AnalysisReport",
    "AuditEvent",
    "Indicator",
    "Scan",
]
