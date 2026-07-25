"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-01-01 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = postgresql.JSONB(astext_type=sa.Text())

scan_status = sa.Enum(
    "pending", "analyzing", "ai_review", "completed", "failed", "quarantined", name="scan_status"
)
verdict = sa.Enum("clean", "low_risk", "suspicious", "malicious", "unknown", name="verdict")
severity = sa.Enum("info", "low", "medium", "high", "critical", name="severity")
decision_source = sa.Enum("heuristics", "ai", "hybrid", "manual", "error", name="decision_source")
upload_source = sa.Enum("api", "dashboard", "watch_folder", "cli", name="upload_source")


def upgrade() -> None:
    bind = op.get_bind()
    for enum_type in (scan_status, verdict, severity, decision_source, upload_source):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("md5", sa.String(length=32), nullable=True),
        sa.Column("storage_key", sa.String(length=1024), nullable=False),
        sa.Column("source", upload_source, nullable=False),
        sa.Column("submitted_by", sa.String(length=255), nullable=True),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("verdict", verdict, nullable=False),
        sa.Column("decided_by", decision_source, nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.String(length=64), nullable=True),
        sa.Column("quarantined", sa.Boolean(), nullable=False),
        sa.Column("reviewed", sa.Boolean(), nullable=False),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("extra", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_scans_risk_score_range"),
        sa.CheckConstraint("file_size >= 0", name="ck_scans_file_size_non_negative"),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_created_at", "scans", ["created_at"])
    op.create_index("ix_scans_sha256", "scans", ["sha256"])
    op.create_index("ix_scans_md5", "scans", ["md5"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_verdict", "scans", ["verdict"])
    op.create_index("ix_scans_task_id", "scans", ["task_id"])
    op.create_index("ix_scans_correlation_id", "scans", ["correlation_id"])
    op.create_index("ix_scans_status_created_at", "scans", ["status", "created_at"])
    op.create_index("ix_scans_verdict_created_at", "scans", ["verdict", "created_at"])

    op.create_table(
        "analysis_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("pdf_version", sa.String(length=16), nullable=True),
        sa.Column("page_count", sa.Integer(), nullable=True),
        sa.Column("object_count", sa.Integer(), nullable=True),
        sa.Column("stream_count", sa.Integer(), nullable=True),
        sa.Column("is_encrypted", sa.Boolean(), nullable=False),
        sa.Column("is_linearized", sa.Boolean(), nullable=False),
        sa.Column("has_xref_stream", sa.Boolean(), nullable=False),
        sa.Column("incremental_updates", sa.Integer(), nullable=False),
        sa.Column("entropy", sa.Float(), nullable=True),
        sa.Column("parse_errors", JSONB, nullable=False),
        sa.Column("keyword_counts", JSONB, nullable=False),
        sa.Column("javascript", JSONB, nullable=False),
        sa.Column("actions", JSONB, nullable=False),
        sa.Column("embedded_files", JSONB, nullable=False),
        sa.Column("urls", JSONB, nullable=False),
        sa.Column("yara_matches", JSONB, nullable=False),
        sa.Column("document_metadata", JSONB, nullable=False),
        sa.Column("structure", JSONB, nullable=False),
        sa.Column("text_excerpt", sa.Text(), nullable=True),
        sa.Column("analysis_ms", sa.Integer(), nullable=True),
        sa.Column("analyzer_version", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_analysis_reports_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_analysis_reports"),
        sa.UniqueConstraint("scan_id", name="uq_analysis_reports_scan_id"),
    )
    op.create_index("ix_analysis_reports_created_at", "analysis_reports", ["created_at"])

    op.create_table(
        "indicators",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", severity, nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("evidence", JSONB, nullable=False),
        sa.Column("mitre_technique", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_indicators_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_indicators"),
        sa.UniqueConstraint("scan_id", "code", name="uq_indicators_scan_code"),
    )
    op.create_index("ix_indicators_scan_id", "indicators", ["scan_id"])
    op.create_index("ix_indicators_code", "indicators", ["code"])
    op.create_index("ix_indicators_category", "indicators", ["category"])
    op.create_index("ix_indicators_created_at", "indicators", ["created_at"])
    op.create_index("ix_indicators_scan_severity", "indicators", ["scan_id", "severity"])

    op.create_table(
        "ai_assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("verdict", verdict, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("reasoning", sa.Text(), nullable=True),
        sa.Column("attack_techniques", JSONB, nullable=False),
        sa.Column("recommended_action", sa.String(length=64), nullable=True),
        sa.Column("raw_response", JSONB, nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_ai_assessments_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_ai_assessments"),
    )
    op.create_index("ix_ai_assessments_scan_id", "ai_assessments", ["scan_id"])
    op.create_index("ix_ai_assessments_created_at", "ai_assessments", ["created_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=True),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_audit_events_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
    )
    op.create_index("ix_audit_events_scan_id", "audit_events", ["scan_id"])
    op.create_index("ix_audit_events_event", "audit_events", ["event"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])

    op.create_table(
        "api_clients",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("key_prefix", sa.String(length=12), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=True),
        sa.Column("scopes", JSONB, nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_api_clients"),
        sa.UniqueConstraint("name", name="uq_api_clients_name"),
        sa.UniqueConstraint("key_hash", name="uq_api_clients_key_hash"),
    )
    op.create_index("ix_api_clients_key_hash", "api_clients", ["key_hash"])
    op.create_index("ix_api_clients_created_at", "api_clients", ["created_at"])


def downgrade() -> None:
    op.drop_table("api_clients")
    op.drop_table("audit_events")
    op.drop_table("ai_assessments")
    op.drop_table("indicators")
    op.drop_table("analysis_reports")
    op.drop_table("scans")

    bind = op.get_bind()
    for enum_type in (upload_source, decision_source, severity, verdict, scan_status):
        enum_type.drop(bind, checkfirst=True)
