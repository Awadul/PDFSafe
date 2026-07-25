"""Scan processing.

This is the synchronous core executed by Celery workers: load the stored file,
analyse it, decide, and persist every artefact. It is deliberately blocking so
it can run under a prefork worker without an event loop.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from pdfsafe.ai.triage import TriageResult, triage
from pdfsafe.analysis.pipeline import AnalysisOutput, analyze_bytes
from pdfsafe.config import get_settings
from pdfsafe.db.models import AIAssessment, AnalysisReport, AuditEvent, Indicator, Scan
from pdfsafe.db.session import sync_session_scope
from pdfsafe.enums import DecisionSource, ScanStatus, Verdict
from pdfsafe.exceptions import ScanNotFoundError, StorageError
from pdfsafe.logging import bind_context, get_logger
from pdfsafe.metrics import scan_failures_total, scans_in_progress, scans_total
from pdfsafe.storage import get_storage

logger = get_logger(__name__)

#: Verdicts that cause the file to be isolated.
QUARANTINE_VERDICTS = {Verdict.MALICIOUS}


def process_scan(scan_id: uuid.UUID | str, *, force_ai: bool = False) -> Verdict:
    """Analyse one scan end to end and persist the outcome.

    Returns the final verdict. Raises only on unrecoverable errors (the scan row
    is marked ``failed`` first, so Celery retries observe a consistent state).
    """
    scan_uuid = uuid.UUID(str(scan_id))
    bind_context(scan_id=str(scan_uuid))
    started = time.perf_counter()

    with sync_session_scope() as session:
        scan = session.get(Scan, scan_uuid)
        if scan is None:
            raise ScanNotFoundError(f"Scan {scan_uuid} does not exist", scan_id=str(scan_uuid))

        scan.status = ScanStatus.ANALYZING
        scan.started_at = datetime.now(UTC)
        session.add(_event(scan.id, "scan.started", "Static analysis started"))
        session.flush()
        storage_key = scan.storage_key
        filename = scan.filename

    scans_in_progress.inc()
    try:
        data = _load(storage_key)
        analysis = analyze_bytes(data, filename=filename)
        result = _decide(analysis, force_ai=force_ai)
        _persist_success(scan_uuid, analysis, result, started)
        scans_total.labels(verdict=result.verdict.value, decided_by=result.decided_by.value).inc()
        return result.verdict
    except Exception as exc:
        stage = "storage" if isinstance(exc, StorageError) else "analysis"
        scan_failures_total.labels(stage=stage).inc()
        logger.exception("scan_failed", scan_id=str(scan_uuid), stage=stage)
        _persist_failure(scan_uuid, exc, started)
        raise
    finally:
        scans_in_progress.dec()


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def _load(storage_key: str) -> bytes:
    storage = get_storage()
    return storage.load(storage_key)


def _decide(analysis: AnalysisOutput, *, force_ai: bool) -> TriageResult:
    return triage(analysis.result, analysis.outcome, force_ai=force_ai)


def _persist_success(
    scan_id: uuid.UUID,
    analysis: AnalysisOutput,
    decision: TriageResult,
    started: float,
) -> None:
    settings = get_settings()
    duration_ms = int((time.perf_counter() - started) * 1000)
    result = analysis.result

    with sync_session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:  # pragma: no cover - deleted mid-flight
            return

        _replace_report(session, scan, analysis)
        _replace_indicators(session, scan, analysis)

        if decision.ai_call is not None:
            session.add(_assessment_row(scan.id, decision))

        scan.status = ScanStatus.COMPLETED
        scan.verdict = decision.verdict
        scan.risk_score = decision.risk_score
        scan.confidence = decision.confidence
        scan.decided_by = decision.decided_by
        scan.summary = decision.summary[:4000]
        scan.completed_at = datetime.now(UTC)
        scan.duration_ms = duration_ms
        scan.error_code = None
        scan.error_message = None
        scan.md5 = scan.md5 or result.md5
        scan.extra = {
            **(scan.extra or {}),
            "heuristic_score": analysis.outcome.score,
            "heuristic_verdict": analysis.outcome.verdict.value,
            "escalation_reason": decision.escalation.reason if decision.escalation else None,
            "analyzer_version": result.analyzer_version,
        }

        if decision.verdict in QUARANTINE_VERDICTS:
            scan.quarantined = True
            scan.status = ScanStatus.QUARANTINED
            _quarantine(scan, settings)

        session.add(
            _event(
                scan.id,
                "scan.completed",
                f"Verdict: {decision.verdict.value} ({decision.risk_score}/100)",
                payload={
                    "verdict": decision.verdict.value,
                    "risk_score": decision.risk_score,
                    "decided_by": decision.decided_by.value,
                    "used_ai": decision.used_ai,
                    "duration_ms": duration_ms,
                },
            )
        )

    logger.info(
        "scan_completed",
        scan_id=str(scan_id),
        verdict=decision.verdict.value,
        risk_score=decision.risk_score,
        decided_by=decision.decided_by.value,
        used_ai=decision.used_ai,
        duration_ms=duration_ms,
    )


def _replace_report(session: Session, scan: Scan, analysis: AnalysisOutput) -> None:
    result = analysis.result
    existing = session.execute(
        select(AnalysisReport).where(AnalysisReport.scan_id == scan.id)
    ).scalar_one_or_none()
    if existing is not None:
        session.delete(existing)
        session.flush()

    session.add(
        AnalysisReport(
            scan_id=scan.id,
            pdf_version=result.structure.pdf_version,
            page_count=result.structure.page_count,
            object_count=result.structure.object_count,
            stream_count=result.structure.stream_count,
            is_encrypted=result.structure.is_encrypted,
            is_linearized=result.structure.is_linearized,
            has_xref_stream=result.structure.has_xref_stream,
            incremental_updates=result.structure.incremental_updates,
            entropy=result.entropy,
            parse_errors=result.parse_errors,
            keyword_counts=result.keyword_counts,
            javascript=[f.model_dump() for f in result.javascript],
            actions=[a.model_dump() for a in result.actions],
            embedded_files=[f.model_dump() for f in result.embedded_files],
            urls=[u.model_dump() for u in result.urls],
            yara_matches=[m.model_dump() for m in result.yara_matches],
            document_metadata=result.metadata.model_dump(),
            structure=result.structure.model_dump(),
            text_excerpt=result.text_excerpt[:8000] or None,
            analysis_ms=result.analysis_ms,
            analyzer_version=result.analyzer_version,
        )
    )


def _replace_indicators(session: Session, scan: Scan, analysis: AnalysisOutput) -> None:
    for existing in session.execute(
        select(Indicator).where(Indicator.scan_id == scan.id)
    ).scalars():
        session.delete(existing)
    session.flush()

    for indicator in analysis.outcome.indicators:
        session.add(
            Indicator(
                scan_id=scan.id,
                code=indicator.code[:64],
                title=indicator.title[:255],
                description=indicator.description,
                severity=indicator.severity,
                weight=indicator.weight,
                category=indicator.category[:64] if indicator.category else None,
                evidence=indicator.evidence,
                mitre_technique=indicator.mitre_technique,
            )
        )


def _assessment_row(scan_id: uuid.UUID, decision: TriageResult) -> AIAssessment:
    call = decision.ai_call
    assert call is not None
    verdict = call.verdict
    return AIAssessment(
        scan_id=scan_id,
        provider=call.provider,
        model=call.model,
        verdict=verdict.verdict if verdict else Verdict.UNKNOWN,
        confidence=verdict.confidence if verdict else None,
        risk_score=verdict.risk_score if verdict else None,
        summary=verdict.summary if verdict else None,
        reasoning=verdict.reasoning if verdict else None,
        attack_techniques=verdict.attack_techniques if verdict else [],
        recommended_action=verdict.recommended_action if verdict else None,
        raw_response=call.raw_response,
        prompt_tokens=call.prompt_tokens,
        completion_tokens=call.completion_tokens,
        latency_ms=call.latency_ms,
        cost_usd=call.cost_usd,
        succeeded=call.succeeded,
        error_message=call.error_message,
    )


def _quarantine(scan: Scan, settings: object) -> None:
    """Move a malicious file out of the general upload area (local backend only)."""
    from pathlib import Path

    from pdfsafe.storage.local import LocalStorage

    storage = get_storage()
    if not isinstance(storage, LocalStorage):
        return
    try:
        target_root = Path(str(getattr(settings, "storage_local_path", "./var/uploads"))).parent / "quarantine"
        storage.quarantine(scan.storage_key, target_root)
        scan.extra = {**(scan.extra or {}), "quarantine_path": str(target_root / scan.storage_key)}
    except Exception as exc:
        logger.warning("quarantine_failed", scan_id=str(scan.id), error=str(exc))


def _persist_failure(scan_id: uuid.UUID, exc: Exception, started: float) -> None:
    from pdfsafe.exceptions import PDFSafeError

    code = exc.code if isinstance(exc, PDFSafeError) else type(exc).__name__
    with sync_session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:  # pragma: no cover
            return
        scan.status = ScanStatus.FAILED
        scan.verdict = Verdict.UNKNOWN
        scan.decided_by = DecisionSource.ERROR
        scan.error_code = str(code)[:64]
        scan.error_message = str(exc)[:4000]
        scan.completed_at = datetime.now(UTC)
        scan.duration_ms = int((time.perf_counter() - started) * 1000)
        scan.retry_count += 1
        session.add(_event(scan.id, "scan.failed", str(exc)[:1000], payload={"code": str(code)}))


def _event(
    scan_id: uuid.UUID,
    event: str,
    message: str,
    *,
    actor: str = "worker",
    payload: dict[str, object] | None = None,
) -> AuditEvent:
    return AuditEvent(
        scan_id=scan_id, event=event, actor=actor, message=message, payload=payload or {}
    )
