"""Synchronous data access for the desktop build."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, selectinload

from pdfsafe.analysis.heuristics import HeuristicOutcome
from pdfsafe.analysis.pipeline import AnalysisOutput
from pdfsafe.db.models import AIAssessment, AnalysisReport, AuditEvent, Indicator, Scan
from pdfsafe.enums import DecisionSource, ScanStatus, UploadSource, Verdict
from pdfsafe.exceptions import ScanNotFoundError
from pdfsafe.logging import get_logger
from pdfsafe.schemas.scan import ScanStats

logger = get_logger(__name__)


class ScanRepository:
    """CRUD operations over a single :class:`~sqlalchemy.orm.Session`."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # -------------------------------------------------------------- create --
    def create(
        self,
        *,
        filename: str,
        file_size: int,
        sha256: str,
        md5: str,
        storage_key: str,
        source: UploadSource = UploadSource.DASHBOARD,
        content_type: str | None = "application/pdf",
        origin_path: str | None = None,
    ) -> Scan:
        scan = Scan(
            filename=filename[:512],
            content_type=content_type,
            file_size=file_size,
            sha256=sha256,
            md5=md5,
            storage_key=storage_key,
            source=source,
            status=ScanStatus.PENDING,
            extra={"origin_path": origin_path} if origin_path else {},
        )
        self.session.add(scan)
        self.session.flush()
        self.add_event(scan.id, "scan.submitted", f"{filename} queued for analysis")
        return scan

    # ---------------------------------------------------------------- read --
    def get(self, scan_id: uuid.UUID, *, detail: bool = False) -> Scan:
        statement = select(Scan).where(Scan.id == scan_id)
        if detail:
            statement = statement.options(
                selectinload(Scan.indicators),
                selectinload(Scan.ai_assessments),
                selectinload(Scan.report),
            )
        scan = self.session.execute(statement).scalar_one_or_none()
        if scan is None:
            raise ScanNotFoundError(f"Scan {scan_id} does not exist", scan_id=str(scan_id))
        return scan

    def find(self, scan_id: uuid.UUID, *, detail: bool = False) -> Scan | None:
        try:
            return self.get(scan_id, detail=detail)
        except ScanNotFoundError:
            return None

    def recent(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        verdict: Verdict | None = None,
        status: ScanStatus | None = None,
        search: str | None = None,
    ) -> list[Scan]:
        statement = select(Scan)
        if verdict is not None:
            statement = statement.where(Scan.verdict == verdict)
        if status is not None:
            statement = statement.where(Scan.status == status)
        if search:
            statement = statement.where(Scan.filename.ilike(f"%{search}%"))
        statement = statement.order_by(Scan.created_at.desc()).limit(limit).offset(offset)
        return list(self.session.execute(statement).scalars().all())

    def count(self) -> int:
        return int(self.session.execute(select(func.count(Scan.id))).scalar_one())

    def find_completed_by_hash(self, sha256: str) -> Scan | None:
        statement = (
            select(Scan)
            .where(
                Scan.sha256 == sha256,
                Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.QUARANTINED]),
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        return self.session.execute(statement).scalar_one_or_none()

    def pending(self) -> list[Scan]:
        statement = select(Scan).where(
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.ANALYZING, ScanStatus.AI_REVIEW])
        )
        return list(self.session.execute(statement).scalars().all())

    def stats(self) -> ScanStats:
        since = datetime.now(UTC) - timedelta(hours=24)
        total = self.count()

        by_status = {
            str(status.value): int(count)
            for status, count in self.session.execute(
                select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
            ).all()
        }
        by_verdict = {
            str(verdict.value): int(count)
            for verdict, count in self.session.execute(
                select(Scan.verdict, func.count(Scan.id)).group_by(Scan.verdict)
            ).all()
        }
        scanned_24h = int(
            self.session.execute(
                select(func.count(Scan.id)).where(Scan.created_at >= since)
            ).scalar_one()
        )
        malicious_24h = int(
            self.session.execute(
                select(func.count(Scan.id)).where(
                    Scan.created_at >= since, Scan.verdict == Verdict.MALICIOUS
                )
            ).scalar_one()
        )
        avg_duration = self.session.execute(
            select(func.avg(Scan.duration_ms)).where(Scan.status == ScanStatus.COMPLETED)
        ).scalar_one()
        ai_calls = int(
            self.session.execute(
                select(func.count(AIAssessment.id)).where(AIAssessment.created_at >= since)
            ).scalar_one()
        )

        return ScanStats(
            total=total,
            by_status=by_status,
            by_verdict=by_verdict,
            scanned_last_24h=scanned_24h,
            malicious_last_24h=malicious_24h,
            avg_duration_ms=float(avg_duration) if avg_duration is not None else None,
            ai_calls_last_24h=ai_calls,
        )

    # -------------------------------------------------------------- update --
    def mark_analyzing(self, scan_id: uuid.UUID) -> None:
        scan = self.get(scan_id)
        scan.status = ScanStatus.ANALYZING
        scan.started_at = datetime.now(UTC)

    def mark_ai_review(self, scan_id: uuid.UUID) -> None:
        scan = self.get(scan_id)
        scan.status = ScanStatus.AI_REVIEW

    def save_result(
        self,
        scan_id: uuid.UUID,
        analysis: AnalysisOutput,
        decision: Any,
        *,
        duration_ms: int,
        quarantined: bool = False,
        quarantine_details: dict[str, Any] | None = None,
    ) -> Scan:
        """Persist the analysis report, indicators, AI assessment and verdict."""
        scan = self.get(scan_id)
        result = analysis.result

        self._replace_report(scan, analysis)
        self._replace_indicators(scan, analysis.outcome)

        if getattr(decision, "ai_call", None) is not None:
            self.session.add(_assessment_row(scan.id, decision))

        scan.status = ScanStatus.QUARANTINED if quarantined else ScanStatus.COMPLETED
        scan.verdict = decision.verdict
        scan.risk_score = decision.risk_score
        scan.confidence = decision.confidence
        scan.decided_by = decision.decided_by
        scan.summary = (decision.summary or "")[:4000]
        scan.completed_at = datetime.now(UTC)
        scan.duration_ms = duration_ms
        scan.quarantined = quarantined
        scan.error_code = None
        scan.error_message = None
        scan.md5 = scan.md5 or result.md5
        scan.extra = {
            **(scan.extra or {}),
            "heuristic_score": analysis.outcome.score,
            "heuristic_verdict": analysis.outcome.verdict.value,
            "escalation_reason": (
                decision.escalation.reason if getattr(decision, "escalation", None) else None
            ),
            "analyzer_version": result.analyzer_version,
            **(quarantine_details or {}),
        }

        self.add_event(
            scan.id,
            "scan.completed",
            f"Verdict: {decision.verdict.value} ({decision.risk_score}/100)",
            payload={
                "verdict": decision.verdict.value,
                "risk_score": decision.risk_score,
                "decided_by": decision.decided_by.value,
                "duration_ms": duration_ms,
            },
        )
        return scan

    def mark_failed(self, scan_id: uuid.UUID, code: str, message: str) -> None:
        scan = self.find(scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.FAILED
        scan.verdict = Verdict.UNKNOWN
        scan.decided_by = DecisionSource.ERROR
        scan.error_code = code[:64]
        scan.error_message = message[:4000]
        scan.completed_at = datetime.now(UTC)
        scan.retry_count += 1
        self.add_event(scan.id, "scan.failed", message[:1000], payload={"code": code})

    def set_review(
        self, scan_id: uuid.UUID, verdict: Verdict, note: str = "", actor: str = "user"
    ) -> Scan:
        scan = self.get(scan_id, detail=True)
        previous = scan.verdict
        scan.verdict = verdict
        scan.reviewed = True
        scan.review_note = note or None
        scan.decided_by = DecisionSource.MANUAL
        if verdict is Verdict.CLEAN:
            scan.quarantined = False
        self.add_event(
            scan.id,
            "scan.reviewed",
            note or f"Verdict changed to {verdict.value}",
            actor=actor,
            payload={"from": previous.value, "to": verdict.value},
        )
        return scan

    def reset_for_rescan(self, scan_id: uuid.UUID) -> Scan:
        scan = self.get(scan_id)
        scan.status = ScanStatus.PENDING
        scan.error_code = None
        scan.error_message = None
        scan.started_at = None
        scan.completed_at = None
        return scan

    # -------------------------------------------------------------- delete --
    def delete(self, scan_id: uuid.UUID) -> None:
        scan = self.find(scan_id)
        if scan is not None:
            self.session.delete(scan)

    def prune(self, keep: int) -> list[str]:
        """Trim history to the newest ``keep`` rows.

        Returns the storage keys that no surviving scan references any more, so
        the caller can delete the blobs. Without this the database self-trims
        while disk usage grows without bound - deduplication means several rows
        can share one key, so a blob is only orphaned once every row pointing at
        it is gone.
        """
        if keep <= 0:
            return []
        if self.count() <= keep:
            return []

        cutoff = self.session.execute(
            select(Scan.created_at).order_by(Scan.created_at.desc()).limit(1).offset(keep - 1)
        ).scalar_one_or_none()
        if cutoff is None:
            return []

        condition = (Scan.created_at < cutoff, Scan.quarantined.is_(False))

        doomed_keys = set(
            self.session.execute(select(Scan.storage_key).where(*condition)).scalars().all()
        )
        if not doomed_keys:
            return []

        res = self.session.execute(
            delete(Scan).where(*condition).execution_options(synchronize_session=False)
        )
        removed = getattr(res, "rowcount", 0)
        self.session.flush()

        # Whatever keys are still attached to a surviving row must be kept. Read
        # them all rather than filtering by the doomed set: history is bounded by
        # ``keep``, so this is cheap, and it cannot go wrong the way an IN clause
        # over a large key set can.
        surviving = set(self.session.execute(select(Scan.storage_key)).scalars().all())
        orphaned = sorted(doomed_keys - surviving)

        logger.info("history_pruned", removed=int(removed or 0), keep=keep, orphaned=len(orphaned))
        return orphaned

    def fail_stale(self, older_than: timedelta) -> int:
        """Fail scans left non-terminal by a crash or forced shutdown."""
        cutoff = datetime.now(UTC) - older_than
        stale = (
            self.session.execute(
                select(Scan).where(
                    Scan.status.in_(
                        [ScanStatus.PENDING, ScanStatus.ANALYZING, ScanStatus.AI_REVIEW]
                    ),
                    Scan.created_at < cutoff,
                )
            )
            .scalars()
            .all()
        )
        for scan in stale:
            scan.status = ScanStatus.FAILED
            scan.verdict = Verdict.UNKNOWN
            scan.error_code = "interrupted"
            scan.error_message = "Analysis was interrupted before it completed"
            scan.completed_at = datetime.now(UTC)
        return len(stale)

    # -------------------------------------------------------------- events --
    def add_event(
        self,
        scan_id: uuid.UUID | None,
        event: str,
        message: str,
        *,
        actor: str = "desktop",
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.session.add(
            AuditEvent(
                scan_id=scan_id,
                event=event,
                actor=actor,
                message=message,
                payload=payload or {},
            )
        )

    # ------------------------------------------------------------ internals --
    def _replace_report(self, scan: Scan, analysis: AnalysisOutput) -> None:
        result = analysis.result
        existing = self.session.execute(
            select(AnalysisReport).where(AnalysisReport.scan_id == scan.id)
        ).scalar_one_or_none()
        if existing is not None:
            self.session.delete(existing)
            self.session.flush()

        self.session.add(
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

    def _replace_indicators(self, scan: Scan, outcome: HeuristicOutcome) -> None:
        self.session.execute(delete(Indicator).where(Indicator.scan_id == scan.id))
        self.session.flush()
        for indicator in outcome.indicators:
            self.session.add(
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


def _assessment_row(scan_id: uuid.UUID, decision: Any) -> AIAssessment:
    call = decision.ai_call
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
