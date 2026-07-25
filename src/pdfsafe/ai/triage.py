"""Triage orchestration: decide whether to call the LLM, then fuse the verdicts.

Cost model
----------
Heuristics run on every file and are free. The LLM is consulted only for files
that land in the *ambiguous band* between ``ai_escalate_min_score`` and
``ai_escalate_max_score``:

    score < min      -> clean/low-risk, decided by heuristics       (no LLM)
    min <= score < max -> ambiguous, escalated to the LLM           (LLM call)
    score >= max     -> conclusive, decided by heuristics           (no LLM)

In practice the overwhelming majority of real-world traffic is ordinary
documents that score near zero, so the LLM is reserved for the cases where its
judgement actually changes the outcome. Set ``ai_always_escalate=true`` to
disable the gate (useful when tuning thresholds against a labelled corpus).
"""

from __future__ import annotations

from dataclasses import dataclass

from pdfsafe.ai import budget
from pdfsafe.ai.evidence import build_evidence
from pdfsafe.ai.registry import get_provider
from pdfsafe.analysis.heuristics import HeuristicOutcome
from pdfsafe.config import Settings, get_settings
from pdfsafe.enums import DecisionSource, Severity, Verdict, worst_verdict
from pdfsafe.logging import get_logger
from pdfsafe.metrics import ai_skipped_total
from pdfsafe.schemas.ai import AICallResult
from pdfsafe.schemas.analysis import StaticAnalysisResult

logger = get_logger(__name__)

#: How much the LLM's score counts relative to the heuristic score.
AI_SCORE_WEIGHT = 0.6


@dataclass(slots=True)
class EscalationDecision:
    """Whether to spend tokens on this file, and why."""

    escalate: bool
    reason: str

    def __bool__(self) -> bool:
        return self.escalate


@dataclass(slots=True)
class TriageResult:
    """Final decision for a scan."""

    verdict: Verdict
    risk_score: int
    confidence: float | None
    decided_by: DecisionSource
    summary: str
    ai_call: AICallResult | None = None
    escalation: EscalationDecision | None = None

    @property
    def used_ai(self) -> bool:
        return self.ai_call is not None and self.ai_call.succeeded


def should_escalate(
    outcome: HeuristicOutcome,
    settings: Settings | None = None,
) -> EscalationDecision:
    """Apply the cost gate."""
    settings = settings or get_settings()

    if not settings.ai_enabled:
        return EscalationDecision(False, "ai_disabled")

    provider = get_provider()
    if provider.name == "null":
        return EscalationDecision(False, "no_provider_configured")

    if not budget.has_budget():
        return EscalationDecision(False, "budget_exhausted")

    if settings.ai_always_escalate:
        return EscalationDecision(True, "always_escalate")

    if outcome.score < settings.ai_escalate_min_score:
        return EscalationDecision(False, "below_escalation_threshold")

    if outcome.score >= settings.ai_escalate_max_score:
        return EscalationDecision(False, "above_escalation_threshold")

    return EscalationDecision(True, "ambiguous_band")


def triage(
    result: StaticAnalysisResult,
    outcome: HeuristicOutcome,
    *,
    settings: Settings | None = None,
    force_ai: bool = False,
) -> TriageResult:
    """Produce the final verdict, consulting the LLM only when it is worth it."""
    settings = settings or get_settings()

    decision = (
        EscalationDecision(True, "forced") if force_ai else should_escalate(outcome, settings)
    )

    if not decision.escalate:
        ai_skipped_total.labels(reason=decision.reason).inc()
        logger.info(
            "ai_skipped",
            reason=decision.reason,
            heuristic_score=outcome.score,
            verdict=outcome.verdict.value,
        )
        return TriageResult(
            verdict=outcome.verdict,
            risk_score=outcome.score,
            confidence=_heuristic_confidence(outcome),
            decided_by=DecisionSource.HEURISTICS,
            summary=_heuristic_summary(outcome, decision.reason),
            escalation=decision,
        )

    provider = get_provider()
    evidence = build_evidence(result, outcome, max_chars=settings.ai_max_evidence_chars)
    call = provider.assess(evidence)

    budget.record_usage(call.total_tokens)

    if not call.succeeded or call.verdict is None:
        logger.warning(
            "ai_triage_failed_falling_back",
            provider=call.provider,
            error=call.error_message,
            heuristic_score=outcome.score,
        )
        return TriageResult(
            verdict=outcome.verdict,
            risk_score=outcome.score,
            confidence=_heuristic_confidence(outcome),
            decided_by=DecisionSource.HEURISTICS,
            summary=(
                f"{_heuristic_summary(outcome, 'ai_unavailable')} "
                f"AI review was unavailable ({call.error_message})."
            ),
            ai_call=call,
            escalation=decision,
        )

    return _fuse(outcome, call, decision)


# ---------------------------------------------------------------------------
# Fusion
# ---------------------------------------------------------------------------
def _fuse(
    outcome: HeuristicOutcome,
    call: AICallResult,
    decision: EscalationDecision,
) -> TriageResult:
    """Combine the heuristic and AI judgements.

    The AI leads, because it sees the same evidence with more context. Two
    guard rails apply:

    * A ``CRITICAL`` heuristic indicator (embedded executable, /Launch action,
      known exploit API) sets a floor of ``suspicious`` - the model may not
      clear a file that demonstrably carries a weapon.
    * The blended score keeps 40% of the heuristic weight so a confidently wrong
      model cannot drag a heavily-indicated file to zero.
    """
    assert call.verdict is not None  # guarded by the caller
    ai = call.verdict

    blended = int(round(AI_SCORE_WEIGHT * ai.risk_score + (1 - AI_SCORE_WEIGHT) * outcome.score))

    verdict = ai.verdict
    has_critical = any(i.severity is Severity.CRITICAL for i in outcome.indicators)
    if has_critical:
        verdict = worst_verdict(verdict, Verdict.SUSPICIOUS)
        blended = max(blended, 60)

    summary = ai.summary.strip() or _heuristic_summary(outcome, decision.reason)
    if verdict is not ai.verdict:
        summary += (
            " Verdict raised to at least 'suspicious' because static analysis found a "
            "critical indicator."
        )

    logger.info(
        "triage_complete",
        decided_by="hybrid",
        heuristic_score=outcome.score,
        ai_score=ai.risk_score,
        final_score=blended,
        heuristic_verdict=outcome.verdict.value,
        ai_verdict=ai.verdict.value,
        final_verdict=verdict.value,
    )

    return TriageResult(
        verdict=verdict,
        risk_score=blended,
        confidence=ai.confidence,
        decided_by=DecisionSource.HYBRID,
        summary=summary,
        ai_call=call,
        escalation=decision,
    )


def _heuristic_confidence(outcome: HeuristicOutcome) -> float:
    """Confidence proxy: extreme scores are more trustworthy than mid-band ones."""
    distance = abs(outcome.score - 50) / 50
    return round(0.5 + 0.4 * distance, 3)


def _heuristic_summary(outcome: HeuristicOutcome, reason: str) -> str:
    if not outcome.indicators:
        return (
            "No suspicious structures were found: no embedded scripts, automatic actions, "
            "attachments or high-risk links."
        )
    top = outcome.top_indicators(3)
    joined = "; ".join(f"{i.title.lower()}" for i in top)
    extra = len(outcome.indicators) - len(top)
    tail = f" (+{extra} further indicator{'s' if extra != 1 else ''})" if extra > 0 else ""
    prefix = {
        "above_escalation_threshold": "Static analysis is conclusive",
        "below_escalation_threshold": "Static analysis found only minor traits",
        "ai_disabled": "AI review is disabled; static analysis found",
        "no_provider_configured": "No AI provider is configured; static analysis found",
        "budget_exhausted": "AI budget exhausted; static analysis found",
    }.get(reason, "Static analysis found")
    return f"{prefix}: {joined}{tail}."
