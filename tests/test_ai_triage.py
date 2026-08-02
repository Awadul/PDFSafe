"""AI escalation gate, evidence packaging and verdict fusion tests."""

from __future__ import annotations

from typing import Any

import pytest

from pdfsafe.ai.evidence import build_evidence
from pdfsafe.ai.triage import should_escalate, triage
from pdfsafe.analysis.heuristics import HeuristicOutcome
from pdfsafe.analysis.pipeline import analyze_bytes
from pdfsafe.enums import DecisionSource, Severity, Verdict
from pdfsafe.schemas.ai import AIVerdict
from pdfsafe.schemas.analysis import IndicatorResult, StaticAnalysisResult


def outcome(score: int, *, critical: bool = False) -> HeuristicOutcome:
    indicators = []
    if critical:
        indicators.append(
            IndicatorResult(
                code="PDF_LAUNCH_ACTION",
                title="launch action",
                severity=Severity.CRITICAL,
                weight=85,
                category="active_content",
            )
        )
    return HeuristicOutcome(
        score=score, verdict=Verdict.SUSPICIOUS, indicators=indicators, rationale=[]
    )


class TestEscalationGate:
    def test_disabled_ai_never_escalates(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", False)
        decision = should_escalate(outcome(50), settings)
        assert not decision.escalate
        assert decision.reason == "ai_disabled"

    def test_low_score_is_not_escalated(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", True)
        decision = should_escalate(outcome(settings.ai_escalate_min_score - 1), settings)
        assert not decision.escalate
        assert decision.reason == "below_escalation_threshold"

    def test_high_score_is_not_escalated(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", True)
        decision = should_escalate(outcome(settings.ai_escalate_max_score), settings)
        assert not decision.escalate
        assert decision.reason == "above_escalation_threshold"

    def test_ambiguous_band_is_escalated(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", True)
        midpoint = (settings.ai_escalate_min_score + settings.ai_escalate_max_score) // 2
        decision = should_escalate(outcome(midpoint), settings)
        assert decision.escalate
        assert decision.reason == "ambiguous_band"

    def test_always_escalate_overrides_bands(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", True)
        monkeypatch.setattr(settings, "ai_always_escalate", True)
        assert should_escalate(outcome(0), settings).escalate


class TestTriage:
    def test_heuristics_only_when_gate_closed(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", False)
        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=1)
        decision = triage(result, outcome(10), settings=settings)
        assert decision.decided_by is DecisionSource.HEURISTICS
        assert decision.ai_call is None

    def test_ai_leads_the_score_when_consulted(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        """The model leads the *score*; the label is derived from it.

        This previously asserted the final verdict equalled the model's label.
        It no longer can: the model scores 90 and the heuristics 50, so the
        blend is 74 and 74 is 'suspicious'. Reporting 'malicious' next to 74
        would be exactly the inconsistency this fusion now prevents.
        """
        monkeypatch.setattr(settings, "ai_enabled", True)
        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=1)
        decision = triage(result, outcome(50), settings=settings, force_ai=True)

        assert decision.decided_by is DecisionSource.HYBRID
        assert stub_provider.calls, "the provider should have been consulted"
        # The model scored 90 against the heuristic 50, so it pulled the result up.
        assert decision.risk_score > 50
        assert decision.verdict is Verdict.SUSPICIOUS

    @pytest.mark.parametrize(
        ("ai_verdict", "ai_score", "heuristic_score"),
        [
            ("malicious", 90, 50),
            ("malicious", 85, 10),
            ("clean", 5, 45),
            ("suspicious", 60, 70),
            ("low_risk", 30, 20),
            ("unknown", 50, 50),
        ],
    )
    def test_verdict_always_matches_the_score(
        self,
        settings: Any,
        monkeypatch: pytest.MonkeyPatch,
        stub_provider: Any,
        ai_verdict: str,
        ai_score: int,
        heuristic_score: int,
    ) -> None:
        """The invariant the fusion bug broke.

        PDFSafe once reported one file as 'malicious' at 64/100 and another as
        'suspicious' at 70/100, because the label came from the model and the
        number from a blend with nothing connecting them. The score is what the
        interface shows in large type and what the history sorts by, and
        quarantine keys off the verdict - so the two disagreeing meant the
        visible number told users nothing about what the app would do.
        """
        from pdfsafe.analysis.heuristics import HeuristicEngine

        monkeypatch.setattr(settings, "ai_enabled", True)
        stub_provider._verdict = ai_verdict
        stub_provider._risk_score = ai_score

        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=1)
        decision = triage(result, outcome(heuristic_score), settings=settings, force_ai=True)

        assert decision.verdict is HeuristicEngine.to_verdict(decision.risk_score, [])

    def test_reconcile_moves_the_score_into_the_labelled_band(self) -> None:
        """A provider can return a label and a number that contradict each other.

        Nothing in AIVerdict prevents it - the fields validate independently.
        The label wins, because a model picks a category far more reliably than
        it emits a calibrated number.
        """
        from pdfsafe.ai.triage import _reconcile_ai_score

        contradictory = AIVerdict(verdict="malicious", risk_score=10, confidence=0.9, summary="x")
        assert _reconcile_ai_score(contradictory) == 80

        also_contradictory = AIVerdict(verdict="clean", risk_score=95, confidence=0.9, summary="x")
        assert _reconcile_ai_score(also_contradictory) == 19

        coherent = AIVerdict(verdict="suspicious", risk_score=65, confidence=0.9, summary="x")
        assert _reconcile_ai_score(coherent) == 65

    def test_critical_indicator_blocks_a_clean_ai_verdict(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        """The model may not clear a file that carries a critical indicator."""
        monkeypatch.setattr(settings, "ai_enabled", True)
        stub_provider._verdict = "clean"
        stub_provider._risk_score = 5

        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=1)
        decision = triage(result, outcome(60, critical=True), settings=settings, force_ai=True)

        assert decision.verdict is not Verdict.CLEAN
        assert decision.risk_score >= 60

    def test_provider_failure_falls_back_to_heuristics(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        from pdfsafe.schemas.ai import AICallResult

        monkeypatch.setattr(settings, "ai_enabled", True)
        monkeypatch.setattr(
            stub_provider,
            "assess",
            lambda evidence: AICallResult(
                provider="stub", model="stub", succeeded=False, error_message="boom"
            ),
        )

        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=1)
        decision = triage(result, outcome(55), settings=settings, force_ai=True)

        assert decision.decided_by is DecisionSource.HEURISTICS
        assert "unavailable" in decision.summary.lower()

    def test_blended_score_keeps_heuristic_weight(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", True)
        stub_provider._risk_score = 100
        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=1)
        decision = triage(result, outcome(0), settings=settings, force_ai=True)
        assert decision.risk_score < 100  # heuristics still count


class TestEvidence:
    def test_bundle_respects_char_budget(self, pdfs: Any) -> None:
        analysis = analyze_bytes(pdfs.openaction_js_pdf(), filename="evil.pdf")
        bundle = build_evidence(analysis.result, analysis.outcome, max_chars=2000)
        assert len(bundle.model_dump_json()) < 12_000
        assert bundle.heuristic_score == analysis.outcome.score

    def test_long_script_is_truncated_and_noted(self, pdfs: Any) -> None:
        analysis = analyze_bytes(
            pdfs.openaction_js_pdf("var payload = '" + "A" * 20000 + "';"), filename="big.pdf"
        )
        bundle = build_evidence(analysis.result, analysis.outcome, max_chars=4000)
        assert bundle.truncation_notes
        assert any("truncated" in note for note in bundle.truncation_notes)

    def test_raw_bytes_are_never_included(self, pdfs: Any) -> None:
        analysis = analyze_bytes(pdfs.embedded_executable_pdf(), filename="exe.pdf")
        bundle = build_evidence(analysis.result, analysis.outcome)
        serialised = bundle.model_dump_json()
        assert "MZ\\x90" not in serialised

    def test_risky_urls_are_prioritised(self, pdfs: Any) -> None:
        analysis = analyze_bytes(pdfs.phishing_pdf(), filename="phish.pdf")
        bundle = build_evidence(analysis.result, analysis.outcome)
        assert bundle.urls
        assert "ip_literal" in bundle.urls[0]["flags"]


class TestAIVerdictSchema:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("benign", Verdict.CLEAN),
            ("MALWARE", Verdict.MALICIOUS),
            ("potentially malicious", Verdict.SUSPICIOUS),
            ("low", Verdict.LOW_RISK),
            ("inconclusive", Verdict.UNKNOWN),
        ],
    )
    def test_verdict_aliases(self, raw: str, expected: Verdict) -> None:
        verdict = AIVerdict(verdict=raw, risk_score=50, confidence=0.5, summary="x")
        assert verdict.verdict is expected

    def test_risk_score_is_clamped(self) -> None:
        assert (
            AIVerdict(verdict="clean", risk_score=500, confidence=0.5, summary="x").risk_score
            == 100
        )
        assert (
            AIVerdict(verdict="clean", risk_score=-20, confidence=0.5, summary="x").risk_score == 0
        )

    def test_schema_is_tool_ready(self) -> None:
        from pdfsafe.ai.prompts import tool_definition

        definition = tool_definition()
        assert definition["name"] == "submit_pdf_verdict"
        assert "verdict" in definition["input_schema"]["properties"]
