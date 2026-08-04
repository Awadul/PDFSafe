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


def outcome(score: int, *, critical: bool = False, corroborated: int = 0) -> HeuristicOutcome:
    """Build a scoring outcome.

    ``corroborated`` pads the indicator list. It matters because the escalation
    gate is evidence-aware: a high score resting on one or two findings is
    reviewed, a high score with several agreeing findings is not.
    """
    indicators = [
        IndicatorResult(
            code=f"PDF_CORROBORATING_{n}",
            title="corroborating finding",
            severity=Severity.MEDIUM,
            weight=30,
            category="active_content",
        )
        for n in range(corroborated)
    ]
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
        # Corroborated: several agreeing indicators is what genuine malware
        # looks like, and spending a token on it buys nothing. A high score on
        # *thin* evidence is escalated - see TestThinEvidenceEscalation.
        decision = should_escalate(
            outcome(settings.ai_escalate_max_score, corroborated=5), settings
        )
        assert not decision.escalate
        assert decision.reason == "above_escalation_threshold"
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


class TestThinEvidenceEscalation:
    """A high score built on one indicator is the least conclusive kind.

    Measured over 20,207 documents at the quarantine threshold:

        indicators |  false positives  |  true positives
        ---------- | ----------------- | ----------------
                 1 |         8         |        0
                 2 |         4         |        1
                 5 |        11         |    6,809

    No malware file in 11,106 reached 80 on a single indicator; eight ordinary
    documents did. The score-only gate refused to review any of them, because it
    treated a high number as settled regardless of what produced it.
    """

    def _outcome(self, score: int, indicators: int) -> HeuristicOutcome:
        return HeuristicOutcome(
            score=score,
            verdict=Verdict.MALICIOUS,
            indicators=[
                IndicatorResult(
                    code=f"PDF_TEST_{n}",
                    title="t",
                    severity=Severity.HIGH,
                    weight=50,
                    category="active_content",
                )
                for n in range(indicators)
            ],
            rationale=[],
        )

    def test_high_score_on_thin_evidence_is_reviewed(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", True)
        decision = should_escalate(self._outcome(95, indicators=1), settings)
        assert decision.escalate
        assert decision.reason == "high_score_thin_evidence"

    def test_high_score_on_corroborated_evidence_is_not(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        """Five agreeing indicators is what genuine malware looks like.

        Escalating these would spend tokens on 6,809 files to no purpose.
        """
        monkeypatch.setattr(settings, "ai_enabled", True)
        decision = should_escalate(self._outcome(95, indicators=5), settings)
        assert not decision.escalate
        assert decision.reason == "above_escalation_threshold"

    def test_the_rule_can_be_switched_off(
        self, settings: Any, monkeypatch: pytest.MonkeyPatch, stub_provider: Any
    ) -> None:
        monkeypatch.setattr(settings, "ai_enabled", True)
        monkeypatch.setattr(settings, "ai_escalate_thin_evidence_max", 0)
        assert not should_escalate(self._outcome(95, indicators=1), settings).escalate


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


class TestAnchoring:
    """The prompt must not hand the model the answer it is checking."""

    def test_heuristic_score_is_withheld_by_default(self) -> None:
        from pdfsafe.ai.prompts import build_user_prompt

        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=1)
        prompt = build_user_prompt(build_evidence(result, outcome(93)))

        assert "93" not in prompt
        assert "pre-assessment" not in prompt.lower()

    def test_sharing_can_be_re_enabled_for_comparison(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pdfsafe.ai import prompts
        from pdfsafe.config import get_settings

        settings = get_settings()
        monkeypatch.setattr(settings, "ai_share_heuristic_score", True)
        monkeypatch.setattr(prompts, "get_settings", lambda: settings)

        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=1)
        prompt = prompts.build_user_prompt(build_evidence(result, outcome(93)))

        assert "93/100" in prompt


class TestTruncatedResponseDiagnosis:
    """A thinking model that exhausts its budget returns an empty message.

    That is indistinguishable at the parser from malformed output, and the
    obvious reading - "loosen the JSON parsing" - is wrong: there is no text to
    parse. Roughly a fifth of one benchmark run was lost to this while the error
    message pointed at the parser. These tests keep the diagnosis attached to
    the cause.
    """

    @staticmethod
    def _response(**over: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "choices": [{"finish_reason": "length", "message": {"content": ""}}],
            "usage": {"completion_tokens_details": {"reasoning_tokens": 2048}},
        }
        base.update(over)
        return base

    def test_truncation_blames_the_budget_not_the_parser(self) -> None:
        from pdfsafe.ai.custom_provider import CustomOpenAICompatibleProvider
        from pdfsafe.exceptions import AIResponseError

        with pytest.raises(AIResponseError) as caught:
            CustomOpenAICompatibleProvider._extract_payload(self._response())

        message = str(caught.value)
        assert "truncated" in message
        assert "2048 tokens reasoning" in message
        assert "JSON" not in message, "must not send the reader to the parser"

    def test_content_filter_is_reported_as_itself(self) -> None:
        from pdfsafe.ai.custom_provider import CustomOpenAICompatibleProvider
        from pdfsafe.exceptions import AIResponseError

        response = self._response(
            choices=[{"finish_reason": "content_filter", "message": {"content": ""}}]
        )
        with pytest.raises(AIResponseError, match="content filter"):
            CustomOpenAICompatibleProvider._extract_payload(response)

    def test_truncation_is_ignored_when_the_verdict_survived(self) -> None:
        """finish_reason=length with usable content is not an error."""
        from pdfsafe.ai.custom_provider import CustomOpenAICompatibleProvider

        response = self._response(
            choices=[
                {
                    "finish_reason": "length",
                    "message": {"content": '{"verdict": "clean", "risk_score": 10}'},
                }
            ]
        )
        assert CustomOpenAICompatibleProvider._extract_payload(response)["verdict"] == "clean"

    @pytest.mark.parametrize(
        ("body", "exhausted"),
        [
            ('{"error": {"message": "You exceeded your current quota"}}', True),
            ('{"error": {"code": "insufficient_quota"}}', True),
            ('{"error": {"message": "Rate limit reached, retry in 20s"}}', False),
            ('{"error": {"message": "Too many concurrent requests"}}', False),
            # Groq appends an upgrade link to ordinary per-minute limits. The
            # word "billing" in a URL is not a claim about the account.
            (
                '{"error":{"message":"Rate limit reached on tokens per minute (TPM): '
                'Limit 8000. Upgrade at https://console.groq.com/settings/billing"}}',
                False,
            ),
        ],
    )
    def test_quota_exhaustion_is_not_treated_as_a_rate_limit(
        self, body: str, exhausted: bool
    ) -> None:
        """Backing off fixes a rate limit and wastes a spent quota."""
        from pdfsafe.ai.custom_provider import _quota_exhausted

        assert _quota_exhausted(body) is exhausted

    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504, 529])
    def test_transient_statuses_are_retryable(self, status: int) -> None:
        """529 is non-standard, so it was missing - and every one failed once."""
        from pdfsafe.ai.custom_provider import _RETRYABLE_STATUS

        assert status in _RETRYABLE_STATUS

    def test_reasoning_is_disabled_by_default(self) -> None:
        """The default must suppress thinking, or the failure returns silently."""
        from pdfsafe.ai.custom_provider import CustomOpenAICompatibleProvider

        provider = CustomOpenAICompatibleProvider(base_url="https://x/v1", model="m")
        assert provider.reasoning_effort == "none"

    def test_unsupported_reasoning_effort_is_dropped_and_retried(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Endpoints that reject the field must still work without operator setup.

        gpt-4o rejects reasoning_effort outright while Gemini needs it. Requiring
        the operator to know which is which means every call fails when they
        guess wrong - and PowerShell deletes an environment variable assigned an
        empty string, so guessing wrong is easy.
        """
        from pdfsafe.ai.custom_provider import CustomOpenAICompatibleProvider
        from pdfsafe.exceptions import AIResponseError

        provider = CustomOpenAICompatibleProvider(
            base_url="https://x/v1", model="gpt-4o-mini", reasoning_effort="none"
        )
        seen: list[dict[str, Any]] = []

        def fake_post(body: dict[str, Any]) -> dict[str, Any]:
            seen.append(dict(body))
            if "reasoning_effort" in body:
                raise AIResponseError(
                    "Endpoint returned 400: Unrecognized request argument "
                    "supplied: reasoning_effort"
                )
            message = {"content": '{"verdict": "clean"}'}
            return {
                "choices": [{"finish_reason": "stop", "message": message}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }

        monkeypatch.setattr(provider, "_post", fake_post)
        payload, _ = provider._invoke("system", "user")

        assert payload["verdict"] == "clean"
        assert len(seen) == 2, "should retry exactly once, without the field"
        assert "reasoning_effort" in seen[0]
        assert "reasoning_effort" not in seen[1]
        assert provider.reasoning_effort == "", "must remember, not relearn per call"
