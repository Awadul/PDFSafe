"""Scoring engine tests."""

from __future__ import annotations

import pytest

from pdfsafe.analysis.heuristics import (
    CRITICAL_FLOOR,
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    HeuristicEngine,
)
from pdfsafe.enums import Severity, Verdict, max_severity, worst_verdict
from pdfsafe.schemas.analysis import IndicatorResult


def indicator(
    weight: int, severity: Severity = Severity.MEDIUM, code: str = "TEST"
) -> IndicatorResult:
    return IndicatorResult(
        code=code, title="test indicator", severity=severity, weight=weight, category="test"
    )


class TestCombine:
    def test_no_indicators_scores_zero(self) -> None:
        assert HeuristicEngine.combine([]) == 0

    def test_single_indicator_matches_weight(self) -> None:
        assert HeuristicEngine.combine([indicator(30, Severity.MEDIUM)]) == 30

    def test_weak_signals_accumulate(self) -> None:
        """Independent weak signals should add up without a plain sum."""
        one = HeuristicEngine.combine([indicator(20, code="A")])
        three = HeuristicEngine.combine(
            [indicator(20, code="A"), indicator(20, code="B"), indicator(20, code="C")]
        )
        assert one < three < 60  # noisy-OR, not a sum

    def test_score_is_bounded(self) -> None:
        many = [indicator(90, Severity.HIGH, code=f"R{i}") for i in range(20)]
        assert 0 <= HeuristicEngine.combine(many) <= 100

    def test_critical_indicator_sets_floor(self) -> None:
        score = HeuristicEngine.combine([indicator(5, Severity.CRITICAL)])
        assert score >= CRITICAL_FLOOR

    def test_high_indicator_sets_lower_floor(self) -> None:
        score = HeuristicEngine.combine([indicator(5, Severity.HIGH)])
        assert 45 <= score < CRITICAL_FLOOR

    def test_ordering_is_monotonic(self) -> None:
        low = HeuristicEngine.combine([indicator(10, Severity.LOW)])
        mid = HeuristicEngine.combine([indicator(40, Severity.MEDIUM)])
        high = HeuristicEngine.combine([indicator(80, Severity.HIGH)])
        assert low < mid < high


class TestVerdictMapping:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0, Verdict.CLEAN),
            (19, Verdict.CLEAN),
            (20, Verdict.LOW_RISK),
            (49, Verdict.LOW_RISK),
            (SUSPICIOUS_THRESHOLD, Verdict.SUSPICIOUS),
            (79, Verdict.SUSPICIOUS),
            (MALICIOUS_THRESHOLD, Verdict.MALICIOUS),
            (100, Verdict.MALICIOUS),
        ],
    )
    def test_bands(self, score: int, expected: Verdict) -> None:
        assert HeuristicEngine.to_verdict(score, []) is expected


class TestEngine:
    def test_a_failing_rule_does_not_break_the_scan(self) -> None:
        def broken(_: object) -> list[IndicatorResult]:
            raise RuntimeError("rule exploded")

        def working(_: object) -> list[IndicatorResult]:
            return [indicator(40, Severity.MEDIUM, code="OK")]

        from pdfsafe.schemas.analysis import StaticAnalysisResult

        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=100)
        outcome = HeuristicEngine(rules=[broken, working]).evaluate(result)  # type: ignore[list-item]

        assert [i.code for i in outcome.indicators] == ["OK"]
        assert outcome.score == 40

    def test_duplicate_codes_are_collapsed(self) -> None:
        from pdfsafe.schemas.analysis import StaticAnalysisResult

        def twice(_: object) -> list[IndicatorResult]:
            return [indicator(30, code="DUP"), indicator(30, code="DUP")]

        result = StaticAnalysisResult(sha256="a" * 64, md5="b" * 32, file_size=100)
        outcome = HeuristicEngine(rules=[twice]).evaluate(result)  # type: ignore[list-item]
        assert len(outcome.indicators) == 1

    def test_top_indicators_sorted_by_weight(self) -> None:
        from pdfsafe.analysis.heuristics import HeuristicOutcome

        outcome = HeuristicOutcome(
            score=50,
            verdict=Verdict.SUSPICIOUS,
            indicators=[indicator(10, code="A"), indicator(90, code="B"), indicator(50, code="C")],
        )
        assert [i.code for i in outcome.top_indicators(2)] == ["B", "C"]


class TestEnumHelpers:
    def test_max_severity(self) -> None:
        assert max_severity([]) is Severity.INFO
        assert max_severity([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL

    def test_worst_verdict(self) -> None:
        assert worst_verdict(Verdict.CLEAN, Verdict.MALICIOUS) is Verdict.MALICIOUS
        assert worst_verdict(Verdict.SUSPICIOUS, Verdict.LOW_RISK) is Verdict.SUSPICIOUS

    def test_terminal_states(self) -> None:
        from pdfsafe.enums import ScanStatus

        assert ScanStatus.COMPLETED.is_terminal
        assert not ScanStatus.ANALYZING.is_terminal
