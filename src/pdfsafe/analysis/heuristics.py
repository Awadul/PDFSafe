"""Heuristic scoring engine.

The engine turns a :class:`StaticAnalysisResult` into a list of indicators and
a 0-100 risk score. It runs *before* the LLM and, for clearly benign or clearly
malicious files, decides on its own - which is what keeps token spend low.

Scoring model
-------------
Weights are combined with a *noisy-OR* rather than a plain sum::

    score = 100 * (1 - PROD(1 - w_i / 100))

Independent weak signals therefore accumulate without a handful of them
saturating the scale, and no single rule can push the score to 100 unless it is
genuinely conclusive. A ``CRITICAL`` indicator additionally imposes a floor.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from pdfsafe.analysis import javascript as js_analysis
from pdfsafe.analysis import urls as url_analysis
from pdfsafe.analysis.constants import (
    ARCHIVE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    HIGH_ENTROPY_THRESHOLD,
    LARGE_TRAILING_BYTES,
    MANY_INCREMENTAL_UPDATES,
    OFFICE_MACRO_EXTENSIONS,
)
from pdfsafe.enums import Severity, Verdict
from pdfsafe.schemas.analysis import IndicatorResult, StaticAnalysisResult

# --------------------------------------------------------------------------
# Verdict bands
# --------------------------------------------------------------------------
MALICIOUS_THRESHOLD = 80
SUSPICIOUS_THRESHOLD = 50
LOW_RISK_THRESHOLD = 20

#: A single CRITICAL finding cannot score below this.
CRITICAL_FLOOR = 75
HIGH_FLOOR = 45


@dataclass(slots=True)
class HeuristicOutcome:
    """Output of the scoring pass."""

    score: int
    verdict: Verdict
    indicators: list[IndicatorResult] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)

    @property
    def is_conclusive_clean(self) -> bool:
        return self.verdict is Verdict.CLEAN and not self.indicators

    def top_indicators(self, limit: int = 10) -> list[IndicatorResult]:
        return sorted(self.indicators, key=lambda i: i.weight, reverse=True)[:limit]


RuleFn = Callable[[StaticAnalysisResult], Iterable[IndicatorResult]]
_RULES: list[RuleFn] = []


def rule(func: RuleFn) -> RuleFn:
    """Register a heuristic rule."""
    _RULES.append(func)
    return func


def _indicator(
    code: str,
    title: str,
    severity: Severity,
    weight: int,
    category: str,
    description: str = "",
    mitre: str | None = None,
    **evidence: Any,
) -> IndicatorResult:
    return IndicatorResult(
        code=code,
        title=title,
        description=description,
        severity=severity,
        weight=weight,
        category=category,
        mitre_technique=mitre,
        evidence=evidence,
    )


# ===========================================================================
# Rules: active content
# ===========================================================================
@rule
def r_javascript_present(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    if not result.javascript:
        return
    total = js_analysis.total_js_length(result.javascript)
    yield _indicator(
        "PDF_JS_PRESENT",
        "Document contains embedded JavaScript",
        Severity.MEDIUM,
        30,
        "active_content",
        "JavaScript is legitimate in forms but is the primary delivery mechanism "
        "for PDF-borne exploits and droppers.",
        mitre="T1059.007",
        script_count=len(result.javascript),
        total_length=total,
        locations=[f.location for f in result.javascript][:10],
    )


@rule
def r_javascript_auto_exec(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    auto_locations = [
        f.location
        for f in result.javascript
        if f.location.startswith(("/OpenAction", "/Names/JavaScript", "/Root/AA"))
    ]
    if not auto_locations:
        return
    yield _indicator(
        "PDF_JS_AUTO_EXEC",
        "JavaScript executes automatically when the document is opened",
        Severity.HIGH,
        55,
        "active_content",
        "Script is reachable from /OpenAction, /Names/JavaScript or a document-level "
        "/AA entry, so no user interaction is required.",
        mitre="T1204.002",
        locations=auto_locations[:10],
    )


@rule
def r_javascript_obfuscated(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    worst = js_analysis.max_obfuscation(result.javascript)
    if worst < 0.45:
        return
    severity = Severity.HIGH if worst >= 0.7 else Severity.MEDIUM
    weight = 55 if worst >= 0.7 else 35
    yield _indicator(
        "PDF_JS_OBFUSCATED",
        "Embedded JavaScript is heavily obfuscated",
        severity,
        weight,
        "obfuscation",
        "Escape-sequence density, string reconstruction and entropy indicate the "
        "script is deliberately hidden from static inspection.",
        mitre="T1027",
        obfuscation_score=worst,
    )


@rule
def r_javascript_exploit_tokens(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    tokens = js_analysis.critical_tokens(result.javascript)
    if not tokens:
        return
    hints = js_analysis.cve_hints(result.javascript)
    yield _indicator(
        "PDF_JS_EXPLOIT_API",
        "JavaScript calls APIs associated with known exploits",
        Severity.CRITICAL,
        85,
        "exploit",
        "The script references reader APIs whose abuse maps to published "
        "memory-corruption or command-execution vulnerabilities.",
        mitre="T1203",
        tokens=tokens,
        cve_hints=hints,
    )


@rule
def r_launch_action(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    launches = [a for a in result.actions if a.kind == "/Launch"]
    if not launches:
        return
    yield _indicator(
        "PDF_LAUNCH_ACTION",
        "Document declares a /Launch action",
        Severity.CRITICAL,
        85,
        "active_content",
        "/Launch instructs the reader to start an external program. Modern readers "
        "prompt first, but this is a classic dropper pattern.",
        mitre="T1204.002",
        targets=[a.target for a in launches if a.target][:5],
        count=len(launches),
    )


@rule
def r_auto_actions(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    auto = [a for a in result.actions if a.auto_executes and a.kind not in {"/Launch"}]
    if not auto:
        return
    yield _indicator(
        "PDF_AUTO_ACTION",
        "Document performs actions without user interaction",
        Severity.MEDIUM,
        30,
        "active_content",
        "Automatic actions run on open, page change or close.",
        mitre="T1204.002",
        actions=[{"kind": a.kind, "trigger": a.trigger} for a in auto][:10],
    )


@rule
def r_remote_reference(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    remote = [a for a in result.actions if a.kind in {"/GoToR", "/GoToE", "/SubmitForm"}]
    if not remote:
        return
    yield _indicator(
        "PDF_REMOTE_REFERENCE",
        "Document references an external or embedded document target",
        Severity.MEDIUM,
        35,
        "network",
        "Remote go-to and form-submit actions can leak NTLM credentials or fetch a "
        "second-stage payload.",
        mitre="T1221",
        targets=[{"kind": a.kind, "target": a.target} for a in remote][:10],
    )


@rule
def r_xfa_form(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    if not result.structure.has_xfa:
        return
    yield _indicator(
        "PDF_XFA_FORM",
        "Document uses an XFA (dynamic XML) form",
        Severity.LOW,
        20,
        "active_content",
        "XFA forms carry their own scripting layer and are rare in ordinary documents.",
    )


# ===========================================================================
# Rules: embedded files
# ===========================================================================
@rule
def r_embedded_executable(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    dangerous = [
        f
        for f in result.embedded_files
        if (f.extension or "") in EXECUTABLE_EXTENSIONS
        or (f.magic_bytes or "") in {"dos/pe-executable", "elf-executable", "mach-o", "mach-o-64"}
    ]
    if not dangerous:
        return
    yield _indicator(
        "PDF_EMBEDDED_EXECUTABLE",
        "An executable file is embedded in the document",
        Severity.CRITICAL,
        90,
        "embedded_file",
        "The attachment's extension or magic bytes identify a native executable or "
        "script interpreter target.",
        mitre="T1027.013",
        files=[
            {"name": f.name, "extension": f.extension, "magic": f.magic_bytes, "size": f.size}
            for f in dangerous
        ][:10],
    )


@rule
def r_embedded_type_mismatch(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    mismatched = []
    expected = {
        ".pdf": "pdf",
        ".zip": "zip-container",
        ".docx": "zip-container",
        ".xlsx": "zip-container",
        ".gz": "gzip",
        ".rar": "rar-archive",
        ".7z": "7z-archive",
    }
    for f in result.embedded_files:
        want = expected.get(f.extension or "")
        if want and f.magic_bytes and f.magic_bytes != want:
            mismatched.append({"name": f.name, "extension": f.extension, "magic": f.magic_bytes})
    if not mismatched:
        return
    yield _indicator(
        "PDF_EMBEDDED_TYPE_MISMATCH",
        "Embedded file extension does not match its content",
        Severity.HIGH,
        60,
        "embedded_file",
        "A renamed attachment is a deliberate attempt to bypass extension filters.",
        mitre="T1036.008",
        files=mismatched[:10],
    )


@rule
def r_embedded_archive_or_macro(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    risky = [
        f
        for f in result.embedded_files
        if (f.extension or "") in ARCHIVE_EXTENSIONS | OFFICE_MACRO_EXTENSIONS
    ]
    if not risky:
        return
    yield _indicator(
        "PDF_EMBEDDED_RISKY_FILE",
        "Document embeds an archive or macro-capable Office file",
        Severity.MEDIUM,
        40,
        "embedded_file",
        "Archives and macro-enabled documents are common second-stage carriers.",
        mitre="T1027.013",
        files=[{"name": f.name, "extension": f.extension, "size": f.size} for f in risky][:10],
    )


@rule
def r_embedded_high_entropy(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    packed = [
        f
        for f in result.embedded_files
        if f.entropy is not None and f.entropy >= HIGH_ENTROPY_THRESHOLD and f.size > 2048
    ]
    if not packed:
        return
    yield _indicator(
        "PDF_EMBEDDED_HIGH_ENTROPY",
        "Embedded file appears encrypted or packed",
        Severity.MEDIUM,
        30,
        "embedded_file",
        "Near-maximal entropy suggests compression, encryption or a packer.",
        mitre="T1027.002",
        files=[{"name": f.name, "entropy": f.entropy} for f in packed][:10],
    )


# ===========================================================================
# Rules: network
# ===========================================================================
@rule
def r_dangerous_uri_scheme(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    dangerous = url_analysis.dangerous(result.urls)
    if not dangerous:
        return
    yield _indicator(
        "PDF_DANGEROUS_URI",
        "Document references a URI scheme that can execute code or leak credentials",
        Severity.HIGH,
        60,
        "network",
        "file://, smb:// and UNC paths trigger outbound authentication; javascript: "
        "and data: URIs can carry payloads directly.",
        mitre="T1187",
        urls=[u.url for u in dangerous][:10],
    )


@rule
def r_risky_hosts(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    risky = url_analysis.risky_hosts(result.urls)
    if not risky:
        return
    reasons = {
        "ip_literal": sum(1 for u in risky if u.is_ip_literal),
        "shortener": sum(1 for u in risky if u.is_shortener),
        "punycode": sum(1 for u in risky if u.is_punycode),
        "suspicious_tld": sum(1 for u in risky if u.suspicious_tld),
    }
    weight = 25 if len(risky) < 3 else 40
    yield _indicator(
        "PDF_RISKY_URL",
        "Document links to hosts with high-risk characteristics",
        Severity.MEDIUM,
        weight,
        "network",
        "Raw IP addresses, link shorteners, punycode homographs and abuse-prone TLDs "
        "are typical of phishing and malware delivery.",
        mitre="T1566.002",
        reasons={k: v for k, v in reasons.items() if v},
        urls=[u.url for u in risky][:10],
    )


# ===========================================================================
# Rules: structure and obfuscation
# ===========================================================================
@rule
def r_name_obfuscation(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    count = int(result.keyword_counts.get("__obfuscated_names__", 0))
    if count < 1:
        return
    severity = Severity.HIGH if count >= 5 else Severity.MEDIUM
    yield _indicator(
        "PDF_NAME_OBFUSCATION",
        "PDF name objects use hex escapes to hide keywords",
        severity,
        55 if count >= 5 else 35,
        "obfuscation",
        "Writing /JavaScript as /J#61vaScript is valid PDF but has no legitimate "
        "purpose beyond evading keyword scanners.",
        mitre="T1027",
        occurrences=count,
    )


@rule
def r_incremental_updates(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    updates = result.structure.incremental_updates
    if updates < MANY_INCREMENTAL_UPDATES:
        return
    yield _indicator(
        "PDF_MANY_INCREMENTAL_UPDATES",
        "Document has an unusual number of incremental updates",
        Severity.LOW,
        20,
        "structure",
        "Repeated appends can hide an older, benign-looking revision behind a "
        "malicious current one.",
        updates=updates,
    )


@rule
def r_trailing_data(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    trailing = result.structure.eof_trailing_bytes
    if trailing < LARGE_TRAILING_BYTES:
        return
    yield _indicator(
        "PDF_DATA_AFTER_EOF",
        "Significant data appended after the final %%EOF marker",
        Severity.MEDIUM,
        35,
        "structure",
        "Appended bytes are ignored by readers and are a common polyglot / payload "
        "smuggling technique.",
        mitre="T1027.009",
        trailing_bytes=trailing,
    )


@rule
def r_header_anomaly(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    offset = result.structure.header_offset
    if offset == 0:
        return
    yield _indicator(
        "PDF_HEADER_OFFSET",
        "PDF header is not at the start of the file",
        Severity.MEDIUM,
        40,
        "structure",
        "Readers tolerate a shifted header; scanners and parsers often disagree, "
        "which is exactly the point.",
        mitre="T1027",
        header_offset=offset,
    )


@rule
def r_encrypted(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    if not result.structure.is_encrypted:
        return
    yield _indicator(
        "PDF_ENCRYPTED",
        "Document is encrypted",
        Severity.MEDIUM,
        30,
        "structure",
        "Encryption blocks static inspection of the object graph. Combined with a "
        "password supplied in the delivery email this is a known evasion pattern.",
        mitre="T1027.013",
        method=result.structure.encryption_method,
    )


@rule
def r_parse_failures(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    if not result.parse_errors:
        return
    fatal = [e for e in result.parse_errors if e.startswith(("open failed", "walk failed"))]
    if not fatal:
        return
    yield _indicator(
        "PDF_PARSE_FAILURE",
        "Document could not be fully parsed",
        Severity.MEDIUM,
        40,
        "structure",
        "Malformed structure may be corruption, or a deliberate attempt to make "
        "analysers and readers disagree.",
        errors=fatal[:5],
    )


@rule
def r_jbig2_filter(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    if not result.structure.filters.get("JBIG2Decode"):
        return
    yield _indicator(
        "PDF_JBIG2_FILTER",
        "Document uses the JBIG2Decode filter",
        Severity.MEDIUM,
        30,
        "exploit",
        "JBIG2 decoders have a long history of memory-corruption vulnerabilities.",
        mitre="T1203",
        count=result.structure.filters["JBIG2Decode"],
    )


@rule
def r_no_pages_but_active(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    pages = result.structure.page_count
    if pages is None or pages > 1 or not result.has_active_content:
        return
    yield _indicator(
        "PDF_MINIMAL_DOC_WITH_ACTIVE_CONTENT",
        "Nearly empty document that still carries active content",
        Severity.HIGH,
        50,
        "structure",
        "A one-page document whose only real payload is script or an action is far "
        "more likely to be a dropper than a real document.",
        page_count=pages,
    )


# ===========================================================================
# Rules: YARA bridge
# ===========================================================================
_YARA_WEIGHTS = {
    "critical": (Severity.CRITICAL, 85),
    "high": (Severity.HIGH, 60),
    "medium": (Severity.MEDIUM, 35),
    "low": (Severity.LOW, 20),
    "info": (Severity.INFO, 5),
}


@rule
def r_yara_matches(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    for match in result.yara_matches:
        level = str(match.meta.get("severity", "medium")).lower()
        severity, weight = _YARA_WEIGHTS.get(level, (Severity.MEDIUM, 35))
        yield _indicator(
            f"YARA_{match.rule.upper()}",
            f"YARA rule matched: {match.rule}",
            severity,
            weight,
            str(match.meta.get("category", "yara")),
            str(match.meta.get("description", "")),
            mitre=str(match.meta["mitre"]) if "mitre" in match.meta else None,
            namespace=match.namespace,
            matched_strings=match.strings[:10],
        )


# ===========================================================================
# Engine
# ===========================================================================
class HeuristicEngine:
    """Applies every registered rule and aggregates the result."""

    def __init__(self, rules: list[RuleFn] | None = None) -> None:
        self.rules = rules if rules is not None else list(_RULES)

    def evaluate(self, result: StaticAnalysisResult) -> HeuristicOutcome:
        indicators: list[IndicatorResult] = []
        seen: set[str] = set()

        for rule_fn in self.rules:
            try:
                for indicator in rule_fn(result):
                    if indicator.code in seen:
                        continue
                    seen.add(indicator.code)
                    indicators.append(indicator)
            except Exception as exc:  # pragma: no cover - a rule must never break a scan
                from pdfsafe.logging import get_logger

                get_logger(__name__).warning(
                    "heuristic_rule_failed", rule=getattr(rule_fn, "__name__", "?"), error=str(exc)
                )

        score = self.combine(indicators)
        verdict = self.to_verdict(score, indicators)
        return HeuristicOutcome(
            score=score,
            verdict=verdict,
            indicators=indicators,
            rationale=[i.as_prompt_line() for i in sorted(indicators, key=lambda x: -x.weight)],
        )

    @staticmethod
    def combine(indicators: list[IndicatorResult]) -> int:
        """Noisy-OR combination of indicator weights, clamped to 0-100."""
        if not indicators:
            return 0

        surviving = 1.0
        for indicator in indicators:
            surviving *= 1.0 - min(indicator.weight, 99) / 100.0
        score = (1.0 - surviving) * 100.0

        severities = {i.severity for i in indicators}
        if Severity.CRITICAL in severities:
            score = max(score, CRITICAL_FLOOR)
        elif Severity.HIGH in severities:
            score = max(score, HIGH_FLOOR)

        return int(round(max(0.0, min(100.0, score))))

    @staticmethod
    def to_verdict(score: int, indicators: list[IndicatorResult]) -> Verdict:
        if score >= MALICIOUS_THRESHOLD:
            return Verdict.MALICIOUS
        if score >= SUSPICIOUS_THRESHOLD:
            return Verdict.SUSPICIOUS
        if score >= LOW_RISK_THRESHOLD:
            return Verdict.LOW_RISK
        if not indicators:
            return Verdict.CLEAN
        return Verdict.CLEAN


def score_result(result: StaticAnalysisResult) -> HeuristicOutcome:
    """Convenience wrapper around the default engine."""
    return HeuristicEngine().evaluate(result)


def registered_rules() -> list[str]:
    """Names of every registered rule (used by the CLI ``rules`` command)."""
    return [getattr(fn, "__name__", "?") for fn in _RULES]
