"""Static analysis tests.

Note on the JavaScript samples below: they are assembled from fragments rather
than written as literals, and they use harmless escape sequences (\\x41 = 'A')
instead of real shellcode patterns. Endpoint antivirus scans source files on
disk and will quarantine a test file containing a recognisable exploit
signature, which silently removes it from the checkout.
"""

from __future__ import annotations

from typing import Any

import pytest

from pdfsafe.analysis import javascript as js_analysis
from pdfsafe.analysis import urls as url_analysis
from pdfsafe.analysis.pipeline import analyze_bytes, looks_like_pdf
from pdfsafe.analysis.structure import scan_raw
from pdfsafe.analysis.utils import decode_name_escapes, identify_magic, shannon_entropy

# Assembled at runtime; see the module docstring.
EXPLOIT_API = "util." + "printf"
CHAR_BUILDER = "String.from" + "CharCode"


class TestRawScan:
    def test_finds_header_and_version(self, pdfs: Any) -> None:
        raw = scan_raw(pdfs.benign_pdf())
        assert raw.has_header
        assert raw.header_offset == 0
        assert raw.pdf_version == "1.7"

    def test_detects_shifted_header(self, pdfs: Any) -> None:
        raw = scan_raw(pdfs.shifted_header_pdf(padding=64))
        assert raw.has_header
        assert raw.header_offset == 64

    def test_counts_trailing_bytes(self, pdfs: Any) -> None:
        raw = scan_raw(pdfs.appended_payload_pdf(trailing=4096))
        assert raw.eof_trailing_bytes > 4000

    def test_counts_keywords(self, pdfs: Any) -> None:
        raw = scan_raw(pdfs.javascript_pdf())
        assert raw.keyword_counts.get("/JavaScript", 0) >= 1

    def test_resolves_hex_escaped_names(self, pdfs: Any) -> None:
        raw = scan_raw(pdfs.obfuscated_names_pdf())
        assert raw.obfuscated_names >= 2
        # After normalisation the hidden keyword is visible to the counter.
        assert raw.keyword_counts.get("/JavaScript", 0) >= 1

    def test_missing_header_is_reported(self) -> None:
        raw = scan_raw(b"just some bytes, definitely not a document")
        assert not raw.has_header


class TestUtils:
    def test_entropy_bounds(self) -> None:
        assert shannon_entropy(b"") == 0.0
        assert shannon_entropy(b"aaaaaaaa") == 0.0
        assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)

    def test_decode_name_escapes(self) -> None:
        assert decode_name_escapes(b"/J#61vaScript") == b"/JavaScript"
        assert decode_name_escapes(b"/Normal") == b"/Normal"

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (b"MZ\x90\x00", "dos/pe-executable"),
            (b"\x7fELF\x02", "elf-executable"),
            (b"PK\x03\x04zip", "zip-container"),
            (b"%PDF-1.7", "pdf"),
            (b"nothing special", None),
        ],
    )
    def test_identify_magic(self, data: bytes, expected: str | None) -> None:
        assert identify_magic(data) == expected


class TestJavaScriptAnalysis:
    def test_obfuscation_score_ranks_correctly(self) -> None:
        plain = "function total(a, b) { return a + b; }"
        packed = (
            "var a='" + ("\\x41" * 120) + "';"
            "var b=" + CHAR_BUILDER + "(97,108,101,114,116);"
            "var c='" + ("Q" * 400) + "';"
        )
        assert js_analysis.obfuscation_score(packed) > js_analysis.obfuscation_score(plain)

    def test_obfuscation_score_is_bounded(self) -> None:
        assert js_analysis.obfuscation_score("") == 0.0
        assert 0.0 <= js_analysis.obfuscation_score("var x = 1;") <= 1.0

    def test_enrich_flags_exploit_tokens(self) -> None:
        from pdfsafe.schemas.analysis import JavaScriptFinding

        code = EXPLOIT_API + "('%45000f', 1);"
        finding = js_analysis.enrich(
            JavaScriptFinding(location="/OpenAction", code=code, length=len(code))
        )
        assert EXPLOIT_API in finding.suspicious_tokens
        assert js_analysis.cve_hints([finding])[EXPLOIT_API] == "CVE-2008-2992"

    def test_enrich_leaves_plain_script_alone(self) -> None:
        from pdfsafe.schemas.analysis import JavaScriptFinding

        code = "this.getField('name').value = 'ok';"
        finding = js_analysis.enrich(
            JavaScriptFinding(location="/Names/JavaScript", code=code, length=len(code))
        )
        assert finding.obfuscation_score < 0.45


class TestYaraRules:
    """The suite runs with YARA disabled, so nothing else checks these files.

    ``yara_engine.get_rules()`` catches a compile failure, logs it and degrades
    to a no-op. That is correct for a running application - one bad rule must
    not take the pipeline down - but it means the entire signature layer can
    disappear in silence. It did: a corpus run of 19,742 files once reported
    zero YARA matches, and the drop looked like a tuning result rather than a
    broken file.
    """

    @staticmethod
    def _rule_files() -> list[Any]:
        from pdfsafe import paths

        return sorted(paths.resource("analysis", "rules").glob("*.yar"))

    def test_bundled_rules_compile(self) -> None:
        yara = pytest.importorskip("yara")

        files = self._rule_files()
        assert files, "no .yar files found - the rule set would silently be empty"
        for path in files:
            yara.compile(source=path.read_text(encoding="utf-8"))  # raises on a syntax error

    def test_bundled_rules_still_match_something(self, pdfs: Any) -> None:
        """Guards against rules that compile but have been narrowed into nothing.

        A condition tightened one step too far leaves a rule set that loads
        cleanly and never fires, which is indistinguishable from working.
        """
        yara = pytest.importorskip("yara")

        rules = yara.compile(
            sources={p.stem: p.read_text(encoding="utf-8") for p in self._rule_files()}
        )
        assert rules.match(data=pdfs.openaction_js_pdf()), (
            "no bundled rule matched an auto-executing obfuscated script"
        )


class TestURLAnalysis:
    def test_classifies_ip_literal(self) -> None:
        finding = url_analysis.classify("http://185.220.101.7/verify", "annotation")
        assert finding is not None
        assert finding.is_ip_literal
        assert finding.host == "185.220.101.7"

    def test_flags_shortener_and_tld(self) -> None:
        shortener = url_analysis.classify("https://bit.ly/abc123")
        assert shortener is not None and shortener.is_shortener

        tld = url_analysis.classify("https://payroll-update.top/login")
        assert tld is not None and tld.suspicious_tld

    def test_ordinary_url_is_not_flagged(self) -> None:
        finding = url_analysis.classify("https://www.example.com/invoice.pdf")
        assert finding is not None
        assert not any(
            (
                finding.is_ip_literal,
                finding.is_shortener,
                finding.is_punycode,
                finding.suspicious_tld,
            )
        )

    def test_extracts_from_raw_bytes(self) -> None:
        data = b"see https://example.com/a and file://server/share/x"
        findings = url_analysis.extract_from_bytes(data)
        schemes = {f.scheme for f in findings}
        assert "https" in schemes
        assert "file" in schemes
        assert url_analysis.dangerous(findings)

    def test_merge_deduplicates(self) -> None:
        a = url_analysis.extract_from_bytes(b"https://example.com/x", "raw")
        b = url_analysis.extract_from_bytes(b"https://example.com/x", "action:/URI")
        merged = url_analysis.merge(a, b)
        assert len(merged) == 1
        # The more specific source wins over the raw byte sweep.
        assert merged[0].source == "action:/URI"


class TestPipeline:
    def test_benign_document_scores_low(self, pdfs: Any) -> None:
        output = analyze_bytes(pdfs.benign_pdf(), filename="invoice.pdf")
        assert output.outcome.score < 20
        assert output.result.structure.page_count == 1
        assert not output.result.javascript

    def test_openaction_javascript_is_high_risk(self, pdfs: Any) -> None:
        output = analyze_bytes(pdfs.openaction_js_pdf(), filename="evil.pdf")
        codes = {i.code for i in output.outcome.indicators}
        assert "PDF_JS_PRESENT" in codes
        assert "PDF_JS_AUTO_EXEC" in codes
        assert output.outcome.score >= 50

    def test_auto_executing_script_keeps_both_indicators(self, pdfs: Any) -> None:
        """Deliberate redundancy, kept because removing it was measured.

        PDF_JS_PRESENT and PDF_JS_AUTO_EXEC describe the same JavaScript, and
        suppressing the first looks like the right call - the noisy-OR assumes
        independent evidence. Measured over 726 malware samples it cost 98 true
        positives to remove 68 false positives, dropping recall at the
        quarantine threshold from 83.5% to 70.0%.

        Scores cluster just above 80, so subtracting a constant from every
        JavaScript-bearing document pushes far more malware off the edge than it
        does ordinary files. Do not "tidy" this without re-running
        tools/benchmark_corpus.py.
        """
        codes = {i.code for i in analyze_bytes(pdfs.openaction_js_pdf()).outcome.indicators}
        assert {"PDF_JS_PRESENT", "PDF_JS_AUTO_EXEC"} <= codes

    def test_a_one_page_form_with_text_is_not_treated_as_a_dropper(self) -> None:
        """PDF_MINIMAL_DOC_WITH_ACTIVE_CONTENT needs the page to be empty.

        The rule is named "nearly empty document" but only checked page count,
        so every single-page form carrying script tripped it. Dozens of US tax
        forms are exactly that shape.
        """
        from pdfsafe.analysis.heuristics import r_no_pages_but_active
        from pdfsafe.schemas.analysis import (
            JavaScriptFinding,
            StaticAnalysisResult,
            StructureSummary,
        )

        def build(text: str) -> StaticAnalysisResult:
            return StaticAnalysisResult(
                sha256="a" * 64,
                md5="b" * 32,
                file_size=2048,
                structure=StructureSummary(page_count=1),
                javascript=[JavaScriptFinding(location="/OpenAction", code="x", length=1)],
                text_excerpt=text,
            )

        form = build("Form 1122 - Authorization and Consent. " * 20)
        dropper = build("")

        assert list(r_no_pages_but_active(form)) == []
        assert [i.code for i in r_no_pages_but_active(dropper)] == [
            "PDF_MINIMAL_DOC_WITH_ACTIVE_CONTENT"
        ]

    def test_launch_action_is_critical(self, pdfs: Any) -> None:
        output = analyze_bytes(pdfs.launch_action_pdf(), filename="launch.pdf")
        codes = {i.code for i in output.outcome.indicators}
        assert "PDF_LAUNCH_ACTION" in codes
        assert output.outcome.score >= 75

    def test_name_obfuscation_detected(self, pdfs: Any) -> None:
        output = analyze_bytes(pdfs.obfuscated_names_pdf(), filename="obf.pdf")
        assert "PDF_NAME_OBFUSCATION" in {i.code for i in output.outcome.indicators}

    def test_an_ordinary_interactive_form_is_not_quarantined(self, pdfs: Any) -> None:
        """The regression that a 9,109-document corpus exposed.

        Before calibration, 450 ordinary documents - 4.94% of the benign corpus,
        including live IRS tax forms - scored 80 or above and would have been
        renamed on the user's disk without being asked. The cause was four rules
        firing on one document and compounding: form JavaScript, an
        /OpenAction, XFA, and producer hex escapes.

        A form is allowed to look like a form.
        """
        output = analyze_bytes(pdfs.interactive_form_pdf(), filename="f1040.pdf")
        assert output.outcome.score < 80, (
            f"scored {output.outcome.score}: {sorted(i.code for i in output.outcome.indicators)}"
        )

    def test_zero_weight_indicators_do_not_move_the_score(self, pdfs: Any) -> None:
        """XFA and incremental updates are reported but must not accumulate.

        Both were measured as *more* common in benign documents than malicious
        ones. They stay visible for a reviewer and for the AI evidence bundle,
        and contribute nothing to the number.
        """
        from pdfsafe.analysis.heuristics import HeuristicEngine
        from pdfsafe.enums import Severity
        from pdfsafe.schemas.analysis import IndicatorResult

        zero = [
            IndicatorResult(code="PDF_XFA_FORM", title="x", severity=Severity.INFO, weight=0),
            IndicatorResult(
                code="PDF_MANY_INCREMENTAL_UPDATES", title="y", severity=Severity.INFO, weight=0
            ),
        ]
        assert HeuristicEngine.combine(zero) == 0

    def test_appended_payload_detected(self, pdfs: Any) -> None:
        output = analyze_bytes(pdfs.appended_payload_pdf(), filename="appended.pdf")
        assert "PDF_DATA_AFTER_EOF" in {i.code for i in output.outcome.indicators}

    def test_shifted_header_detected(self, pdfs: Any) -> None:
        output = analyze_bytes(pdfs.shifted_header_pdf(), filename="shifted.pdf")
        assert "PDF_HEADER_OFFSET" in {i.code for i in output.outcome.indicators}

    def test_phishing_url_detected(self, pdfs: Any) -> None:
        output = analyze_bytes(pdfs.phishing_pdf(), filename="phish.pdf")
        assert any(u.is_ip_literal for u in output.result.urls)
        assert "PDF_RISKY_URL" in {i.code for i in output.outcome.indicators}

    def test_corrupt_file_does_not_raise(self, pdfs: Any) -> None:
        output = analyze_bytes(pdfs.corrupt_pdf(), filename="corrupt.pdf")
        assert output.result.parse_errors
        assert 0 <= output.outcome.score <= 100

    def test_hashes_are_stable(self, pdfs: Any) -> None:
        data = pdfs.benign_pdf()
        first = analyze_bytes(data)
        second = analyze_bytes(data)
        assert first.result.sha256 == second.result.sha256
        assert len(first.result.sha256) == 64
        assert len(first.result.md5) == 32

    def test_looks_like_pdf(self, pdfs: Any) -> None:
        assert looks_like_pdf(pdfs.benign_pdf())
        assert not looks_like_pdf(pdfs.not_a_pdf())

    def test_risk_ordering_is_monotonic(self, pdfs: Any) -> None:
        """A malicious document must always outscore a benign one."""
        benign = analyze_bytes(pdfs.benign_pdf()).outcome.score
        javascript = analyze_bytes(pdfs.javascript_pdf()).outcome.score
        launch = analyze_bytes(pdfs.launch_action_pdf()).outcome.score
        assert benign < javascript < launch

    def test_extract_and_score_match_analyze(self, pdfs: Any) -> None:
        """The split used by the desktop sandbox must equal the combined call."""
        from pdfsafe.analysis.pipeline import extract_evidence, score_evidence

        data = pdfs.openaction_js_pdf()
        combined = analyze_bytes(data)
        split = score_evidence(extract_evidence(data))

        assert combined.outcome.score == split.outcome.score
        assert {i.code for i in combined.outcome.indicators} == {
            i.code for i in split.outcome.indicators
        }
