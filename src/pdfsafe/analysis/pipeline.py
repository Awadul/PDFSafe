"""Analysis orchestration.

``analyze_bytes`` is the single entry point used by the worker, the CLI and the
tests. It is pure with respect to the database and the network: give it bytes,
get back evidence plus a heuristic verdict.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from pdfsafe.analysis import javascript as js_analysis
from pdfsafe.analysis import urls as url_analysis
from pdfsafe.analysis import yara_engine
from pdfsafe.analysis.constants import ANALYZER_VERSION
from pdfsafe.analysis.heuristics import HeuristicEngine, HeuristicOutcome
from pdfsafe.analysis.structure import file_hashes, parse_document, scan_raw
from pdfsafe.analysis.utils import identify_magic
from pdfsafe.config import get_settings
from pdfsafe.exceptions import CorruptPDFError
from pdfsafe.logging import get_logger
from pdfsafe.metrics import analysis_duration_seconds, heuristic_score, indicators_total
from pdfsafe.schemas.analysis import StaticAnalysisResult, URLFinding

logger = get_logger(__name__)


@dataclass(slots=True)
class AnalysisOutput:
    """Static-analysis evidence plus the heuristic decision derived from it."""

    result: StaticAnalysisResult
    outcome: HeuristicOutcome

    @property
    def score(self) -> int:
        return self.outcome.score


def extract_evidence(
    data: bytes,
    *,
    filename: str | None = None,
    strict: bool = False,
) -> StaticAnalysisResult:
    """Parse ``data`` and return the evidence, without scoring it.

    This is the only part of the pipeline that touches attacker-controlled
    structure, so the desktop build runs *this* function inside a disposable
    child process. Scoring is pure and stays in the caller.

    Args:
        data: Raw file bytes.
        filename: Original name, used only for logging and evidence.
        strict: When ``True``, a file without a PDF header raises
            :class:`CorruptPDFError` instead of being reported as an anomaly.
    """
    settings = get_settings()
    started = time.perf_counter()

    sha256, md5 = file_hashes(data)
    log = logger.bind(sha256=sha256[:12], filename=filename, size=len(data))

    raw = scan_raw(data)
    if strict and not raw.has_header:
        raise CorruptPDFError("File does not contain a %PDF- header", sha256=sha256)

    parsed = parse_document(data, raw)

    # --- JavaScript enrichment -------------------------------------------
    javascript = [js_analysis.enrich(f) for f in parsed.javascript]

    # --- URLs: raw sweep + targets recovered from the object graph --------
    raw_urls = url_analysis.extract_from_bytes(data, "raw", limit=settings.extract_max_urls)
    action_urls = [
        finding
        for target, source in parsed.raw_uri_targets
        if (finding := url_analysis.classify(target, source)) is not None
    ]
    js_urls: list[URLFinding] = []
    for finding in javascript:
        js_urls.extend(
            url_analysis.extract_from_bytes(finding.code.encode("utf-8", "ignore"), "javascript", 50)
        )
    all_urls = url_analysis.merge(action_urls, js_urls, raw_urls, limit=settings.extract_max_urls)

    # --- YARA -------------------------------------------------------------
    yara_matches = yara_engine.scan(data) if settings.enable_yara else []

    # --- keyword counts (plus derived counters used by the rules) ---------
    keyword_counts = dict(raw.keyword_counts)
    keyword_counts["__obfuscated_names__"] = raw.obfuscated_names
    keyword_counts["__eof_markers__"] = raw.eof_count

    elapsed_ms = int((time.perf_counter() - started) * 1000)

    result = StaticAnalysisResult(
        sha256=sha256,
        md5=md5,
        file_size=len(data),
        detected_type=identify_magic(data),
        analyzer_version=ANALYZER_VERSION,
        analysis_ms=elapsed_ms,
        structure=parsed.structure,
        metadata=parsed.metadata,
        keyword_counts=keyword_counts,
        entropy=raw.entropy,
        javascript=javascript,
        actions=parsed.actions,
        embedded_files=parsed.embedded_files,
        urls=all_urls,
        yara_matches=yara_matches,
        text_excerpt=parsed.text_excerpt,
        parse_errors=parsed.parse_errors,
    )
    if not raw.has_header:
        result.parse_errors.append("missing %PDF- header")

    analysis_duration_seconds.observe(time.perf_counter() - started)
    log.debug(
        "evidence_extracted",
        javascript=len(javascript),
        embedded_files=len(parsed.embedded_files),
        urls=len(all_urls),
        yara=len(yara_matches),
        duration_ms=elapsed_ms,
        parse_errors=len(parsed.parse_errors),
    )
    return result


def score_evidence(result: StaticAnalysisResult) -> AnalysisOutput:
    """Apply the heuristic rules to already-extracted evidence.

    Kept separate from :func:`extract_evidence` so the desktop build can score
    in the parent process after parsing in a sandboxed child.
    """
    outcome = HeuristicEngine().evaluate(result)
    result.indicators = outcome.indicators

    heuristic_score.observe(outcome.score)
    for indicator in outcome.indicators:
        indicators_total.labels(indicator=indicator.code, severity=indicator.severity.value).inc()

    logger.info(
        "static_analysis_complete",
        sha256=result.sha256[:12],
        score=outcome.score,
        verdict=outcome.verdict.value,
        indicators=len(outcome.indicators),
        duration_ms=result.analysis_ms,
    )
    return AnalysisOutput(result=result, outcome=outcome)


def analyze_bytes(
    data: bytes,
    *,
    filename: str | None = None,
    strict: bool = False,
) -> AnalysisOutput:
    """Extract evidence from ``data`` and score it in one call."""
    return score_evidence(extract_evidence(data, filename=filename, strict=strict))


def analyze_file(path: str | Path, *, strict: bool = False) -> AnalysisOutput:
    """Read ``path`` and analyse it."""
    file_path = Path(path)
    data = file_path.read_bytes()
    return analyze_bytes(data, filename=file_path.name, strict=strict)


def looks_like_pdf(data: bytes) -> bool:
    """Cheap pre-flight check used by the upload endpoint."""
    return b"%PDF-" in data[:1024]
