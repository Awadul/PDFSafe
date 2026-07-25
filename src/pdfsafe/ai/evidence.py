"""Evidence packaging.

Turns a :class:`StaticAnalysisResult` into an :class:`EvidenceBundle` that fits
inside a token budget. Truncation is deliberate and recorded, so the model is
told what it is *not* seeing rather than silently reasoning over a partial view.
"""

from __future__ import annotations

from typing import Any

from pdfsafe.analysis.heuristics import HeuristicOutcome
from pdfsafe.config import get_settings
from pdfsafe.schemas.ai import EvidenceBundle
from pdfsafe.schemas.analysis import StaticAnalysisResult

#: Rough characters-per-token ratio used for budgeting.
CHARS_PER_TOKEN = 3.6

MAX_INDICATORS = 25
MAX_ACTIONS = 20
MAX_EMBEDDED = 15
MAX_URLS = 25
MAX_YARA = 20
MAX_SCRIPTS = 6
MIN_SCRIPT_CHARS = 400


def build_evidence(
    result: StaticAnalysisResult,
    outcome: HeuristicOutcome,
    *,
    max_chars: int | None = None,
) -> EvidenceBundle:
    """Package analysis output for the LLM within ``max_chars``."""
    settings = get_settings()
    budget = max_chars or settings.ai_max_evidence_chars
    notes: list[str] = []

    file_summary: dict[str, Any] = {
        "sha256": result.sha256,
        "size_bytes": result.file_size,
        "detected_type": result.detected_type,
        "entropy": result.entropy,
        "page_count": result.structure.page_count,
    }

    structure: dict[str, Any] = {
        "pdf_version": result.structure.pdf_version,
        "object_count": result.structure.object_count,
        "stream_count": result.structure.stream_count,
        "filters": result.structure.filters,
        "is_encrypted": result.structure.is_encrypted,
        "is_linearized": result.structure.is_linearized,
        "incremental_updates": result.structure.incremental_updates,
        "has_acroform": result.structure.has_acroform,
        "has_xfa": result.structure.has_xfa,
        "has_openaction": result.structure.has_openaction,
        "has_names_javascript": result.structure.has_names_javascript,
        "has_object_streams": result.structure.has_object_streams,
        "eof_trailing_bytes": result.structure.eof_trailing_bytes,
        "header_offset": result.structure.header_offset,
        "parse_errors": result.parse_errors[:5],
    }

    metadata = {
        k: v
        for k, v in result.metadata.model_dump(exclude={"extra"}).items()
        if v not in (None, "")
    }

    indicators = [
        {
            "code": i.code,
            "title": i.title,
            "severity": i.severity.value,
            "weight": i.weight,
            "category": i.category,
            "evidence": _shrink(i.evidence),
        }
        for i in outcome.top_indicators(MAX_INDICATORS)
    ]
    if len(outcome.indicators) > MAX_INDICATORS:
        notes.append(f"{len(outcome.indicators) - MAX_INDICATORS} lower-weight indicators omitted")

    actions = [
        {
            "kind": a.kind,
            "trigger": a.trigger,
            "target": a.target,
            "auto_executes": a.auto_executes,
        }
        for a in result.actions[:MAX_ACTIONS]
    ]
    if len(result.actions) > MAX_ACTIONS:
        notes.append(f"{len(result.actions) - MAX_ACTIONS} additional actions omitted")

    embedded = [
        {
            "name": f.name,
            "extension": f.extension,
            "size": f.size,
            "magic_bytes": f.magic_bytes,
            "entropy": f.entropy,
            "sha256": (f.sha256 or "")[:16],
        }
        for f in result.embedded_files[:MAX_EMBEDDED]
    ]
    if len(result.embedded_files) > MAX_EMBEDDED:
        notes.append(f"{len(result.embedded_files) - MAX_EMBEDDED} additional attachments omitted")

    urls = [
        {
            "url": u.url[:300],
            "scheme": u.scheme,
            "host": u.host,
            "source": u.source,
            "flags": _url_flags(u),
        }
        for u in _prioritise_urls(result)[:MAX_URLS]
    ]
    if len(result.urls) > MAX_URLS:
        notes.append(f"{len(result.urls) - MAX_URLS} additional URLs omitted")

    yara = [
        {"rule": m.rule, "severity": m.meta.get("severity"), "description": m.meta.get("description")}
        for m in result.yara_matches[:MAX_YARA]
    ]

    keyword_counts = {
        k: v for k, v in result.keyword_counts.items() if not k.startswith("__") and v
    }

    # Document text can contain personal or confidential content. It is useful
    # for spotting phishing wording, but the user can withhold it.
    if settings.ai_share_text_excerpt:
        text_excerpt = result.text_excerpt[:2000]
    else:
        text_excerpt = ""
        if result.text_excerpt:
            notes.append("document text withheld by the user's privacy setting")

    bundle = EvidenceBundle(
        file_summary=file_summary,
        structure=structure,
        metadata=metadata,
        keyword_counts=keyword_counts,
        heuristic_score=outcome.score,
        heuristic_verdict=outcome.verdict,
        indicators=indicators,
        actions=actions,
        embedded_files=embedded,
        urls=urls,
        yara_matches=yara,
        text_excerpt=text_excerpt,
        truncation_notes=notes,
    )

    bundle.javascript_snippets = _fit_scripts(result, bundle, budget, notes)
    bundle.truncation_notes = notes
    return bundle


def _prioritise_urls(result: StaticAnalysisResult) -> list[Any]:
    """Surface the interesting URLs first so truncation drops the boring ones."""

    def key(u: Any) -> tuple[int, str]:
        risky = int(
            u.is_ip_literal
            or u.is_shortener
            or u.is_punycode
            or u.suspicious_tld
            or u.scheme not in {"http", "https"}
        )
        return (-risky, u.url)

    return sorted(result.urls, key=key)


def _url_flags(url: Any) -> list[str]:
    flags = []
    if url.is_ip_literal:
        flags.append("ip_literal")
    if url.is_shortener:
        flags.append("shortener")
    if url.is_punycode:
        flags.append("punycode")
    if url.suspicious_tld:
        flags.append("suspicious_tld")
    if url.scheme not in {"http", "https"}:
        flags.append(f"scheme:{url.scheme}")
    return flags


def _fit_scripts(
    result: StaticAnalysisResult,
    bundle: EvidenceBundle,
    budget: int,
    notes: list[str],
) -> list[dict[str, Any]]:
    """Give the remaining character budget to the most suspicious scripts."""
    if not result.javascript:
        return []

    used = len(bundle.model_dump_json())
    remaining = max(0, budget - used)
    if remaining < MIN_SCRIPT_CHARS:
        notes.append("JavaScript omitted entirely: evidence budget exhausted")
        return []

    ranked = sorted(
        result.javascript,
        key=lambda f: (f.obfuscation_score, len(f.suspicious_tokens), f.length),
        reverse=True,
    )[:MAX_SCRIPTS]
    if len(result.javascript) > MAX_SCRIPTS:
        notes.append(f"{len(result.javascript) - MAX_SCRIPTS} additional scripts omitted")

    per_script = max(MIN_SCRIPT_CHARS, remaining // len(ranked))
    snippets: list[dict[str, Any]] = []
    for finding in ranked:
        code = finding.code[:per_script]
        truncated = finding.truncated or len(finding.code) > per_script
        if truncated:
            notes.append(
                f"script at {finding.location} truncated to {len(code)} of {finding.length} chars"
            )
        snippets.append(
            {
                "location": finding.location,
                "length": finding.length,
                "obfuscation_score": finding.obfuscation_score,
                "entropy": finding.entropy,
                "suspicious_tokens": finding.suspicious_tokens[:20],
                "code": code,
                "truncated": truncated,
            }
        )
    return snippets


def _shrink(evidence: dict[str, Any], limit: int = 600) -> dict[str, Any]:
    """Clip long evidence values so one noisy indicator cannot eat the budget."""
    shrunk: dict[str, Any] = {}
    for key, value in evidence.items():
        if isinstance(value, list) and len(value) > 5:
            shrunk[key] = value[:5] + [f"...+{len(value) - 5} more"]
        elif isinstance(value, str) and len(value) > limit:
            shrunk[key] = value[:limit] + "..."
        else:
            shrunk[key] = value
    return shrunk


def estimate_tokens(bundle: EvidenceBundle) -> int:
    """Rough prompt-token estimate for budgeting and logging."""
    return int(len(bundle.model_dump_json()) / CHARS_PER_TOKEN)
