"""JavaScript inspection: token detection and obfuscation scoring."""

from __future__ import annotations

import re

from pdfsafe.analysis.constants import (
    JS_CRITICAL_TOKENS,
    JS_CVE_HINTS,
    JS_HIGH_ENTROPY_THRESHOLD,
    JS_SUSPICIOUS_TOKENS,
    LONG_JS_LINE_THRESHOLD,
)
from pdfsafe.analysis.utils import shannon_entropy
from pdfsafe.schemas.analysis import JavaScriptFinding

_HEX_ESCAPE_RE = re.compile(r"(\\x[0-9A-Fa-f]{2}|%u[0-9A-Fa-f]{4}|\\u[0-9A-Fa-f]{4})")
_CHARCODE_RE = re.compile(r"fromCharCode\s*\(", re.IGNORECASE)
_CONCAT_RE = re.compile(r"[\"'][^\"']{0,4}[\"']\s*\+\s*[\"']")
_LONG_STRING_RE = re.compile(r"[\"'][A-Za-z0-9+/=%\\]{200,}[\"']")
_IDENTIFIER_RE = re.compile(r"\b[_$a-zA-Z][_$a-zA-Z0-9]{0,40}\b")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def enrich(finding: JavaScriptFinding) -> JavaScriptFinding:
    """Annotate a finding with suspicious tokens, entropy and obfuscation score."""
    code = finding.code
    if not code:
        return finding

    lowered = code.lower()
    tokens = [t for t in JS_SUSPICIOUS_TOKENS if t.lower() in lowered]

    finding.suspicious_tokens = tokens
    finding.entropy = round(shannon_entropy(code), 4)
    finding.obfuscation_score = obfuscation_score(code)
    return finding


def obfuscation_score(code: str) -> float:
    """Heuristic 0.0-1.0 measure of how obfuscated a script looks.

    Individual signals are weak on their own; the score is the weighted sum of
    several independent ones, capped at 1.0.
    """
    if not code:
        return 0.0

    length = len(code)
    signals: list[float] = []

    # 1. Escape-sequence density (\x41, %u9090, A).
    escapes = len(_HEX_ESCAPE_RE.findall(code))
    signals.append(min(1.0, (escapes * 4) / max(length, 1) * 10))

    # 2. String building via fromCharCode / eval / unescape.
    builders = len(_CHARCODE_RE.findall(code))
    if builders:
        signals.append(min(1.0, 0.4 + builders * 0.1))

    # 3. Excessive concatenation of tiny string literals.
    concats = len(_CONCAT_RE.findall(code))
    if concats > 5:
        signals.append(min(1.0, concats / 40))

    # 4. Very long single-token strings (packed payloads).
    if _LONG_STRING_RE.search(code) or _BASE64_RE.search(code):
        signals.append(0.6)

    # 5. Entropy of the source itself.
    entropy = shannon_entropy(code)
    if entropy > JS_HIGH_ENTROPY_THRESHOLD:
        signals.append(min(1.0, (entropy - JS_HIGH_ENTROPY_THRESHOLD) / 2))

    # 6. Minified / single-line payloads.
    longest_line = max((len(line) for line in code.splitlines()), default=0)
    if longest_line > LONG_JS_LINE_THRESHOLD:
        signals.append(min(1.0, longest_line / (LONG_JS_LINE_THRESHOLD * 5)))

    # 7. Mangled identifiers (_0x1a2b style or single letters everywhere).
    identifiers = _IDENTIFIER_RE.findall(code)
    if identifiers:
        mangled = sum(1 for i in identifiers if len(i) <= 2 or i.startswith("_0x"))
        signals.append(min(1.0, mangled / len(identifiers)))

    if not signals:
        return 0.0
    combined = sum(sorted(signals, reverse=True)[:4]) / 4
    return round(min(1.0, combined), 3)


def critical_tokens(findings: list[JavaScriptFinding]) -> list[str]:
    """Tokens that map to known exploit primitives across all scripts."""
    found: set[str] = set()
    for finding in findings:
        for token in finding.suspicious_tokens:
            if token in JS_CRITICAL_TOKENS:
                found.add(token)
    return sorted(found)


def cve_hints(findings: list[JavaScriptFinding]) -> dict[str, str]:
    """Map any observed exploit-prone API to its historical CVE."""
    hints: dict[str, str] = {}
    for finding in findings:
        for token in finding.suspicious_tokens:
            cve = JS_CVE_HINTS.get(token)
            if cve:
                hints[token] = cve
    return hints


def total_js_length(findings: list[JavaScriptFinding]) -> int:
    return sum(f.length for f in findings)


def max_obfuscation(findings: list[JavaScriptFinding]) -> float:
    return max((f.obfuscation_score for f in findings), default=0.0)
