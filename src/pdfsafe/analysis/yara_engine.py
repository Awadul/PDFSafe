"""YARA integration.

Rules are compiled once per process and cached. If ``yara-python`` is missing
or a rule file fails to compile the scanner degrades to a no-op so that a bad
rule can never take the pipeline down.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pdfsafe import paths
from pdfsafe.config import get_settings
from pdfsafe.logging import get_logger
from pdfsafe.schemas.analysis import YaraMatch

logger = get_logger(__name__)

BUNDLED_RULES_DIR = paths.resource("analysis", "rules")
_SCAN_TIMEOUT_SECONDS = 30
_MAX_STRINGS_PER_MATCH = 20


def _rule_sources(extra_dir: Path | None) -> dict[str, str]:
    sources: dict[str, str] = {}
    for directory in (BUNDLED_RULES_DIR, extra_dir):
        if directory is None or not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.yar")) + sorted(directory.glob("*.yara")):
            try:
                sources[path.stem] = path.read_text(encoding="utf-8")
            except Exception as exc:
                logger.warning("yara_read_failed", path=str(path), error=str(exc))
    return sources


@lru_cache(maxsize=1)
def get_rules() -> Any | None:
    """Compile and cache the rule set, or return ``None`` when unavailable."""
    settings = get_settings()
    if not settings.enable_yara:
        return None

    try:
        import yara
    except ImportError:
        logger.warning("yara_unavailable", reason="yara-python is not installed")
        return None

    sources = _rule_sources(settings.yara_rules_dir)
    if not sources:
        # ERROR, not WARNING. Missing rules mean every signature check silently
        # passes, and a scan with no signature coverage is indistinguishable in
        # the output from a scan that found nothing. Endpoint antivirus deletes
        # this file - it is a list of malware signature strings - so "the rules
        # vanished" is a routine event, not a hypothetical one.
        logger.error(
            "yara_no_rules",
            searched=str(BUNDLED_RULES_DIR),
            impact="signature detection is disabled for every scan",
            likely_cause="antivirus quarantined the rule file",
        )
        return None

    try:
        rules = yara.compile(sources=sources)
    except Exception as exc:
        logger.error("yara_compile_failed", error=str(exc))
        return None

    logger.info("yara_rules_loaded", namespaces=sorted(sources))
    return rules


def scan(data: bytes) -> list[YaraMatch]:
    """Run the compiled rules against ``data``; never raises."""
    rules = get_rules()
    if rules is None:
        return []

    try:
        raw_matches = rules.match(data=data, timeout=_SCAN_TIMEOUT_SECONDS)
    except Exception as exc:
        logger.warning("yara_scan_failed", error=str(exc))
        return []

    results: list[YaraMatch] = []
    for match in raw_matches:
        results.append(
            YaraMatch(
                rule=match.rule,
                namespace=getattr(match, "namespace", "default"),
                tags=list(getattr(match, "tags", []) or []),
                meta=dict(getattr(match, "meta", {}) or {}),
                strings=_summarise_strings(match),
            )
        )
    return results


def _summarise_strings(match: Any) -> list[str]:
    """Return identifiers of the strings that matched, without leaking payloads."""
    identifiers: list[str] = []
    try:
        for string_match in getattr(match, "strings", []) or []:
            identifier = getattr(string_match, "identifier", None) or str(string_match)
            if identifier not in identifiers:
                identifiers.append(identifier)
            if len(identifiers) >= _MAX_STRINGS_PER_MATCH:
                break
    except Exception:  # pragma: no cover
        return identifiers
    return identifiers


def severity_of(match: YaraMatch) -> str:
    """Read the ``severity`` meta field, defaulting to ``medium``."""
    value = match.meta.get("severity", "medium")
    return str(value).lower()


def reset_cache() -> None:
    """Drop the compiled rule cache (used by tests and hot reloads)."""
    get_rules.cache_clear()
