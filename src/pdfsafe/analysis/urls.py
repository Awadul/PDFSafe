"""URL extraction and classification."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from pdfsafe.analysis.constants import (
    DANGEROUS_URI_SCHEMES,
    SUSPICIOUS_TLDS,
    URL_SHORTENER_HOSTS,
)
from pdfsafe.schemas.analysis import URLFinding

_URL_RE = re.compile(
    rb"(?:https?|ftp|file|smb|javascript|data|vbscript|ms-msdt|search-ms)://[^\s<>\"'\\)\]}]{3,2048}",
    re.IGNORECASE,
)
_UNC_RE = re.compile(rb"\\\\[A-Za-z0-9._-]{2,}\\[^\s<>\"']{1,255}")


def classify(url: str, source: str = "unknown") -> URLFinding | None:
    """Build a :class:`URLFinding`, returning ``None`` for unusable input."""
    url = url.strip().strip("()<>[]{}\"'")
    if len(url) < 4:
        return None

    try:
        parsed = urlparse(url)
    except ValueError:
        return None

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    is_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

    port: int | None
    try:
        port = parsed.port
    except ValueError:
        port = None

    return URLFinding(
        url=url[:2048],
        scheme=scheme,
        host=host,
        source=source,
        is_ip_literal=is_ip,
        is_shortener=host in URL_SHORTENER_HOSTS,
        is_punycode=host.startswith("xn--") or ".xn--" in host,
        suspicious_tld=any(host.endswith(tld) for tld in SUSPICIOUS_TLDS),
        port=port,
    )


def extract_from_bytes(data: bytes, source: str = "raw", limit: int = 500) -> list[URLFinding]:
    """Scan raw bytes for URL-looking strings (catches obfuscated streams)."""
    findings: list[URLFinding] = []
    seen: set[str] = set()

    for match in _URL_RE.finditer(data):
        raw = match.group().decode("utf-8", errors="ignore")
        if raw in seen:
            continue
        seen.add(raw)
        finding = classify(raw, source)
        if finding:
            findings.append(finding)
        if len(findings) >= limit:
            return findings

    for match in _UNC_RE.finditer(data):
        raw = match.group().decode("utf-8", errors="ignore")
        if raw in seen:
            continue
        seen.add(raw)
        findings.append(
            URLFinding(url=raw[:2048], scheme="unc", host=raw.split("\\")[2], source=source)
        )
        if len(findings) >= limit:
            break

    return findings


def merge(*groups: list[URLFinding], limit: int = 500) -> list[URLFinding]:
    """De-duplicate URL findings by URL, preferring the most specific source."""
    merged: dict[str, URLFinding] = {}
    for group in groups:
        for finding in group:
            existing = merged.get(finding.url)
            if existing is None or (existing.source == "raw" and finding.source != "raw"):
                merged[finding.url] = finding
    return list(merged.values())[:limit]


def dangerous(findings: list[URLFinding]) -> list[URLFinding]:
    """URLs whose scheme can trigger local code execution or credential leaks."""
    return [f for f in findings if f.scheme in DANGEROUS_URI_SCHEMES or f.scheme == "unc"]


def risky_hosts(findings: list[URLFinding]) -> list[URLFinding]:
    """URLs with hosting traits commonly seen in phishing and malware delivery."""
    return [
        f
        for f in findings
        if f.is_ip_literal or f.is_shortener or f.is_punycode or f.suspicious_tld
    ]
