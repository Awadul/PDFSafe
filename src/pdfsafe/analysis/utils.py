"""Small pure helpers shared by the analysis modules."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Any

from pdfsafe.analysis.constants import MAGIC_SIGNATURES

_HEX_ESCAPE_RE = re.compile(rb"#[0-9A-Fa-f]{2}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def shannon_entropy(data: bytes | str) -> float:
    """Shannon entropy in bits per symbol (0.0 for empty input)."""
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def identify_magic(data: bytes) -> str | None:
    """Return a coarse type name based on leading bytes."""
    head = data[:16]
    for signature, label in MAGIC_SIGNATURES:
        if head.startswith(signature):
            return label
    return None


def decode_name_escapes(raw: bytes) -> bytes:
    """Resolve ``#xx`` hex escapes used to obfuscate PDF name objects.

    ``/J#61vaScript`` is equivalent to ``/JavaScript``; malware uses this to
    evade naive keyword scanners.
    """
    return _HEX_ESCAPE_RE.sub(lambda m: bytes([int(m.group()[1:], 16)]), raw)


def safe_text(value: Any, limit: int = 512) -> str:
    """Best-effort conversion of a PDF value to a short printable string."""
    if value is None:
        return ""
    try:
        text = value if isinstance(value, str) else str(value)
    except Exception:  # pragma: no cover - exotic pikepdf objects
        return ""
    text = text.replace("\x00", "")
    printable = "".join(ch if ch.isprintable() or ch in "\n\t" else "." for ch in text)
    return printable[:limit]


def truncate(text: str, limit: int) -> tuple[str, bool]:
    """Return ``(text, was_truncated)`` clipped to ``limit`` characters."""
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def count_overlapping(haystack: bytes, needle: bytes) -> int:
    """Count non-overlapping occurrences of ``needle``."""
    if not needle:
        return 0
    return haystack.count(needle)


def ratio(part: int, whole: int) -> float:
    return part / whole if whole else 0.0
