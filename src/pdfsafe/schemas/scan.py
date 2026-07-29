"""Scan-related data contracts.

Only aggregates survive here. The REST request/response models
(``ScanSubmitResponse``, ``PaginatedScans``, ``HealthResponse`` and friends)
belonged to the removed HTTP API; the desktop UI reads ORM objects directly and
has no serialisation boundary to model.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanStats(BaseModel):
    """Aggregate counters shown on the dashboard and returned by the CLI."""

    total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_verdict: dict[str, int] = Field(default_factory=dict)
    malicious_last_24h: int = 0
    scanned_last_24h: int = 0
    avg_duration_ms: float | None = None
    ai_calls_last_24h: int = 0

    @property
    def clean_rate(self) -> float | None:
        """Share of completed scans that came back clean, 0.0-1.0.

        ``None`` when nothing has been scanned yet, so callers can distinguish
        "no data" from "nothing was clean".
        """
        if not self.total:
            return None
        clean = self.by_verdict.get("clean", 0) + self.by_verdict.get("low_risk", 0)
        return round(clean / self.total, 4)


__all__ = ["ScanStats"]
