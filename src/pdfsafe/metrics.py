"""Prometheus metrics registry.

Metric objects are module-level singletons; importing this module twice in the
same process is safe because prometheus_client de-duplicates by name only on
registration, which happens exactly once here.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

REGISTRY = CollectorRegistry(auto_describe=True)

# --------------------------------------------------------------- ingestion ---
uploads_total = Counter(
    "pdfsafe_uploads_total",
    "PDF uploads accepted by the API.",
    labelnames=("source",),
    registry=REGISTRY,
)

upload_bytes = Histogram(
    "pdfsafe_upload_bytes",
    "Size of accepted uploads in bytes.",
    buckets=(1e4, 1e5, 5e5, 1e6, 5e6, 1e7, 2.5e7, 5e7),
    registry=REGISTRY,
)

uploads_rejected_total = Counter(
    "pdfsafe_uploads_rejected_total",
    "Uploads rejected before analysis.",
    labelnames=("reason",),
    registry=REGISTRY,
)

# ---------------------------------------------------------------- analysis ---
scans_total = Counter(
    "pdfsafe_scans_total",
    "Completed scans by final verdict.",
    labelnames=("verdict", "decided_by"),
    registry=REGISTRY,
)

scan_failures_total = Counter(
    "pdfsafe_scan_failures_total",
    "Scans that ended in an error state.",
    labelnames=("stage",),
    registry=REGISTRY,
)

analysis_duration_seconds = Histogram(
    "pdfsafe_analysis_duration_seconds",
    "Wall-clock duration of the static analysis stage.",
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
    registry=REGISTRY,
)

heuristic_score = Histogram(
    "pdfsafe_heuristic_score",
    "Distribution of heuristic risk scores.",
    buckets=tuple(range(0, 101, 10)),
    registry=REGISTRY,
)

indicators_total = Counter(
    "pdfsafe_indicators_total",
    "Individual indicators raised during static analysis.",
    labelnames=("indicator", "severity"),
    registry=REGISTRY,
)

scans_in_progress = Gauge(
    "pdfsafe_scans_in_progress",
    "Scans currently being processed by workers.",
    registry=REGISTRY,
)

# ---------------------------------------------------------------------- ai ---
ai_calls_total = Counter(
    "pdfsafe_ai_calls_total",
    "LLM triage calls.",
    labelnames=("provider", "outcome"),
    registry=REGISTRY,
)

ai_skipped_total = Counter(
    "pdfsafe_ai_skipped_total",
    "Scans where the LLM was intentionally not consulted.",
    labelnames=("reason",),
    registry=REGISTRY,
)

ai_latency_seconds = Histogram(
    "pdfsafe_ai_latency_seconds",
    "LLM round-trip latency.",
    labelnames=("provider",),
    buckets=(0.5, 1, 2, 5, 10, 20, 40, 60),
    registry=REGISTRY,
)

ai_tokens_total = Counter(
    "pdfsafe_ai_tokens_total",
    "Tokens consumed by the LLM triage layer.",
    labelnames=("provider", "kind"),
    registry=REGISTRY,
)

# --------------------------------------------------------------------- api ---
http_requests_total = Counter(
    "pdfsafe_http_requests_total",
    "HTTP requests handled.",
    labelnames=("method", "path", "status"),
    registry=REGISTRY,
)

http_request_duration_seconds = Histogram(
    "pdfsafe_http_request_duration_seconds",
    "HTTP request latency.",
    labelnames=("method", "path"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
    registry=REGISTRY,
)


def render_metrics() -> tuple[bytes, str]:
    """Return the exposition payload and its content type."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
