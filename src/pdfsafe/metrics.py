"""In-process counters.

These used to feed a Prometheus ``/metrics`` endpoint on the HTTP API. With the
API gone nothing scrapes them, so the set has been reduced to the values the
desktop build actually records, and :func:`snapshot` exposes them to the CLI and
the About dialog. A counter nobody can read is just overhead.
"""

from __future__ import annotations

from typing import Any

from prometheus_client import CollectorRegistry, Counter, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

# ---------------------------------------------------------------- analysis ---
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


def snapshot() -> dict[str, Any]:
    """Current counter values as plain data.

    Only counters and histogram totals are reported - the bucket detail is not
    useful without a time series behind it.
    """
    result: dict[str, Any] = {}
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            if not sample.name.endswith(("_total", "_sum", "_count")):
                continue
            key = sample.name
            if sample.labels:
                labels = ",".join(f"{k}={v}" for k, v in sorted(sample.labels.items()))
                key = f"{key}{{{labels}}}"
            result[key] = sample.value
    return result


def reset() -> None:
    """Clear every counter. Used by tests; there is no runtime caller."""
    for collector in list(REGISTRY._collector_to_names):
        try:
            collector._metrics.clear()  # type: ignore[attr-defined]
        except AttributeError:
            continue
