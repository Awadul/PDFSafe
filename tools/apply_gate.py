"""Re-score a benchmark_ai run through the escalation gate that actually ships.

    python tools/apply_gate.py benchmark-ai/changes.csv

benchmark_ai.py calls triage with force_ai=True, because the question it asks is
"what can the model contribute when consulted?" - and gating first would leave
most of the interesting files unmeasured.

But that is not the question a user cares about. In a real scan the gate decides
who gets consulted, and a file that never reaches the model cannot be corrected
by it. Reporting the forced numbers as the product's behaviour overstates the
layer, because the corrections concentrate in exactly the band the gate excludes:
high-scoring documents with several agreeing indicators.

This script applies the shipped gate to a completed run. No API calls: the
verdicts are already recorded, so this only decides which of them count.
"""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path

os.environ.setdefault("PDFSAFE_LOG_LEVEL", "ERROR")

QUARANTINE = 80


def escalates(score: int, indicators: int, low: int, high: int, thin: int) -> bool:
    """Mirror pdfsafe.ai.triage.should_escalate for a recorded row.

    Kept deliberately small and read from settings rather than hard-coded, so a
    threshold change moves both together. If the gate grows a condition that
    cannot be derived from score and indicator count alone, this stops being
    sound and the run must be repeated without force_ai.
    """
    if score < low:
        return False
    if score >= high:
        return indicators <= thin
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("changes", type=Path, help="changes.csv from benchmark_ai.py")
    args = parser.parse_args()

    from pdfsafe.config import get_settings

    settings = get_settings()
    low = settings.ai_escalate_min_score
    high = settings.ai_escalate_max_score
    thin = settings.ai_escalate_thin_evidence_max

    print(
        f"Gate: escalate when {low} <= score < {high}, "
        f"or score >= {high} with <= {thin} indicators\n"
    )

    with args.changes.open(encoding="utf-8") as handle:
        rows = [r for r in csv.DictReader(handle) if not r["error"]]

    counts = {"forced": {}, "gated": {}}  # type: ignore[var-annotated]
    for mode in ("forced", "gated"):
        tp = fp = tn = fn = 0
        for row in rows:
            static = int(row["static_score"])
            consulted = mode == "forced" or escalates(
                static, int(row["indicators"]), low, high, thin
            )
            score = int(row["ai_score"]) if consulted else static
            flagged = score >= QUARANTINE
            if row["label"] == "malware":
                tp, fn = (tp + 1, fn) if flagged else (tp, fn + 1)
            else:
                fp, tn = (fp + 1, tn) if flagged else (fp, tn + 1)
        counts[mode] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}

    consulted_rows = [
        r for r in rows if escalates(int(r["static_score"]), int(r["indicators"]), low, high, thin)
    ]
    print(f"Files in the sample:        {len(rows)}")
    print(
        f"Consulted under the gate:   {len(consulted_rows)}"
        f"  ({len(consulted_rows) / len(rows):.0%})"
    )
    print(f"Decided locally:            {len(rows) - len(consulted_rows)}\n")

    print(f"{'':<20}{'static':>10}{'forced':>10}{'shipped':>10}")
    static_counts = {
        "tp": sum(1 for r in rows if r["label"] == "malware" and int(r["static_score"]) >= 80),
        "fp": sum(1 for r in rows if r["label"] == "clean" and int(r["static_score"]) >= 80),
        "tn": sum(1 for r in rows if r["label"] == "clean" and int(r["static_score"]) < 80),
        "fn": sum(1 for r in rows if r["label"] == "malware" and int(r["static_score"]) < 80),
    }
    for key, name in (
        ("tp", "true positives"),
        ("fp", "false positives"),
        ("tn", "true negatives"),
        ("fn", "false negatives"),
    ):
        print(
            f"{name:<20}{static_counts[key]:>10}{counts['forced'][key]:>10}"
            f"{counts['gated'][key]:>10}"
        )

    fixed = [
        r
        for r in consulted_rows
        if r["label"] == "clean" and int(r["static_score"]) >= 80 and int(r["ai_score"]) < 80
    ]
    lost = [
        r
        for r in consulted_rows
        if r["label"] == "malware" and int(r["static_score"]) >= 80 and int(r["ai_score"]) < 80
    ]
    gained = [
        r
        for r in consulted_rows
        if r["label"] == "malware" and int(r["static_score"]) < 80 and int(r["ai_score"]) >= 80
    ]

    print("\nUnder the shipped gate:")
    print(f"  False positives corrected:  {len(fixed)}")
    print(f"  True positives lost:        {len(lost)}")
    print(f"  Detections recovered:       {len(gained)}")

    missed = [
        r
        for r in rows
        if r["label"] == "clean"
        and int(r["static_score"]) >= 80
        and int(r["ai_score"]) < 80
        and r not in consulted_rows
    ]
    if missed:
        print(f"\n  {len(missed)} false positives the model WOULD have corrected are never")
        print("  consulted, because the gate decides them locally:")
        for r in sorted(missed, key=lambda x: -int(x["static_score"]))[:15]:
            print(
                f"    {r['file'][:42]:<44}score {r['static_score']:>3}"
                f"  {r['indicators']} indicators"
            )
        print("\n  Widening the gate would capture these, at the cost of one API call")
        print("  per high-scoring document. Measure that before changing it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
