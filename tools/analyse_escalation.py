"""Plan AI escalation from an existing benchmark, without spending anything.

Every question that matters about the escalation gate - how many documents it
would send, what that costs, and whether it can even see the cases worth
reviewing - is answerable from ``results.csv``. Running the model first and
looking at the distribution afterwards is the expensive way round.

    python tools/analyse_escalation.py benchmark-final-noocr/results.csv

The gate currently escalates ``ai_escalate_min_score`` to ``ai_escalate_max_score``
(25-84 by default), on the assumption that a score at or above the upper bound is
conclusive. This script tests that assumption directly: it reports where the
false positives actually sit, and whether a cheaper rule - escalate a high score
only when it rests on few indicators - would reach them.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

#: Mirrors pdfsafe.config defaults.
GATE_MIN = 25
GATE_MAX = 85

#: Rough per-call cost inputs. Override on the command line; the evidence bundle
#: is token-budgeted, so the input side is fairly stable per document.
DEFAULT_TOKENS_IN = 3000
DEFAULT_TOKENS_OUT = 500


def load(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        return [row for row in csv.DictReader(handle) if row.get("score")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, help="results.csv from benchmark_corpus.py")
    parser.add_argument("--gate-min", type=int, default=GATE_MIN)
    parser.add_argument("--gate-max", type=int, default=GATE_MAX)
    parser.add_argument("--usd-per-million-in", type=float, default=3.0)
    parser.add_argument("--usd-per-million-out", type=float, default=15.0)
    args = parser.parse_args()

    rows = load(args.results)
    for row in rows:
        row["_score"] = int(row["score"])  # type: ignore[assignment]
        row["_indicators"] = len([c for c in row["indicators"].split(";") if c])  # type: ignore[assignment]

    clean = [r for r in rows if r["label"] == "clean"]
    malware = [r for r in rows if r["label"] == "malware"]

    def band(items: list[dict[str, str]], low: int, high: int) -> list[dict[str, str]]:
        return [r for r in items if low <= int(r["_score"]) < high]  # type: ignore[arg-type]

    print(f"\n{len(rows):,} scored documents: {len(clean):,} clean, {len(malware):,} malware\n")

    # --- what the gate would send -----------------------------------------
    esc_clean = band(clean, args.gate_min, args.gate_max)
    esc_malware = band(malware, args.gate_min, args.gate_max)
    total = len(esc_clean) + len(esc_malware)

    cost = (
        total * DEFAULT_TOKENS_IN / 1_000_000 * args.usd_per_million_in
        + total * DEFAULT_TOKENS_OUT / 1_000_000 * args.usd_per_million_out
    )
    print(
        f"Gate {args.gate_min}-{args.gate_max - 1}: {total:,} calls "
        f"({len(esc_malware):,} malware, {len(esc_clean):,} clean)"
    )
    print(f"  approx ${cost:,.2f} at {DEFAULT_TOKENS_IN}/{DEFAULT_TOKENS_OUT} tokens per call\n")

    # --- can it see the cases worth reviewing? -----------------------------
    # False positives at the quarantine threshold are the whole reason to want a
    # second opinion: each one is a document renamed on a user's disk.
    quarantined_fp = [r for r in clean if int(r["_score"]) >= 80]  # type: ignore[arg-type]
    visible = [r for r in quarantined_fp if int(r["_score"]) < args.gate_max]  # type: ignore[arg-type]
    print(f"False positives at >= 80: {len(quarantined_fp)}")
    print(f"  visible to the gate:    {len(visible)}")
    print(f"  invisible (>= {args.gate_max}):     {len(quarantined_fp) - len(visible)}\n")

    # --- would a thin-evidence rule reach them? ----------------------------
    # A verdict resting on one or two indicators is a weaker conclusion than one
    # resting on six, whatever the score says. Escalating those is cheap if
    # genuine malware rarely looks that way.
    print("Escalating scores >= gate max when the evidence is thin:")
    print(f"  {'max indicators':>14} | {'FPs reached':>11} | {'extra malware calls':>19} | cost")
    for limit in (1, 2, 3, 4):
        reached = [r for r in quarantined_fp if int(r["_indicators"]) <= limit]  # type: ignore[arg-type]
        extra = [
            r
            for r in malware
            if int(r["_score"]) >= args.gate_max and int(r["_indicators"]) <= limit  # type: ignore[arg-type]
        ]
        n = len(reached) + len(extra)
        extra_cost = (
            n * DEFAULT_TOKENS_IN / 1_000_000 * args.usd_per_million_in
            + n * DEFAULT_TOKENS_OUT / 1_000_000 * args.usd_per_million_out
        )
        print(f"  {limit:>14} | {len(reached):>11} | {len(extra):>19,} | ${extra_cost:,.2f}")

    # --- indicator counts, which is what the rule above turns on -----------
    print("\nIndicators per document at >= 80:")
    fp_counts = Counter(int(r["_indicators"]) for r in quarantined_fp)  # type: ignore[arg-type]
    tp_counts = Counter(
        int(r["_indicators"])
        for r in malware
        if int(r["_score"]) >= 80  # type: ignore[arg-type]
    )
    print(f"  {'count':>5} | {'false positives':>15} | {'true positives':>14}")
    for n in sorted(set(fp_counts) | set(tp_counts)):
        print(f"  {n:>5} | {fp_counts.get(n, 0):>15} | {tp_counts.get(n, 0):>14,}")

    print("\nA sampled AI run should target the false positives and a matched set of")
    print("true positives - a few hundred calls answers whether the model helps.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
