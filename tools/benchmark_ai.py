"""Measure what the AI layer changes, on a targeted sample rather than a corpus.

    python tools/benchmark_ai.py benchmark-final-noocr/results.csv --dry-run
    python tools/benchmark_ai.py benchmark-final-noocr/results.csv --max-calls 150

Running the model over 20,000 documents would cost real money to answer a
question a few hundred calls answers better. The reason is that this is a
**paired** measurement: every file is scored by the static engine and then by
the fused verdict, so the comparison is a per-file delta rather than an estimate
of a population rate. Sampling error does not enter it. What matters is covering
the cases where the two could disagree, not covering the corpus.

Selection therefore prioritises, in order:

1. **Every false positive at the quarantine threshold.** Each one is a document
   PDFSafe would rename on someone's disk. If the model cannot fix these, the
   layer has no case.
2. **Thin-evidence verdicts** - high score, few indicators. Measured at 12 false
   positives to 1 true positive, this is where the gate now sends work.
3. **True positives stratified by score**, to detect the failure that matters
   more than any gain: the model clearing malware the engine caught.

The report is the confusion matrix before and after fusion over the same files,
plus every individual verdict change, because with samples this size the
individual changes are the evidence and the aggregate is just arithmetic.
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

os.environ.setdefault("PDFSAFE_LOG_LEVEL", "ERROR")

QUARANTINE = 80

# Five in a row is far past coincidence: transient failures do not queue up.
_ABORT_AFTER_CONSECUTIVE_FAILURES = 5


@dataclass(slots=True)
class Change:
    path: str
    label: str
    static_score: int
    static_verdict: str
    ai_score: int
    ai_verdict: str
    indicators: int
    ai_said: str = ""
    tokens: int = 0
    error: str = ""

    @property
    def moved(self) -> bool:
        return self.static_verdict != self.ai_verdict


class RateLimiter:
    """Cap sustained throughput over a sliding window.

    A fixed sleep between calls is not a rate limit: analysis time varies from
    30 ms to 5 s per file, so a 20-second pause yields anywhere from 2.4 to 3
    requests a minute. Free tiers measure what arrives, not what we intended to
    send, so measure the same thing they do.
    """

    def __init__(self, per_minute: float) -> None:
        self.per_minute = per_minute
        self._sent: list[float] = []

    def wait(self) -> None:
        if self.per_minute <= 0:
            return
        while True:
            now = time.monotonic()
            self._sent = [t for t in self._sent if now - t < 60.0]
            if len(self._sent) < self.per_minute:
                self._sent.append(now)
                return
            time.sleep(max(0.1, 60.0 - (now - self._sent[0])))


@dataclass(slots=True)
class Bucket:
    name: str
    rows: list[dict[str, str]] = field(default_factory=list)


def load(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        rows = [r for r in csv.DictReader(handle) if r.get("score") and not r.get("error")]
    for row in rows:
        row["_score"] = str(int(row["score"]))
        row["_n"] = str(len([c for c in row["indicators"].split(";") if c]))
    return rows


def select(rows: list[dict[str, str]], max_calls: int, seed: int) -> list[Bucket]:
    """Choose files where static and fused verdicts could plausibly differ.

    Each bucket gets a reserved share of the budget. An earlier version filled
    them greedily in order and the second bucket consumed everything, leaving
    the control groups empty - which silently removed the only way to detect the
    failure that disqualifies the layer: the model clearing real malware. A
    measurement that can only find good news is not a measurement.
    """
    # Reproducible sampling, not a security decision: the seed is recorded so a
    # reviewer can regenerate the exact file set this measurement used.
    rng = random.Random(seed)  # noqa: S311
    clean = [r for r in rows if r["label"] == "clean"]
    malware = [r for r in rows if r["label"] == "malware"]

    def pool(items: list[dict[str, str]], low: int, high: int) -> list[dict[str, str]]:
        return [r for r in items if low <= int(r["_score"]) < high]

    # (name, candidates, share of the budget). Shares sum to 1.0.
    plan: list[tuple[str, list[dict[str, str]], float]] = [
        # Every false positive at the quarantine threshold. These are documents
        # PDFSafe renames on someone's disk; if the model cannot fix them the
        # layer has no case.
        ("false positives at >= 80", pool(clean, QUARANTINE, 101), 0.25),
        # Where the evidence-aware gate now sends work.
        (
            "thin evidence at >= 80 (malware)",
            [r for r in malware if int(r["_score"]) >= QUARANTINE and int(r["_n"]) <= 3],
            0.20,
        ),
        # Controls. A model that clears strongly-indicated malware is
        # disqualifying however many false positives it fixes.
        ("true positives 90-100", pool(malware, 90, 101), 0.20),
        ("true positives 80-89", pool(malware, QUARANTINE, 90), 0.15),
        ("true positives 50-79", pool(malware, 50, QUARANTINE), 0.10),
        # The opposite failure: the model raising an ordinary document.
        ("true negatives 20-79", pool(clean, 20, QUARANTINE), 0.10),
    ]

    buckets: list[Bucket] = []
    spent = 0
    for name, candidates, share in plan:
        quota = max(1, round(max_calls * share))
        chosen = rng.sample(candidates, min(quota, len(candidates)))
        buckets.append(Bucket(name, chosen))
        spent += len(chosen)

    # Redistribute anything a small bucket could not use, so the budget is spent
    # rather than left on the table.
    for bucket, (_, candidates, _) in zip(buckets, plan, strict=True):
        if spent >= max_calls:
            break
        remaining = [r for r in candidates if r not in bucket.rows]
        extra = rng.sample(remaining, min(max_calls - spent, len(remaining)))
        bucket.rows.extend(extra)
        spent += len(extra)

    return buckets


def run_one(row: dict[str, str]) -> Change:
    from pdfsafe.ai.triage import triage
    from pdfsafe.analysis.pipeline import analyze_bytes

    path = Path(row["path"])
    change = Change(
        path=path.name,
        label=row["label"],
        static_score=int(row["_score"]),
        static_verdict=row["verdict"],
        ai_score=int(row["_score"]),
        ai_verdict=row["verdict"],
        indicators=int(row["_n"]),
    )

    try:
        output = analyze_bytes(path.read_bytes(), filename=path.name)
        result = triage(output.result, output.outcome, force_ai=True)
    except Exception as exc:  # one bad file must not end a 150-call run
        change.error = f"{type(exc).__name__}: {exc}"
        return change

    change.ai_score = result.risk_score
    change.ai_verdict = result.verdict.value
    if result.ai_call is not None:
        change.tokens = result.ai_call.total_tokens
        if result.ai_call.verdict is not None:
            change.ai_said = result.ai_call.verdict.verdict.value
        if not result.ai_call.succeeded:
            change.error = result.ai_call.error_message or "provider call failed"
    return change


def confusion(changes: list[Change], *, after: bool) -> Counter[str]:
    counts: Counter[str] = Counter()
    for c in changes:
        if c.error:
            continue
        score = c.ai_score if after else c.static_score
        flagged = score >= QUARANTINE
        if c.label == "malware":
            counts["tp" if flagged else "fn"] += 1
        else:
            counts["fp" if flagged else "tn"] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, help="results.csv from benchmark_corpus.py")
    parser.add_argument("--max-calls", type=int, default=150)
    parser.add_argument("--seed", type=int, default=20260803)
    parser.add_argument("--dry-run", action="store_true", help="show selection, call nothing")
    parser.add_argument(
        "--delay", type=float, default=2.0, help="seconds between calls; raise if you see 429s"
    )
    parser.add_argument(
        "--rpm",
        type=float,
        default=0,
        help="cap requests per minute (e.g. 3 for a free tier). Overrides --delay.",
    )
    parser.add_argument("--out", type=Path, default=Path("benchmark-ai"))
    args = parser.parse_args()

    buckets = select(load(args.results), args.max_calls, args.seed)
    planned = sum(len(b.rows) for b in buckets)
    if planned == 0:
        print("No candidates matched. Check the results.csv columns.")
        return 2

    print(f"\nSelected {planned} files:")
    for bucket in buckets:
        print(f"  {len(bucket.rows):>4}  {bucket.name}")

    if args.dry_run:
        print("\nDry run - nothing called.")
        return 0

    from pdfsafe.ai.triage import get_provider

    if get_provider().name == "null":
        print("\nNo AI provider configured. Set PDFSAFE_AI_PROVIDER and a key first.")
        return 2

    limiter = RateLimiter(args.rpm)
    if args.rpm:
        minutes = planned / args.rpm
        print(
            f"\nRate limited to {args.rpm:g}/min - {planned} calls will take "
            f"~{minutes:.0f} minutes."
        )
        if minutes > 55:
            print(
                "  NOTE: that exceeds the lifetime of a short-lived OAuth token. If the\n"
                "  credential expires mid-run every remaining call falls back silently.\n"
                "  Use a long-lived API key, or split the run with a smaller --max-calls."
            )

    print(f"\nCalling the provider {planned} times...\n")
    # Interleave the buckets rather than draining them in order. A run that
    # stops early is the normal case here - credits, quotas and tokens all
    # expire mid-flight - and consuming bucket 1 before touching bucket 5 means
    # a partial run covers only the cases chosen first. One such run finished 71
    # of 150 files having never sampled a single control, so it could measure
    # the gain and not the risk. Round-robin makes every prefix a fair sample.
    ordered: list[dict[str, str]] = []
    for tier in range(max((len(b.rows) for b in buckets), default=0)):
        ordered.extend(b.rows[tier] for b in buckets if tier < len(b.rows))

    changes: list[Change] = []
    consecutive = 0
    for index, row in enumerate(ordered, 1):
        limiter.wait()
        change = run_one(row)
        changes.append(change)

        # Stop on a systemic failure instead of spending the whole budget
        # proving the same point 150 times. An exhausted daily quota or a dead
        # credential fails every remaining call, and each one still costs a
        # request against the quota plus its retries. A run that cannot produce
        # a measurement should end while the operator can still act on it.
        consecutive = consecutive + 1 if change.error else 0
        if consecutive >= _ABORT_AFTER_CONSECUTIVE_FAILURES:
            print(
                f"\n\n  ABORTED after {consecutive} consecutive failures at file {index}"
                f" of {planned}.\n  Last error: {change.error[:160]}\n"
                "  Nothing was measured. Fix the provider and re-run.\n"
            )
            break
        print(f"  {index}/{planned}", end="\r", flush=True)
        # A fixed pause between calls. Free endpoints rate-limit aggressively,
        # and a 429 is indistinguishable in the results from "the model had
        # nothing to add" - every failure falls back to the heuristic verdict
        # and contributes a spurious "no change".
        if index < planned and not args.rpm:
            time.sleep(args.delay)
    print()

    failed = [c for c in changes if c.error]
    if len(failed) > planned * 0.1:
        print(
            f"\n  WARNING: {len(failed)}/{planned} calls failed. Every failure falls back\n"
            "  to the heuristic verdict, so the result is biased towards 'the AI\n"
            "  changed nothing'. Treat the numbers below as a lower bound on the\n"
            "  model's effect, and fix the provider before drawing conclusions.\n"
        )

    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "changes.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "file",
                "label",
                "static_score",
                "static_verdict",
                "ai_score",
                "ai_verdict",
                "indicators",
                "model_said",
                "tokens",
                "error",
            ]
        )
        for c in changes:
            writer.writerow(
                [
                    c.path,
                    c.label,
                    c.static_score,
                    c.static_verdict,
                    c.ai_score,
                    c.ai_verdict,
                    c.indicators,
                    c.ai_said,
                    c.tokens,
                    c.error,
                ]
            )

    before, after = confusion(changes, after=False), confusion(changes, after=True)
    errors = [c for c in changes if c.error]
    tokens = sum(c.tokens for c in changes)

    print(f"{'':<22}{'before':>10}{'after':>10}{'delta':>10}")
    for key, name in (
        ("tp", "true positives"),
        ("fp", "false positives"),
        ("tn", "true negatives"),
        ("fn", "false negatives"),
    ):
        delta = after[key] - before[key]
        print(f"{name:<22}{before[key]:>10}{after[key]:>10}{delta:>+10}")

    fixed = [
        c
        for c in changes
        if c.label == "clean" and c.static_score >= QUARANTINE and c.ai_score < QUARANTINE
    ]
    broken = [
        c
        for c in changes
        if c.label == "malware" and c.static_score >= QUARANTINE and c.ai_score < QUARANTINE
    ]

    # Threshold crossings are not the whole story. A clean file moved from 60 to
    # 75 counts as a true negative before and after, so a model that inflates
    # ordinary documents looks harmless until one finally crosses 80 - by which
    # point the pressure has been building unmeasured. Report the drift itself.
    pushed = [
        c for c in changes if c.label == "clean" and not c.error and c.ai_score > c.static_score
    ]
    near = [c for c in pushed if c.ai_score >= QUARANTINE - 10]
    clean_ok = [c for c in changes if c.label == "clean" and not c.error]
    if clean_ok:
        drift = sum(c.ai_score - c.static_score for c in clean_ok) / len(clean_ok)
        print(
            f"\nMean score change on clean files: {drift:+.1f}"
            "   (negative is the desired direction)"
        )
        print(f"Clean files pushed upward:  {len(pushed)}/{len(clean_ok)}")
        if near:
            print(f"  ...of which within 10 points of quarantine: {len(near)}")
            for c in sorted(near, key=lambda x: -x.ai_score):
                print(
                    f"    {c.path[:42]:<44}{c.static_score:>4} -> {c.ai_score:<4}"
                    f" model said {c.ai_said or '?'}"
                )

    # A model with nothing to say can still answer every time. gpt-4o-mini
    # returned 85 on eight of ten files with confidence 0.9 - fluent, confident
    # and constant. Every other metric here reads that as agreement. Spread is
    # what separates a second opinion from an expensive echo.
    scored = [c for c in changes if not c.error and c.ai_said]
    if len(scored) >= 5:
        values = [c.ai_score for c in scored]
        modal = Counter(values).most_common(1)[0]
        labels = Counter(c.ai_said for c in scored)
        print(f"\nDistinct fused scores:      {len(set(values))} across {len(scored)} files")
        print(f"Most common score:          {modal[0]} on {modal[1]} of {len(scored)}")
        print(
            "Model verdicts:             " + ", ".join(f"{k} {v}" for k, v in labels.most_common())
        )
        if modal[1] > len(scored) * 0.6 or len(labels) == 1:
            print(
                "\n  WARNING: the model's output barely varies. A near-constant\n"
                "  answer cannot discriminate, and every gain below is then\n"
                "  coincidence - it would 'catch' malware by calling everything\n"
                "  malicious. Try a stronger model before reading further.\n"
            )

    print(f"\nFalse positives corrected: {len(fixed)}")
    print(f"True positives lost:       {len(broken)}")
    print(f"Tokens used:               {tokens:,}")
    if errors:
        print(f"Errors:                    {len(errors)}  (see changes.csv)")

    # The individual moves are the evidence at this sample size. A reviewer
    # should be able to check each one by hand.
    moved = [c for c in changes if c.moved and not c.error]
    if moved:
        print(f"\n{len(moved)} verdict changes:")
        print(f"  {'file':<44}{'label':<9}{'static':>14}{'fused':>16}")
        for c in sorted(moved, key=lambda x: -x.static_score)[:40]:
            print(
                f"  {c.path[:42]:<44}{c.label:<9}"
                f"{c.static_verdict + ' ' + str(c.static_score):>14}"
                f"{c.ai_verdict + ' ' + str(c.ai_score):>16}"
            )

    print(f"\nWrote {args.out / 'changes.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
