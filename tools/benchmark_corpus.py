"""Measure PDFSafe's detection and false-positive rates against a labelled corpus.

Run it over a directory whose immediate subdirectories are datasets, labelled by
name (``MALWARE_...`` / ``CLEAN_...``)::

    python tools\\benchmark_corpus.py "Testing Folders\\Testing Folders" --out benchmark

Two design decisions worth explaining, because they are what separate a useful
measurement from a misleading one.

**Indicators are recorded per file, not just the score.** A score alone cannot
tell you *why* a file was flagged. ``PDF_PARSE_FAILURE`` carries a weight of 40
and no severity floor, so any document that merely fails to parse lands on
exactly 40 — indistinguishable, by score, from a document that scored 40 through
genuine suspicion. On a historical malware corpus that single rule can account
for the overwhelming majority of apparent detections, which inflates recall into
a number the rule set did not earn. This script therefore reports an *adjusted*
recall that excludes files whose only finding was a parse failure.

**Metrics are reported at the product's own thresholds** (20 / 50 / 80), because
those are the numbers that decide what a user actually sees. Reporting an
invented optimum that maximises F1 describes a scanner nobody is running.

Analysis runs in-process rather than through the sandbox: isolation protects the
application from hostile input, it does not change the verdict, and spawning a
process per file would dominate the runtime on a corpus this size.

Antivirus will interfere. Exclude the corpus directory before running, or
Defender will delete samples mid-measurement and silently skew the result.
"""

from __future__ import annotations

import argparse
import csv
import multiprocessing
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# The corpus is scored by the static engine only; an AI call per file would cost
# money and is not what this benchmark measures.
os.environ.setdefault("PDFSAFE_AI_ENABLED", "false")
os.environ.setdefault("PDFSAFE_LOG_LEVEL", "ERROR")

#: Thresholds PDFSafe actually ships with, plus a few neighbours for shape.
THRESHOLDS = (10, 20, 25, 35, 40, 50, 80)

#: Bands the user is shown, from pdfsafe.analysis.constants.
PRODUCT_BANDS = {20: "low risk", 50: "suspicious", 80: "malicious (quarantined)"}

#: Scoring a file solely on this means "the document is broken", not "the
#: document is hostile". Counting it as a detection overstates the rule set.
PARSE_ONLY_CODES = {"PDF_PARSE_FAILURE"}

MALWARE = "malware"
CLEAN = "clean"


@dataclass(slots=True)
class FileResult:
    path: str
    dataset: str
    label: str
    score: int
    verdict: str
    indicators: list[str] = field(default_factory=list)
    is_pdf: bool = True
    error: str = ""
    #: Raw count of hex-escaped name objects, recorded whether or not the rule
    #: fired. Without the distribution there is no way to choose the threshold
    #: from evidence rather than by guessing, which is how the rule ended up
    #: mis-tuned in the first place.
    obfuscated_names: int = 0

    @property
    def parse_failure_only(self) -> bool:
        return bool(self.indicators) and set(self.indicators) <= PARSE_ONLY_CODES


def label_for(dataset: str) -> str | None:
    """Infer ground truth from the dataset directory name."""
    upper = dataset.upper()
    if "MALWARE" in upper:
        return MALWARE
    if "CLEAN" in upper:
        return CLEAN
    return None


def analyse_one(job: tuple[str, str, str]) -> FileResult:
    """Worker body. Imports happen here so each process pays the cost once."""
    path_str, dataset, label = job
    path = Path(path_str)

    from pdfsafe.analysis.pipeline import analyze_bytes, looks_like_pdf

    try:
        data = path.read_bytes()
    except OSError as exc:
        return FileResult(path_str, dataset, label, 0, "error", error=f"read: {exc}")

    if not looks_like_pdf(data):
        # Non-PDF input is not a false positive for a PDF scanner - it is out of
        # scope. Recorded separately rather than dropped, because a corpus that
        # quietly contains .xls files would otherwise distort every rate here.
        return FileResult(path_str, dataset, label, 0, "not-pdf", is_pdf=False)

    try:
        output = analyze_bytes(data, filename=path.name)
    except Exception as exc:
        return FileResult(
            path_str, dataset, label, 0, "error", error=f"{type(exc).__name__}: {exc}"
        )

    return FileResult(
        path_str,
        dataset,
        label,
        output.outcome.score,
        output.outcome.verdict.value,
        [i.code for i in output.outcome.indicators],
        obfuscated_names=int(output.result.keyword_counts.get("__obfuscated_names__", 0)),
    )


def collect_jobs(root: Path) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Walk the corpus, returning work items and any unlabelled directories."""
    jobs: list[tuple[str, str, str]] = []
    unlabelled: list[str] = []

    for dataset_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        label = label_for(dataset_dir.name)
        if label is None:
            unlabelled.append(dataset_dir.name)
            continue
        for path in dataset_dir.rglob("*"):
            if path.is_file():
                jobs.append((str(path), dataset_dir.name, label))

    return jobs, unlabelled


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def specificity(self) -> float:
        return self.tn / (self.tn + self.fp) if (self.tn + self.fp) else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.tn + self.fp) if (self.tn + self.fp) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def confusion(results: list[FileResult], threshold: int, *, strict: bool = False) -> Metrics:
    """Confusion matrix at ``threshold``.

    With ``strict``, a malware file detected only through a parse failure counts
    as a miss. That is the honest reading: the engine noticed the file was
    broken, not that it was dangerous.
    """
    m = Metrics()
    for r in results:
        if not r.is_pdf or r.error:
            continue
        flagged = r.score >= threshold
        if strict and flagged and r.parse_failure_only:
            flagged = False
        if r.label == MALWARE:
            if flagged:
                m.tp += 1
            else:
                m.fn += 1
        elif flagged:
            m.fp += 1
        else:
            m.tn += 1
    return m


def _row(threshold: int, m: Metrics) -> str:
    return (
        f"| {threshold} | {m.tp} | {m.fp} | {m.tn} | {m.fn} | "
        f"{m.precision:.2%} | {m.recall:.2%} | {m.specificity:.2%} | "
        f"{m.fpr:.2%} | {m.f1:.4f} |"
    )


def write_summary(results: list[FileResult], out: Path, elapsed: float, workers: int) -> str:
    scored = [r for r in results if r.is_pdf and not r.error]
    malware = [r for r in scored if r.label == MALWARE]
    clean = [r for r in scored if r.label == CLEAN]
    non_pdf = [r for r in results if not r.is_pdf]
    errors = [r for r in results if r.error]

    parse_only = [r for r in malware if r.parse_failure_only]
    header = (
        "| Cutoff | TP | FP | TN | FN | Precision | Recall | Specificity | FPR | F1 |\n"
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )

    lines: list[str] = [
        "# PDFSafe corpus benchmark",
        "",
        f"{len(results):,} files examined in {elapsed:.1f}s "
        f"({len(results) / elapsed:.1f} files/s, {workers} workers, static engine only).",
        "",
        "## Corpus",
        "",
        "| Dataset | Label | Files scored |",
        "|---|---|---:|",
    ]

    by_dataset: Counter[tuple[str, str]] = Counter((r.dataset, r.label) for r in scored)
    for (dataset, label), count in sorted(by_dataset.items()):
        lines.append(f"| {dataset} | {label} | {count:,} |")

    lines += [
        f"| **Total scored** | — | **{len(scored):,}** |",
        "",
        f"Excluded: {len(non_pdf):,} non-PDF files, {len(errors):,} read/analysis errors.",
        "",
        "## Headline numbers, at the thresholds PDFSafe ships",
        "",
        "| Score band | Meaning to the user | Clean files flagged | Rate |",
        "|---:|---|---:|---:|",
    ]

    for t, meaning in PRODUCT_BANDS.items():
        flagged = sum(1 for r in clean if r.score >= t)
        rate = flagged / len(clean) if clean else 0.0
        lines.append(f"| ≥ {t} | {meaning} | {flagged:,} / {len(clean):,} | **{rate:.2%}** |")

    lines += [
        "",
        "The last row is the one that decides whether this is safe to ship: those",
        "files are renamed on the user's disk without being asked.",
        "",
        "## Detection, as measured",
        "",
        header,
    ]
    for t in THRESHOLDS:
        lines.append(_row(t, confusion(scored, t)))

    lines += [
        "",
        "## Detection, excluding parse-failure-only findings",
        "",
        f"**{len(parse_only):,} of {len(malware):,} malware files "
        f"({len(parse_only) / len(malware):.1%} of the corpus) were flagged solely "
        "because they failed to parse.**",
        "",
        "`PDF_PARSE_FAILURE` has weight 40 and no severity floor, so those files score",
        "exactly 40. That finding means the document is malformed - which a corrupted",
        "but harmless PDF also is. Counting it as detection credits the rule set with",
        "work it did not do, and would not survive contact with modern malware, which",
        "parses cleanly on purpose.",
        "",
        header,
    ]
    for t in THRESHOLDS:
        lines.append(_row(t, confusion(scored, t, strict=True)))

    lines += [
        "",
        "## What fires on clean documents",
        "",
        "| Indicator | Clean files | Rate |",
        "|---|---:|---:|",
    ]
    clean_codes: Counter[str] = Counter(c for r in clean for c in set(r.indicators))
    for code, count in clean_codes.most_common(15):
        lines.append(f"| `{code}` | {count:,} | {count / len(clean):.2%} |")

    worst = sorted((r for r in clean if r.score >= 80), key=lambda r: -r.score)
    lines += [
        "",
        f"## Clean documents scoring ≥ 80 ({len(worst):,})",
        "",
        "These would be quarantined automatically. Every one is a bug report.",
        "",
        "| Score | Dataset | File | Indicators |",
        "|---:|---|---|---|",
    ]
    for r in worst[:40]:
        codes = ", ".join(f"`{c}`" for c in r.indicators) or "—"
        lines.append(f"| {r.score} | {r.dataset} | {Path(r.path).name} | {codes} |")
    if len(worst) > 40:
        lines.append(f"| … | | {len(worst) - 40:,} more in results.csv | |")

    # Name obfuscation is scored by how many hex escapes a document contains, so
    # the threshold has to come from the distribution rather than from taste.
    lines += [
        "",
        "## Hex-escaped names: where to put the threshold",
        "",
        "| Minimum escapes | Malware | Benign | Ratio |",
        "|---:|---:|---:|---:|",
    ]
    for cutoff in (1, 2, 3, 5, 10, 20, 50):
        mal = sum(1 for r in malware if r.obfuscated_names >= cutoff)
        ben = sum(1 for r in clean if r.obfuscated_names >= cutoff)
        mal_rate = mal / len(malware) if malware else 0.0
        ben_rate = ben / len(clean) if clean else 0.0
        ratio = f"{mal_rate / ben_rate:.1f}x" if ben_rate else "—"
        lines.append(
            f"| >= {cutoff} | {mal:,} ({mal_rate:.2%}) | {ben:,} ({ben_rate:.2%}) | **{ratio}** |"
        )
    lines += [
        "",
        "Pick the cutoff where the ratio is highest and the malware count is still",
        "worth having. A ratio near 1 means the rule is measuring how the producer",
        "writes names, not what the author intended.",
    ]

    lines += [
        "",
        "## What fires on malware",
        "",
        "| Indicator | Malware files | Rate |",
        "|---|---:|---:|",
    ]
    malware_codes: Counter[str] = Counter(c for r in malware for c in set(r.indicators))
    for code, count in malware_codes.most_common(15):
        lines.append(f"| `{code}` | {count:,} | {count / len(malware):.2%} |")

    text = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(text, encoding="utf-8")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Directory whose subdirectories are datasets")
    parser.add_argument("--out", type=Path, default=Path("benchmark"))
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    parser.add_argument("--limit", type=int, default=0, help="Sample N files per dataset (0 = all)")
    args = parser.parse_args()

    if not args.root.is_dir():
        print(f"Not a directory: {args.root}", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)

    jobs, unlabelled = collect_jobs(args.root)
    if unlabelled:
        print(f"Skipped unlabelled directories: {', '.join(unlabelled)}", file=sys.stderr)
        print("Rename them to contain MALWARE or CLEAN to include them.", file=sys.stderr)

    if args.limit:
        capped: list[tuple[str, str, str]] = []
        seen: Counter[str] = Counter()
        for job in jobs:
            if seen[job[1]] < args.limit:
                capped.append(job)
                seen[job[1]] += 1
        jobs = capped

    if not jobs:
        print("No files found.", file=sys.stderr)
        return 1

    print(f"Scoring {len(jobs):,} files with {args.workers} workers…")
    started = time.perf_counter()
    results: list[FileResult] = []

    with multiprocessing.Pool(args.workers) as pool:
        for done, result in enumerate(pool.imap_unordered(analyse_one, jobs, chunksize=16), 1):
            results.append(result)
            if done % 250 == 0 or done == len(jobs):
                rate = done / (time.perf_counter() - started)
                print(f"  {done:,}/{len(jobs):,}  ({rate:.1f}/s)", end="\r", flush=True)

    elapsed = time.perf_counter() - started
    print()

    with (args.out / "results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "path",
                "dataset",
                "label",
                "score",
                "verdict",
                "indicators",
                "obfuscated_names",
                "error",
            ]
        )
        for r in results:
            writer.writerow(
                [
                    r.path,
                    r.dataset,
                    r.label,
                    r.score,
                    r.verdict,
                    ";".join(r.indicators),
                    r.obfuscated_names,
                    r.error,
                ]
            )

    print(write_summary(results, args.out, elapsed, args.workers))
    print(f"\nWrote {args.out / 'results.csv'} and {args.out / 'summary.md'}")
    return 0


if __name__ == "__main__":
    # Required on Windows: the pool re-imports this module in every child.
    multiprocessing.freeze_support()
    sys.exit(main())
