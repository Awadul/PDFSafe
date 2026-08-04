"""Print the exact prompt the model receives for one file.

    python tools/show_prompt.py "path/to/clean.pdf"
    python tools/show_prompt.py benchmark-corroborated/results.csv --label clean

Four models from four vendors returned "malicious" for nearly every escalated
file. When independent systems agree that strongly, the shared input is the more
likely cause than the models, and the shared input is this prompt.

The bundle is assembled from indicators, suspicious JavaScript and YARA hits -
that is, from findings. A document with nothing wrong contributes nothing to it.
So the question we actually ask is closer to "here are five bad things, is this
bad?" than to "is this bad?", and confident agreement is the correct answer to
the question as posed. Read a benign file's prompt before blaming a model: if it
reads as an indictment, no model can clear the document.
"""

from __future__ import annotations

import argparse
import csv
import os
import random
from pathlib import Path

os.environ.setdefault("PDFSAFE_LOG_LEVEL", "ERROR")


def resolve(target: Path, label: str, seed: int) -> Path:
    if target.suffix.lower() != ".csv":
        return target
    with target.open(encoding="utf-8") as handle:
        rows = [
            r
            for r in csv.DictReader(handle)
            if r.get("score") and not r.get("error") and r.get("label") == label
        ]
    if not rows:
        raise SystemExit(f"No {label} rows in {target}")
    # Prefer a file that actually reached the model, since a document scoring
    # zero never gets escalated and its prompt is not the one under suspicion.
    escalated = [r for r in rows if 25 <= int(r["score"]) <= 85] or rows
    # Reproducible file choice, not a security decision.
    return Path(random.Random(seed).choice(escalated)["path"])  # noqa: S311


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="a PDF, or a results.csv to sample from")
    parser.add_argument("--label", default="clean", choices=["clean", "malware"])
    parser.add_argument("--seed", type=int, default=20260804)
    args = parser.parse_args()

    from pdfsafe.ai.evidence import build_evidence
    from pdfsafe.ai.prompts import build_system_prompt, build_user_prompt
    from pdfsafe.analysis.pipeline import analyze_bytes

    path = resolve(args.target, args.label, args.seed)
    output = analyze_bytes(path.read_bytes(), filename=path.name)
    evidence = build_evidence(output.result, output.outcome)

    print(f"=== {path.name}  ({args.label}, heuristic {output.outcome.score}) ===\n")
    print("--- system ---")
    print(build_system_prompt())
    print("\n--- user ---")
    prompt = build_user_prompt(evidence)
    print(prompt)

    print("\n" + "=" * 70)
    print(f"user prompt: {len(prompt):,} chars")
    print(
        "Ask while reading: is there anything here that could talk the model OUT\n"
        "of a malicious verdict? If every section is a finding, the prompt is an\n"
        "indictment and the verdict is decided before the model sees it."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
