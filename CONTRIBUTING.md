# Contributing to PDFSafe

Thanks for considering it. This document covers the two contributions that
matter most for a scanner — **reporting a false positive** and **adding a
detection rule** — plus the usual setup.

Security vulnerabilities go through [`SECURITY.md`](SECURITY.md), not the issue
tracker.

## The most valuable contribution

**Tell us when PDFSafe is wrong about an ordinary document.**

The heuristic weights were set by hand and have never been validated against a
large corpus of real-world PDFs. We do not currently know the false-positive
rate. If PDFSafe flags an invoice, a bank statement, a signed contract or a
government form, that is a genuine defect and we want the report.

Use the **False positive** issue template. You do not need to attach the
document — the indicator list and score are usually enough, and if the file is
confidential, please don't send it.

## Setup

```bash
git clone https://github.com/<your-fork>/pdfsafe
cd pdfsafe
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

Building `pikepdf` and `yara-python` from source needs system libraries:

```bash
sudo apt-get install build-essential libqpdf-dev   # Debian/Ubuntu
brew install qpdf                                  # macOS
```

On Windows, install the prebuilt wheels rather than compiling.

### Before you push

```bash
pytest
ruff check src tests
ruff format src tests
mypy src
```

All four must pass. `mypy` runs in strict mode.

### Antivirus will delete your files

PDFSafe's source contains malware signatures by necessity — the token tables in
`analysis/constants.py`, the YARA rules, and the test fixtures. Windows Defender
has already silently deleted files from this repository mid-development. Add an
exclusion before you start:

```powershell
Add-MpPreference -ExclusionPath "<path-to-your-clone>"
```

When writing tests, assemble signature-like strings at runtime from fragments
rather than as literals. `tests/fixtures/pdf_builder.py` shows the pattern.

## Adding a detection rule

Rules live in `src/pdfsafe/analysis/heuristics.py`. Each is a function decorated
with `@rule` that yields zero or more `IndicatorResult`s:

```python
@rule
def r_my_detection(result: StaticAnalysisResult) -> Iterable[IndicatorResult]:
    if not <condition>:
        return
    yield _indicator(
        "PDF_MY_DETECTION",          # stable, machine-readable, never renamed
        "One-line human summary",
        Severity.MEDIUM,
        35,                          # weight, 0-100
        "category",
        "Why this matters, and why a legitimate document rarely does it.",
        mitre="T1204.002",           # optional
        evidence_field=...,          # whatever a human needs to verify it
    )
```

### What we look for in a rule

**Weights are not severity.** The weight is roughly "how much does this alone
move me toward malicious". Weights combine with a noisy-OR, so several 30s add
up meaningfully — you rarely want anything above 60 unless the finding is close
to conclusive on its own.

**Justify the weight in the description.** The description is shown to the user
and sent to the AI reviewer. "Contains JavaScript" is not useful; "JavaScript
reachable from /OpenAction runs with no user interaction" is.

**Consider the benign case first.** Ask what fraction of ordinary business
documents would trip this. Forms have JavaScript. Invoices have links. If a rule
fires on 5% of normal documents it needs a low weight or a tighter condition.

**Attach evidence a human can check.** The indicator's `evidence` dict should
let someone confirm or refute the finding without re-running the scan.

**Every rule needs a test both ways** — a fixture that trips it, and confirmation
that a benign document does not. Add fixtures to
`tests/fixtures/pdf_builder.py`.

### YARA rules

Signature rules go in `src/pdfsafe/analysis/rules/pdf_malware.yar`. Include
`severity` and `description` in the `meta` block — the scoring bridge reads them:

```yara
rule PDFSafe_Example {
    meta:
        author      = "you"
        description = "What this catches"
        severity    = "high"          // critical | high | medium | low | info
        category    = "active_content"
        mitre       = "T1204.002"     // optional
    strings:
        $a = "..."
    condition:
        $a
}
```

## Pull requests

- One logical change per PR.
- Explain **why**, not just what. The code shows what changed.
- New behaviour needs tests. Bug fixes need a test that fails without the fix.
- Public functions get type annotations and a docstring explaining the *reason*
  for non-obvious choices.
- Don't reformat unrelated code — it buries the actual change.

Comments should explain reasoning, not restate the code. `# increment counter`
above `counter += 1` is noise; `# Renaming rather than deleting: the verdict
comes from untuned heuristics` is the kind that earns its space.

## Project structure

```
src/pdfsafe/
  analysis/    parsing, JS/URL analysis, YARA, scoring   ← most contributions
  ai/          provider abstraction, evidence, cost gate
  local/       SQLite, scan queue, sandbox, watcher
  desktop/     PySide6 window, tray, dialogs
  cli.py       Typer CLI
```

Layering rule: `desktop/` may import `local/`, `local/` may import `analysis/`
and `ai/`, and **nothing outside `desktop/` may import Qt**. That keeps the
engine testable headlessly and the CLI free of a GUI dependency.

## Things we will probably say no to

- Executing or rendering document content. PDFSafe reads structure; a detonation
  sandbox is a different product.
- Bundling an API key, or routing AI calls through a service we operate. Users
  supply their own key.
- Deleting user files automatically. Quarantine renames, deliberately.
- New runtime dependencies without a strong case — everything here ships inside
  the executable.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
