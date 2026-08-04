# PDFSafe

[![CI](https://github.com/Awadul/PDFSafe/actions/workflows/ci.yml/badge.svg)](https://github.com/Awadul/PDFSafe/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

A Windows desktop application that scans PDF files for malicious content before you open
them. It works entirely offline; AI review is optional and uses your own API key.

Measured against 20,207 real documents: **0.32%** false positives at the quarantine
threshold from the static engine alone, **0.09%** with AI review enabled, with no
detection loss. Both figures, and the code that produced them, are in this repository.

```
PDFSafe.exe  →  drop a PDF  →  static analysis  →  verdict in ~1 second
                                      ↓
                            ambiguous? → optional AI second opinion
```

---

## What it does

Most PDF malware works the same handful of ways: JavaScript that runs the moment the
document opens, a `/Launch` action that starts a program, an executable hidden as an
attachment, or a link designed to harvest credentials. PDFSafe parses the document
structure and looks for exactly those capabilities, then scores what it finds.

|                                |                                                                         |
| ------------------------------ | ----------------------------------------------------------------------- |
| **Verdict in about a second**  | Structural analysis, no signatures to download, no cloud round-trip     |
| **Works offline**              | Every rule runs locally. With AI review off, nothing leaves the machine |
| **Optional AI second opinion** | For ambiguous files — [measured](#measured-effect) at 72% fewer false positives, no detection loss |
| **Quarantine**                 | Malicious files are renamed so they cannot open by accident — never deleted |
| **Watch folders**              | New PDFs in Downloads are scanned automatically                         |
| **Explorer integration**       | Right-click any PDF → _Scan with PDFSafe_                               |
| **Optional OCR**               | Reads text out of scanned documents. Off by default — [see why](#5-ocr--optional-and-off-by-default) |

### What it does not do

It is a detection aid, not an antivirus. It reads document structure; it does not
execute documents in a sandbox, monitor running processes, or scan anything but PDFs.
A clean verdict means "no dangerous structure found", not "definitely safe".

---

## Install

> **Status: pre-release.** There is no published installer yet, and builds are
> currently unsigned, so SmartScreen will warn. Build from source for now —
> see [For developers](#for-developers).

Once releases are published, download `PDFSafe-x.y.z-setup.exe` from
[Releases](https://github.com/Awadul/PDFSafe/releases) and run it. No
administrator rights required — it installs per-user and can be removed from
Add/Remove Programs.

Requires 64-bit Windows 10 1809 or later.

---

## How the analysis works

### 1. Structural parsing

The file is parsed **in a separate, disposable process**. This matters: parsing hostile
input is where a scanner is most likely to be attacked, and a parser crash or hang in a
child process is an error message instead of a crashed application. The child is killed
if it exceeds the timeout.

What gets extracted:

| Category       | Detections                                                                                                                                            |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Active content | Embedded JavaScript, `/OpenAction`, `/AA` triggers, `/Launch`, XFA forms                                                                              |
| Obfuscation    | Hex-escaped names (`/J#61vaScript`), escape density, `fromCharCode`/`eval`/`unescape` chains, packed strings, mangled identifiers                     |
| Exploits       | Reader APIs tied to known CVEs (`util.printf`, `Collab.getIcon`, `media.newPlayer`, …), heap-spray patterns, `JBIG2Decode`                            |
| Attachments    | Executable extensions and magic bytes, extension/content mismatch, archives, macro-capable Office files, high-entropy blobs                           |
| Network        | `file:`/`smb:`/`javascript:` URIs and UNC paths, raw-IP hosts, link shorteners, punycode homographs, abuse-prone TLDs, `/GoToR` remote references     |
| Structure      | Shifted headers, data appended after `%%EOF`, excessive incremental updates, encryption, parse failures, near-empty documents carrying active content |
| Signatures     | Bundled YARA rules                                                                                                                                    |

### 2. Scoring

Twenty-three rules produce a 0–100 risk score. Weights combine with a **noisy-OR** rather
than a sum, so several weak signals accumulate without any pair of them saturating the
scale, and a `critical` finding imposes a floor.

Three rules carry a weight of zero. They were measured against a real corpus and found to
fire as often on ordinary documents as on malware, so they are reported as context but
excluded from the score — see [Which rules earn their weight](#which-rules-earn-their-weight).

```
 0 ────────── 20 ────────── 50 ────────── 80 ────── 100
    clean       low risk      suspicious    malicious
```

### 3. AI review — only when it changes the answer

```
score < 25    →  decided locally: clean            no API call
25 – 84       →  ambiguous: ask the model          one API call
score ≥ 85    →  decided locally: malicious        no API call
              ...unless ≤ 3 indicators raised it   one API call
```

That last line matters. A score of 90 built from seven agreeing findings is not the same
claim as a score of 90 resting on two, but the band alone cannot tell them apart. Measured
on the corpus, high scores with thin evidence ran twelve false positives to one true
positive, so evidence count now gates escalation alongside the score.

In normal use almost everything scores near zero, so the model is consulted rarely. When
it is, it receives a **summary of the evidence** — structure, indicators, decoded
JavaScript, URLs — never the document itself.

Three rules govern the result:

- A `critical` local finding imposes a floor. The model cannot clear a file that
  demonstrably carries an executable.
- The final score keeps 40% of the local weight, so a confidently wrong model cannot drag
  a heavily-indicated file to zero.
- **The verdict is derived from the final score, never set independently.** If the model
  returns a label and a number that contradict each other — which the response schema
  permits, since the two fields are validated separately — the label wins and the score
  moves into its band. A model picks a category far more reliably than it emits a
  calibrated number.

That last rule exists because it was once absent. The label came from the model and the
number from the blend, so PDFSafe could report one file as *malicious* at 64/100 and
another as *suspicious* at 70/100 — a worse label on a lower number, leaving the score
useless for ranking anything.

A fourth rule governs the prompt rather than the result: **the model is not told the
heuristic's score.** Sharing it produced agreement instead of review — one model returned
the engine's own number on half the sample and called every file malicious, including the
clean ones. Agreement laundered as corroboration is worse than no second opinion, so the
model now sees the evidence and not the conclusion.

#### Measured effect

Running the model over 20,000 documents would spend real money to answer a question a few
hundred calls answer better. The measurement is **paired** — each file is scored by the
static engine and then by the fused verdict — so it reports a per-file delta rather than
an estimate of a population rate, and sampling error does not enter it. Selection
therefore targets the cases where the two could disagree: every false positive at the
quarantine threshold, thin-evidence verdicts, and controls drawn from true positives at
each score band.

`google/gemini-2.5-flash`, 150 files, 719,559 tokens (about $0.30), zero failed calls:

| | static only | with AI review |
|---|---:|---:|
| True positives | 91 | **101** |
| False positives | 29 | **8** |
| True negatives | 15 | 36 |
| False negatives | 15 | **5** |

**Twenty-one of twenty-nine quarantine-threshold false positives removed, with zero true
positives lost.** That bucket held every such file in the corpus rather than a sample of
them, so the figure carries over directly:

> **Quarantine false-positive rate: 0.32% → 0.09%.**

The ten recovered detections come from sampled buckets and do not extrapolate the same
way; on the tested files, ten of fifteen missed detections were recovered.

The corrections are legible, which matters more than the totals. Every `RichContentorFlash`
sample, the IRS `f8xxx` accessible-forms family and the `purepdf_*` demos — scripted but
benign documents the static rules over-weight. The eight promoted malware files all sat at
exactly 76, capped by the corroboration ceiling, and the model supplied the corroboration
the rules could not.

**Where it does not help:** eight of forty-four clean files drifted upward, one from 40 to
70. None crossed the quarantine threshold, but the layer is net positive with a small
countervailing effect rather than uniformly protective. Reproduce with:

```bash
python tools/benchmark_ai.py benchmark-corroborated/results.csv --max-calls 150
```

Model choice matters more than expected. Of five models tested, three returned a
near-constant score regardless of evidence — one answered 85 on eight of ten files at
confidence 0.9. The benchmark reports score spread for exactly this reason: a model that
calls everything malicious will "catch" malware and look successful in every other metric.

Thresholds are adjustable in Settings.

### 4. Quarantine — defused, not destroyed

A file judged malicious is **renamed, not deleted**: `invoice.pdf` becomes
`invoice.pdf.quarantine`, so Windows no longer hands it to a PDF reader on a
double-click. PDFSafe's own copy is moved to the quarantine folder and renamed the
same way.

Nothing is destroyed, deliberately. The verdict comes from heuristics whose
false-positive rate has not been measured against a real corpus, and losing a
document you needed is a worse outcome than having to rename one back. You can see
exactly which indicators fired, judge for yourself, and click **Mark as safe** to
restore the original name.

---

### 5. OCR — optional, and off by default

A scanned document contains no extractable text. Every text-based signal is blind to it:
phishing wording is invisible to both the rules and the model, and a scanned form is hard
to tell apart from a near-empty dropper, because both look like a page with nothing on it.

OCR closes that gap by rasterising the first few pages and reading them back.

```powershell
winget install UB-Mannheim.TesseractOCR   # the engine, one Apache-2.0 binary
pip install -e ".[ocr-tesseract]"         # the Python side
```

Then enable it in **Settings → Scanning**, or:

```powershell
$env:PDFSAFE_OCR_ENABLED = "true"
python -c "from pdfsafe.analysis import ocr; print(ocr.available())"   # (True, 'tesseract')
```

**Why it is off by default.** Everywhere else PDFSafe reads structure and never renders.
OCR requires running a rendering engine over attacker-controlled input, and rasterisers
have their own history of memory-corruption bugs. That is a real trade, not a footnote —
`SECURITY.md` treats rendering bugs reachable through OCR as in scope.

Three things contain it, and a fourth keeps it affordable:

| | |
|---|---|
| Runs in the parser sandbox | rendering happens in the disposable child process, under the same hard timeout |
| Capped | 3 pages, 200 DPI ceiling, 4,000 characters |
| Optional dependency | no rendering engine or OCR model ships in the installer |
| **Gated on relevance** | only documents that *also* carry active content, an embedded file, a YARA hit or a risky link |

That last gate is what makes it usable. Only two things ever read the recovered text: the
"nearly empty document" rule, which cannot fire unless the document has active content,
and the evidence bundle sent to the model, which only exists for escalated files. Without
the gate, a corpus run spent ~30 s per file writing text that nothing read — about 55
hours for 20,000 documents.

Every scan records `text_source` as `extracted`, `ocr` or `none`. Extracted text is exact;
OCR output is a guess, and anything weighing it should know which it holds.

Settings: `ocr_enabled`, `ocr_engine`, `ocr_min_text_chars`, `ocr_max_pages`, `ocr_dpi`,
`ocr_max_chars`, `ocr_only_when_relevant`, `ocr_tesseract_path`.

---

## Privacy

**A default install opens no network connection at all.** AI review and the update
check are both off until you turn them on.

With AI review **on**, ambiguous files produce one request to the provider you
configured, containing the evidence summary described above. You can exclude the document
text excerpt in Settings if your documents are sensitive.

With the update check **on**, PDFSafe fetches a small JSON manifest and sends nothing
but the request itself — no version, no identifier, no file information.

Your API key is stored in **Windows Credential Manager**, encrypted against your user
account. It is never written to the settings file or the logs. PDFSafe ships with no key
of its own — one embedded in the executable would be extractable in minutes, so the
application asks for yours instead.

There is no telemetry.

---

## Where things are kept

|              |                                               |
| ------------ | --------------------------------------------- |
| Settings     | `%APPDATA%\PDFSafe\config.json`               |
| Scan history | `%LOCALAPPDATA%\PDFSafe\data\pdfsafe.sqlite3` |
| Quarantine   | `%LOCALAPPDATA%\PDFSafe\quarantine`           |
| Logs         | `%LOCALAPPDATA%\PDFSafe\logs`                 |
| API key      | Windows Credential Manager (`PDFSafe`)        |

Uninstalling removes the program and offers to remove your history and quarantine.

---

## For developers

Every command below runs from the repository root and uses relative paths.

### Run from source

```powershell
git clone https://github.com/Awadul/PDFSafe
cd PDFSafe
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev,desktop]"

pdfsafe-desktop                      # the GUI
pdfsafe scan <file.pdf>              # the CLI
pdfsafe scan <folder> --json --no-ai # bulk, machine-readable, no API calls
```

Omit `desktop` from the extras if you only want the CLI — it skips the ~90 MB Qt
download. Add `ocr-tesseract` if you are working on scanned-document handling; see
[OCR](#5-ocr--optional-and-off-by-default).

Available extras: `desktop`, `build`, `dev`, `ocr`, `ocr-tesseract`, `ocr-rapidocr`.

System libraries for building `pikepdf` and `yara-python` from source:

```bash
# Debian/Ubuntu
sudo apt-get install build-essential libqpdf-dev
# macOS
brew install qpdf
```

On Windows, install the prebuilt wheels rather than compiling.

### Build the executable

```powershell
pip install -e ".[desktop,build]"
.\packaging\build.ps1 -SkipInstaller          # executable only, into dist\PDFSafe
.\packaging\build.ps1 -Clean                  # plus the Inno Setup installer
.\packaging\build.ps1 -CertificateThumbprint <thumbprint> -Clean   # signed
```

The script stops any running PDFSafe first — a copy left in the tray holds every
DLL in `dist\` open and PyInstaller reports that as an unhelpful *Access is
denied*. See [`packaging/README.md`](packaging/README.md) for signing, antivirus
false positives and release hosting.

Build with a python.org interpreter, not the Microsoft Store one: the Store build
embeds a `python312.dll` from a per-user `WindowsApps` package that will not be
present on the target machine.

### Layout

```
src/pdfsafe/
  analysis/       parsing, JS/URL analysis, YARA, scoring
  ai/             provider abstraction, evidence packaging, cost gate
  local/          SQLite, scan queue, sandbox, watcher, updater
  desktop/        PySide6 window, tray, dialogs, widgets
  schemas/        Pydantic contracts shared across the layers
  db/             SQLAlchemy base and ORM models
  storage/        content-addressed local storage and quarantine
  cli.py          Typer CLI
packaging/        PyInstaller spec, Inno Setup script, build pipeline
tools/            benchmarks, prompt inspection, icons, import-graph check,
                  reset_dev_state.ps1
tests/            pytest suite with synthetic malicious fixtures
```

**Layering rule:** `desktop/` may import `local/`; `local/` may import `analysis/` and
`ai/`; and nothing outside `desktop/` may import Qt. That keeps the engine testable
headlessly and the CLI free of a GUI dependency.

PDFSafe is a single-target desktop application. An earlier revision carried an optional
FastAPI/Celery/PostgreSQL server alongside it; that was removed, because the duplicated
orchestration silently drifted from the desktop engine twice and caused a real bug that
no test caught.

### Testing

```powershell
pytest -q                            # 197 tests
ruff check src tests                 # lint
ruff format --check src tests        # formatting (a different tool from the above)
mypy --platform win32 src            # strict, checked against the target OS
python tools\check_import_graph.py   # enforces the layering rule
```

`--platform win32` matters when checking from Linux: `winreg` and
`ctypes.WinDLL` are legitimately absent there, and reporting them wastes a
reviewer's time on six errors that cannot occur where the code runs.

CI additionally runs the engine suite on Linux without Qt installed
(`-m "not gui" -p no:pytest-qt`). That job exists to keep the analysis engine
independent of the desktop layer; if it starts needing PySide6, the layering
rule has been broken somewhere `check_import_graph.py` did not look.

Between manual GUI tests, reset the app's state so the same files can be scanned
again — quarantine renames the originals, so a second run is not the same test:

```powershell
.\tools\reset_dev_state.ps1 -TestFolder <folder-with-your-test-pdfs> -WhatIf
```

Drop `-WhatIf` to apply. It stops PDFSafe, clears the database, file store and
quarantine vault, and restores `.quarantine` filenames.

### Reproducing the measurements

```powershell
python tools\benchmark_corpus.py <corpus-root> --out benchmark      # static engine
python tools\analyse_escalation.py benchmark\results.csv            # plan AI cost, no calls
python tools\benchmark_ai.py benchmark\results.csv --max-calls 150  # measure the AI layer
python tools\show_prompt.py benchmark\results.csv --label clean     # inspect one prompt
```

`benchmark_ai.py` reports more than accuracy, because accuracy alone hid two real
failures. **Mean score drift on clean files** catches a model that inflates ordinary
documents without yet crossing the threshold — invisible to a confusion matrix, which
scores those as correct right up to the moment one crosses. **Score spread** catches a
model whose answer barely varies: three of five models tested returned essentially one
number for every file, and one answered 85 on eight of ten at confidence 0.9. Such a
model "detects" malware by calling everything malicious and looks excellent on every
conventional metric.

Both are cheap to compute and neither is standard. Add them before trusting a number
from any AI layer, including this one.

Fixtures in `tests/fixtures/pdf_builder.py` assemble PDFs byte by byte so the suite can
produce structures a well-behaved writer would refuse to emit. Nothing there is
executable malware — the payloads are inert markers, assembled at runtime so that
endpoint antivirus does not quarantine the source file.

---

## Known limitations

- **Windows only.** The engine is portable and `paths.py`/`credentials.py` already handle
  macOS and Linux, but no packaging exists for them.
- **Sandbox cost.** Spawning a parser process costs roughly 0.2–0.5 s per file. Switch to
  in-process parsing in Settings if you are scanning thousands of files and accept the
  reduced isolation.
- **Image-only PDFs.** Scanned documents contain no extractable text, so phishing wording
  in them is invisible to both the rules and the model — and a scanned form is hard to
  distinguish from a near-empty dropper. Optional OCR closes this:

  ```powershell
  winget install UB-Mannheim.TesseractOCR   # one Apache-2.0 binary
  pip install -e ".[ocr-tesseract]"         # then enable it in Settings
  ```

  Tesseract is recommended on dependency grounds: one audited Apache-2.0 binary,
  against RapidOCR's OpenCV, ONNX Runtime and opaque model weights. A pure-pip
  alternative exists (`.[ocr-rapidocr]`) for environments where an external
  binary is impractical.

  **Measured over the full 20,207-document corpus, OCR did not improve
  detection — it reduced it.** 362 documents were rendered:

  | At ≥ 80 | OCR off | OCR on |
  |---|---:|---:|
  | True positives | 8,887 | **8,876** |
  | False positives | 37 | 37 |
  | Wall clock | 631 s | 2,202 s |

  Eleven true positives lost, one false positive removed at `suspicious`, none
  at `malicious`, for 3.5× the runtime.

  The cause is worth understanding before enabling it. OCR suppressed
  `PDF_MINIMAL_DOC_WITH_ACTIVE_CONTENT` on **24 malware documents and 2 benign
  ones** — a dropper's single page is usually an image (a decoy invoice, a
  "click to enable content" lure), OCR reads it happily, and the page stops
  looking empty. The engine's strongest discriminator switches off on exactly
  the files it exists to catch.

  That specific interaction is now fixed — only *extracted* text counts toward
  the emptiness check, never OCR output — but the broader lesson stands:
  **recovered text is weaker evidence than extracted text, and any rule
  consuming it should say which it is holding.** `text_source` records that on
  every scan.

  OCR's remaining purpose is the AI evidence bundle. That layer is now
  [measured](#measured-effect), so OCR's contribution is finally separable — but it has
  not yet been isolated, since the AI benchmark ran with OCR enabled throughout and no
  paired OCR-off comparison exists. **OCR remains unproven on its own terms.**

  Confirm an engine is actually loaded before trusting any comparison — a run
  with no engine installed looks identical to one where OCR found nothing, which
  produced a wrong conclusion here once already:

  ```powershell
  python -c "from pdfsafe.analysis import ocr; print(ocr.available())"
  ```

  **Off by default, and not only for speed.** OCR rasterises pages, which means a
  rendering engine processes attacker-controlled input — the one thing the rest of the
  design avoids. It runs inside the parser sandbox, caps pages and resolution, and its
  dependencies stay out of the shipped bundle. Its effect on the false-positive rate is
  unmeasured; OCR output is noisy, and feeding noisy text to text-based rules is new
  ground. Measure before trusting it.
- **Encrypted PDFs.** A password-protected document cannot be inspected; PDFSafe reports
  that rather than guessing.
- **Detection, not prevention.** PDFSafe does not stop you opening a file it flagged; it
  quarantines and warns.

### Measured performance

Static engine only, no AI review, against **20,207 documents**: 11,098 malware
samples (Contagio, pre-2011 and CVE-sorted) and 9,109 ordinary documents (US
government forms, business reports, academic papers).

| Threshold | What the user sees | Malware caught | Ordinary documents flagged |
|---:|---|---:|---:|
| ≥ 20 | `low risk` | **93.6%** | 10.1% |
| ≥ 50 | `suspicious` | 82.4% | 6.4% |
| ≥ 80 | `malicious` — quarantined | 80.1% | **0.41%** |

At the quarantine threshold that is **99.59% precision**: of 8,924 files PDFSafe
would rename, 8,887 are malware and 37 are not.

Reproduce it with `python tools\benchmark_corpus.py <corpus-root>`.

**Read the numbers honestly.** 0.41% is roughly 1 document in 244 — far above a
commercial scanner, which is one reason a flagged file is renamed rather than
deleted. The malware corpus is historical, so recall against 2020s samples is
unknown and probably lower; techniques that parse cleanly are exactly what this
corpus lacks. And 3.9% of detections come from `PDF_PARSE_FAILURE` alone, which
means "this file is malformed" rather than "this file is hostile" — a corrupted
holiday photo would score the same.

The 37 remaining false positives cluster tightly: Adobe rich-media sample
documents, and legacy US government publications that use `/Launch` to trigger
printing. If PDFSafe flags something of yours that is plainly fine, that is a
defect and we want the report — see [Contributing](CONTRIBUTING.md).

### Which rules earn their weight

The measure that matters is not how often a rule fires on malware, but the ratio
between its rate there and on ordinary documents:

| Indicator | Malware | Ordinary | Ratio |
|---|---:|---:|---:|
| `PDF_JS_OBFUSCATED` | 12.9% | <0.1% | **>117×** |
| `YARA_..._OPENACTION_JAVASCRIPT` | 74.5% | 0.24% | **311×** |
| `PDF_MINIMAL_DOC_WITH_ACTIVE_CONTENT` | 74.8% | 0.11% | **680×** |
| `PDF_JS_AUTO_EXEC` | 79.1% | 3.50% | 23× |
| `PDF_LAUNCH_ACTION` | 0.67% | 0.15% | 4.5× |
| `PDF_XFA_FORM` | 9.3% | 6.35% | 1.5× — scored zero |
| `PDF_NAME_OBFUSCATION` | 1.4% | 2.49% | 0.6× — scored zero |

Two rules were found to be adding weight in the wrong direction and are now
reported for context but excluded from the score. `PDF_NAME_OBFUSCATION` is the
instructive one: counting hex-escaped names measures how a *producer* writes a
document, not what its author intended, and no threshold from 1 to 50 escapes
gives a ratio above 1.5. Detecting obfuscated *JavaScript* works; detecting
obfuscated *names* by counting escapes does not.

## Roadmap

- Re-measure the AI layer on a second model. The current figures come from one
  provider, and three of five models tested could not do the task at all — that
  variance belongs in the result, not in a footnote.
- Measure OCR's effect on the full-corpus false-positive rate. Its value rests on the
  evidence bundle, which the AI measurement now exercises, so the question is finally
  answerable.
- Optional ClamAV / VirusTotal enrichment
- Scheduled full-folder sweeps
- Signed builds, and a macOS package

Done: [measured false-positive rate](#measured-performance) against a 20,207-document
corpus, [optional OCR](#5-ocr--optional-and-off-by-default) for image-only documents, and
[a measured AI review layer](#measured-effect) — 0.32% → 0.09% quarantine false positives
with no detection loss.

## Contributing

Bug reports, false positives and new detection rules are all welcome — start
with [`CONTRIBUTING.md`](CONTRIBUTING.md). Security vulnerabilities go through
[`SECURITY.md`](SECURITY.md), privately, never a public issue.

## Licence

PDFSafe is licensed under the [Apache License 2.0](LICENSE).

The graphical interface links against **Qt via PySide6, which is LGPL-3.0**. The
two are compatible because Qt is dynamically linked, and PDFSafe ships as a
directory bundle with Qt as separate replaceable `.dll` files precisely so that
LGPL relinking rights are preserved. The CLI links no Qt at all. Full
third-party attribution is in [`NOTICE`](NOTICE).
