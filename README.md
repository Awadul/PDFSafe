# PDFSafe

A Windows desktop application that scans PDF files for malicious content before you open
them. It works entirely offline; AI review is optional and uses your own API key.

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
| **Optional AI second opinion** | For files that are neither clearly safe nor clearly malicious           |
| **Quarantine**                 | Malicious files are renamed so they cannot open by accident — never deleted |
| **Watch folders**              | New PDFs in Downloads are scanned automatically                         |
| **Explorer integration**       | Right-click any PDF → _Scan with PDFSafe_                               |

### What it does not do

It is a detection aid, not an antivirus. It reads document structure; it does not
execute documents in a sandbox, monitor running processes, or scan anything but PDFs.
A clean verdict means "no dangerous structure found", not "definitely safe".

---

## Install

Download `PDFSafe-x.y.z-setup.exe` and run it. No administrator rights required — it
installs per-user and can be removed from Add/Remove Programs.

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

Twenty-three weighted rules produce a 0–100 risk score. Weights combine with a
**noisy-OR** rather than a sum, so several weak signals accumulate without any pair of
them saturating the scale, and a `critical` finding imposes a floor.

```
 0 ────────── 20 ────────── 50 ────────── 80 ────── 100
    clean       low risk      suspicious    malicious
```

### 3. AI review — only when it changes the answer

```
score < 25    →  decided locally: clean            no API call
25 – 84       →  ambiguous: ask the model          one API call
score ≥ 85    →  decided locally: malicious        no API call
```

In normal use almost everything scores near zero, so the model is consulted rarely. When
it is, it receives a **summary of the evidence** — structure, indicators, decoded
JavaScript, URLs — never the document itself.

Two guard rails on the result: a `critical` local finding floors the verdict at
`suspicious` (the model cannot clear a file that demonstrably carries an executable), and
the final score keeps 40% of the local weight so a confidently wrong model cannot drag a
heavily-indicated file to zero.

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

## Privacy

With AI review **off** (the default), no network connection is made except the update
check, which sends only a version number.

With AI review **on**, ambiguous files produce one request to the provider you
configured, containing the evidence summary described above. You can exclude the document
text excerpt in Settings if your documents are sensitive.

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

### Run from source

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

pdfsafe-desktop          # the GUI
pdfsafe scan file.pdf    # the CLI
```

System libraries for building `pikepdf` and `yara-python` from source:

```bash
# Debian/Ubuntu
sudo apt-get install build-essential libqpdf-dev
# macOS
brew install qpdf
```

On Windows, install the prebuilt wheels rather than compiling.

### Build the installer

See [`packaging/README.md`](packaging/README.md). Short version:

```powershell
.\packaging\build.ps1 -CertificateThumbprint <thumbprint> -Clean
```

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
tools/            icon rendering and developer utilities
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

```bash
make test    # pytest
make lint    # ruff + mypy --strict
```

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
  in them is invisible to both the rules and the model. OCR is on the roadmap.
- **Encrypted PDFs.** A password-protected document cannot be inspected; PDFSafe reports
  that rather than guessing.
- **Detection, not prevention.** PDFSafe does not stop you opening a file it flagged; it
  quarantines and warns.

### The one that matters most

**The detection thresholds have not been validated against a corpus of real
documents.** The 23 rule weights were chosen by judgement, not measured. Nobody
yet knows what fraction of ordinary invoices, statements and signed contracts
PDFSafe flags.

If it flags something of yours that is plainly fine, that is a defect and we
want the report — see [Contributing](CONTRIBUTING.md). Those reports are how this
number gets established.

## Roadmap

- Publish a measured false-positive rate against a benign corpus
- OCR for image-only documents
- Optional ClamAV / VirusTotal enrichment
- Scheduled full-folder sweeps
- Signed macOS build

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
