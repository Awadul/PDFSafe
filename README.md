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
| **Quarantine**                 | Malicious files are moved somewhere they cannot be opened by accident   |
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

About twenty weighted rules produce a 0–100 risk score. Weights combine with a
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
  analysis/       parsing, JS/URL analysis, YARA, scoring       ← shared
  ai/             provider abstraction, evidence, cost gate     ← shared
  local/          SQLite, scan queue, sandbox, watcher, updater ← desktop
  desktop/        PySide6 window, tray, dialogs                 ← desktop
  api/ worker/    FastAPI + Celery                              ← server (optional)
  web/            server dashboard templates                    ← server (optional)
  cli.py          Typer CLI                                     ← both
packaging/        PyInstaller spec, Inno Setup script, build pipeline
tests/            pytest suite with synthetic malicious fixtures
```

The dependency split in `pyproject.toml` mirrors this: the desktop build installs
`.[desktop]` and never pulls in FastAPI, Celery, Postgres drivers or boto3, which the
PyInstaller spec also excludes explicitly.

### Server target

The same engine can run as a multi-user service — REST API, Celery workers, PostgreSQL,
web dashboard, Docker Compose. It is not built or shipped as part of the desktop product
and is not needed to use it:

```bash
pip install -e ".[server]"
docker compose up -d --build
```

Only the persistence and queueing layers differ; `analysis/` and `ai/` are identical.

|           | Desktop            | Server               |
| --------- | ------------------ | -------------------- |
| Database  | SQLite (WAL)       | PostgreSQL + Alembic |
| Queue     | thread pool        | Celery + Redis       |
| Isolation | child process      | container            |
| Secrets   | Credential Manager | environment          |

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

## Roadmap

- OCR for image-only documents
- Optional ClamAV / VirusTotal enrichment
- Scheduled full-folder sweeps
- Signed macOS build

<!-- Run the GUI -->

.\.venv\Scripts\python.exe -m pdfsafe.desktop.app

<!-- Run the CLI with the directory to track -->
.\.venv\Scripts\python.exe -m pdfsafe.cli watch "C:\Users\Home\Downloads"

<!-- Complete the Project from scratch from demo -->

.\.venv\Scripts\python.exe "C:\Users\Home\.gemini\antigravity-ide\brain\a50953fc-02f2-4948-a933-68cb31a0e588\scratch\reset_pdfsafe.py"
