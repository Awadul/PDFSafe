# Changelog

All notable changes to PDFSafe are recorded here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [Semantic Versioning](https://semver.org/).

Because PDFSafe is a scanner, **changes to detection are called out separately
from changes to the application**. A verdict that changes between releases
matters more to users than a UI tweak.

## [Unreleased]

### Detection
- Definitive measurement published in the README, replacing the figures quoted
  in 0.2.0. Those came from a run whose malware corpus antivirus had been
  deleting mid-scan, and predated the `PDF_NAME_OBFUSCATION` change. The full
  corpus — **20,207 documents, 11,098 of them malware, zero read errors** —
  gives **99.59% precision and 80.08% recall at the quarantine threshold, with
  0.41% of ordinary documents flagged.**
- The escape-count distribution settles `PDF_NAME_OBFUSCATION`. Across
  thresholds from 1 to 50 escapes the malware-to-benign ratio never exceeds 1.5
  and moves non-monotonically, which is what noise looks like. Counting hex
  escapes measures the producer, not the author. `PDF_JS_OBFUSCATED` — 12.9% of
  malware against under 0.1% of ordinary documents — is the obfuscation rule
  that works.
- `PDF_LAUNCH_ACTION` confirmed at 0.67% of malware against 0.15% of ordinary
  documents. Earlier partial corpora suggested it was inverted; on the complete
  set it discriminates 4.5×, which retrospectively justifies declining to
  weaken it on damaged evidence.

### Fixed
- **The verdict and the risk score could contradict each other.** When the AI
  reviewed a file, `_fuse` took the label from the model and the number from a
  weighted blend, with nothing tying them together — so PDFSafe would report one
  document as *malicious* at 64/100 and another as *suspicious* at 70/100. The
  score is what the interface shows in large type and what the history table
  sorts by, while quarantine keys off the verdict, so the visible number told
  users nothing about what the application would actually do to their file.
  The verdict is now always derived from the final score.
- A provider returning a label and a number that contradict each other (say
  `verdict="malicious"` with `risk_score=30`, which the schema permits because
  the fields validate independently) has its score moved into the band its own
  label implies. The label wins: a model chooses a category far more reliably
  than it emits a calibrated number.
- Where the model's judgement differs from the final verdict, the summary now
  says so rather than resolving the disagreement silently.

## [0.2.0] — 2026-08-03

**Detection behaviour differs materially from 0.1.0.** Documents that 0.1.0
quarantined may now come back clean, and the reverse is possible too. If you
recorded verdicts with 0.1.0, re-scan rather than compare.

### Detection

Weights recalibrated against **19,736 documents** — 10,627 malware samples and
9,109 ordinary ones — using the new `tools/benchmark_corpus.py`.

> **These figures were superseded.** They came from a run whose malware corpus
> antivirus was deleting mid-scan. The definitive measurement is under
> [Unreleased] and in the README: 99.59% precision, 80.08% recall, 0.41% of
> ordinary documents flagged, over 20,207 files.

At the quarantine threshold the engine reached **99.5% precision and 79.2%
recall, flagging 0.47% of ordinary documents**. Before calibration, 4.94% of
ordinary documents — 450 files, including live IRS tax forms — scored 80 or
above and would have been renamed on the user's disk without being asked.

Two corrections to conclusions drawn from an earlier, damaged malware sample.
`PDF_XFA_FORM` was recorded as 2.7× more common in benign documents; valid data
says the reverse (9.74% of malware against 6.35% of benign). It stays at zero
weight anyway, because a ratio of 1.5 is worth nothing and the YARA rule does
the job at better than 70×. `PDF_NAME_OBFUSCATION` went the other way: raising
its threshold looked like a fix, but against a valid corpus the tightened rule
fires on 2.49% of benign documents and only 1.47% of malware, so it is now
scored zero too.

The measure applied to each rule is the ratio between its rate on malware and
its rate on benign documents. Three rules failed it:

- **`PDF_XFA_FORM` no longer scores** (was 20). Measured at 6.35% of benign
  documents against 2.34% of malware — 2.7× more likely in a document that is
  fine. XFA is how interactive government and enterprise forms work.
- **`PDF_MANY_INCREMENTAL_UPDATES` no longer scores** (was 20). 5.54% benign
  against 0.83% malware. Every signature and annotation round appends a
  revision, so a stack of them marks a document that went through a legitimate
  workflow.
- **`PDF_NAME_OBFUSCATION` requires 5+ escapes and weighs 10–25** (was 1+ escape
  at 35–55). It fired on 19.72% of benign documents against 25.34% of malware —
  a ratio of 1.3, close to no information — while its `HIGH` rating floored the
  score at 45 unaided.
- **`PDF_AUTO_ACTION` no longer double-counts JavaScript** and weighs 15 (was
  30). An `/OpenAction` pointing at script is already scored at 55 by
  `PDF_JS_AUTO_EXEC`; counting it twice is what carried forms over the line.
- **YARA `PDFSafe_Name_Obfuscation` downgraded to `medium`** (was `high`, which
  maps to weight 60 and floors the score at 45). It matched 152 benign
  documents, and it duplicates evidence the heuristic rule already scores. Its
  generic two-escape pattern now needs more than four occurrences to count;
  the specific escaped keywords (`/J#61vaScript`, `/Op#65nAction`, `/#4C#61unch`)
  still match on sight.

A second pass then addressed the residue — 109 documents, almost all one-page
government forms whose field-validation script runs on open. Both changes are
de-duplications rather than reweightings: the noisy-OR treats indicators as
independent evidence, so scoring one fact twice compounds it.

- **`PDF_MINIMAL_DOC_WITH_ACTIVE_CONTENT` now requires the page to be empty.**
  The rule is named "nearly empty document" but only ever checked page count, so
  it fired on every one-page document carrying script. It now also requires
  fewer than 200 characters of extractable text. A dropper's single page exists
  only to hold the script; a form has labels and instructions. The weight stays
  at 50 — this rule has the best discrimination in the engine and deserved a
  better condition, not a smaller number. The change took it from 1.88% of
  ordinary documents to 0.11% while costing 5% of its malware coverage,
  improving its malware-to-benign ratio from 35× to roughly 575×.

- **YARA `PDFSafe_Legacy_Exploit_API` split in two.** It matched six API names,
  two of which — `util.printf` and `getAnnots` — are ordinary Acrobat
  JavaScript. It rated `high` (weight 60, floor 45), so IRS publications that
  format a currency value were scored 87 and quarantined. CVE-2008-2992 is
  reached through a crafted *format string*, not through calling the function,
  so `PDFSafe_Printf_Format_Overflow` now requires an oversized precision
  specifier. The four APIs with no legitimate use — `Collab.collectEmailInfo`,
  `Collab.getIcon`, `media.newPlayer`, `spell.customDictionaryOpen` — remain in
  `PDFSafe_Exploit_API`. Bare `getAnnots` is dropped: it is how any script
  enumerates annotations.

One change was made and reverted, recorded here because the reasoning was sound
and the measurement still said no. Suppressing `PDF_JS_PRESENT` when
`PDF_JS_AUTO_EXEC` fires removes an obvious double-count — both describe the
same script, and the noisy-OR assumes independent evidence. Measured, it cost
**98 true positives to remove 68 false positives**, and recall at the quarantine
threshold fell from 83.5% to 70.0%. Scores cluster just above 80, so subtracting
a constant from every JavaScript-bearing document pushes far more malware off
the edge than it does ordinary files.

Both indicators kept at zero weight remain visible in the report and in the AI
evidence bundle — they are useful context, they just must not move the number.

`PDF_JS_PRESENT`, `PDF_JS_AUTO_EXEC` and `PDF_MINIMAL_DOC_WITH_ACTIVE_CONTENT`
are unchanged; measurement confirmed them as the strongest discriminators
(19×, 24× and 35× respectively).

No weight was *lowered* on the strength of the malware corpus, which was too
badly damaged by antivirus interference to support a conclusion.

### Added
- Apache-2.0 licence, `NOTICE` with third-party attribution, security policy,
  contribution guide and issue templates.

### Changed
- Daily AI token budget now persists in SQLite (`pdfsafe_meta`) instead of
  Redis. On a desktop install Redis was never present, so a configured budget
  silently had no effect.
- **The update check now ships disabled.** No feed is published yet, so every
  launch made a DNS lookup that failed and logged an error. A fresh install now
  opens no network connection at all until the user asks for one.
- A failed scan no longer renders as "no suspicious structures were detected".
  Nothing was examined, so the honest report is that the file is unknown — the
  previous wording read as a clean bill of health.

### Removed
- The optional server target: FastAPI app, Celery workers, PostgreSQL/Alembic,
  Docker, S3 storage, and the REST data-transfer objects. PDFSafe is a desktop
  application; the second target had drifted twice and caused a real bug.

### Fixed
- Quarantine no longer deleted the user's file. It renames it to
  `<name>.quarantine`, which removes the `.pdf` association without destroying
  data — the false-positive rate is not yet characterised, so an irreversible
  action was the wrong default.
- Quarantining the same content twice failed silently: the vault entry from the
  first run was read-only and Windows refused to overwrite it.
- Quarantine failures no longer discard a completed analysis. The verdict is the
  product; a locked file or an antivirus handle must not lose it.
- History pruning now reports orphaned blobs so disk is reclaimed. Previously
  the database self-trimmed while stored files accumulated indefinitely.
- File logging in the frozen build: `configure_logging()` returned early after
  import-time initialisation, so the log file was never created.
- YARA rules and the parser sandbox now resolve correctly inside a PyInstaller
  bundle.
- **Every scan failed in the frozen build.** A windowed PyInstaller executable
  has no console, so `sys.stdout` and `sys.stderr` are `None`. The spawned parser
  child never configured logging, fell back to structlog's default `PrintLogger`,
  and died taking a weak reference to `None` — reported to the user as
  "Parsing failed", which pointed at entirely the wrong subsystem.
- The parser child now returns its traceback rather than just an exception type
  and message. A child process's stack dies with it, so whatever crosses the pipe
  is all anyone gets.
- `configure_logging()` no longer assumes `sys.stderr` exists; a windowed build
  crashed on startup before it could draw a window or write a log line.

### Added (developer)
- `tools/benchmark_corpus.py` — measures detection and false-positive rates
  against a labelled corpus, recording *which indicators fired* per file rather
  than the score alone, and reporting metrics at the thresholds the product
  actually ships.
- `tools/reset_dev_state.ps1` — clears scan history, file store and quarantine,
  and restores `.quarantine` filenames so the same fixtures can be re-scanned.
- `packaging/build.ps1` stops a running PDFSafe before building. A copy left in
  the tray locks every DLL in `dist\`, which PyInstaller reports as an opaque
  *Access is denied* on an arbitrary `.pyd`.

## [0.1.0] — never tagged

Initial development version. Published to GitHub, never released as a binary.
Its detection weights were set by judgement and never measured; superseded by
0.2.0.

### Detection
- 23 weighted heuristic rules combined with a noisy-OR, covering active content,
  obfuscation, known exploit APIs, embedded files, network references and
  structural anomalies.
- Bundled YARA rule set.
- Optional AI review, gated to files scoring 25–84 so ordinary documents cost
  nothing.

### Application
- PySide6 desktop interface with drag-and-drop, scan history, evidence detail,
  tray icon and notifications.
- Typer CLI: `scan`, `watch`, `rules`, `config`, `version`.
- Folder watching with download-stability detection.
- SQLite history, content-addressed storage, quarantine.
- PDF parsing isolated in a spawned child process with a hard timeout.
- API keys stored in the OS credential manager; none ship with the application.

### Known limitations
- Detection thresholds have **not** been validated against a corpus of real
  documents. The false-positive rate is unmeasured.
- Windows only.
- Builds are unsigned, so SmartScreen will warn.
