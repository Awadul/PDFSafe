# Changelog

All notable changes to PDFSafe are recorded here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [Semantic Versioning](https://semver.org/).

Because PDFSafe is a scanner, **changes to detection are called out separately
from changes to the application**. A verdict that changes between releases
matters more to users than a UI tweak.

## [Unreleased]

### Added
- Apache-2.0 licence, `NOTICE` with third-party attribution, security policy,
  contribution guide and issue templates.

### Changed
- Daily AI token budget now persists in SQLite (`pdfsafe_meta`) instead of
  Redis. On a desktop install Redis was never present, so a configured budget
  silently had no effect.

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

## [0.1.0] — unreleased

Initial development version. Not released.

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
