# Security Policy

PDFSafe deliberately ingests hostile input. Vulnerabilities in it are expected,
not surprising, and we would much rather hear about them from you than from a
user.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

Use GitHub's [private reporting][advisory]. If that is unavailable to you, email
`awaisabdullahm@gmail.com` with `PDFSafe security` in the subject line.

[advisory]: https://github.com/Awadul/PDFSafe/security/advisories/new

Please include:

- what you were able to make PDFSafe do (crash, hang, read or write a file
  outside its directories, execute code)
- a proof-of-concept file, or a script that generates one
- the PDFSafe version (`pdfsafe version`) and your Windows build
- whether the sandbox was enabled (Settings → Scanning → Parsing mode)

If your proof-of-concept is live malware, say so and **do not attach it** — send
the SHA-256 and, if it is public, a VirusTotal or MalwareBazaar link instead.

### What to expect

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan | communicated with the assessment |
| Credit | in the release notes and `CHANGELOG.md`, unless you prefer otherwise |

We will not take legal action against good-faith research: testing against your
own files and machines, staying within the disclosure process, and not accessing
other people's data.

## Supported versions

Pre-1.0, only the latest release receives fixes. Once 1.0 ships this table will
list a supported window.

| Version | Supported |
|---|---|
| 0.2.x | ✅ |
| 0.1.x | ❌ — detection was uncalibrated; upgrade |

## Threat model

Knowing what PDFSafe *tries* to defend against makes reports easier to triage.

### In scope

- **Parser exploitation.** PDFSafe parses attacker-controlled structure through
  pikepdf/qpdf and pypdf. A malformed document that achieves code execution in a
  parser is the highest-severity finding possible here.
- **Sandbox escape.** Parsing runs in a spawned child process. Anything that
  lets a document affect the parent — beyond the JSON evidence the child
  returns — is in scope.
- **Timeout or resource-limit bypass.** A document that hangs the application
  despite `analysis_timeout_seconds`, or exhausts memory or disk.
- **Path traversal.** Storage keys are content hashes and paths are checked
  against the storage root; anything that writes outside `%LOCALAPPDATA%\PDFSafe`
  is a bug.
- **Credential exposure.** The API key must never reach `config.json`, the logs,
  the evidence bundle sent to a model, or a crash report.
- **Evidence leakage.** With AI review enabled, only derived evidence should
  leave the machine. Raw document bytes escaping is a serious bug.
- **Quarantine bypass.** A malicious file that stays openable after being
  quarantined.

### Out of scope

- **Detection misses and false positives.** These are correctness issues, not
  vulnerabilities — please open a normal issue using the *False positive* or
  *False negative* template.

  They are still taken seriously, and they are measurable. The rates published
  in the [README](README.md#measured-performance) come from
  `tools/benchmark_corpus.py` run over a labelled corpus, so any claim there can
  be checked or contradicted:

  ```
  python tools/benchmark_corpus.py <corpus-root> --out benchmark
  ```

  Datasets are labelled by directory name (`MALWARE_...`, `CLEAN_...`). The
  report gives per-indicator rates on both halves, which is what makes a
  disagreement actionable — "this rule fires on 20% of ordinary documents" is a
  fixable claim in a way that "it flagged my file" is not.

  A single misclassified document is worth reporting too. The SHA-256, the score
  and the indicator list are usually enough; please don't send confidential
  files.
- **Attacks requiring an already-compromised machine**, such as another process
  running as the same user editing `config.json` or the database. PDFSafe offers
  no protection against code already running with your privileges.
- **Denial of service by supplying enormous files.** Bounded by
  `max_upload_bytes`; if you can get past that bound, that *is* in scope.
- **SmartScreen and antivirus warnings** on unsigned builds.

## Design notes relevant to security review

- **Parsing is isolated in a spawned child process** (`local/sandbox.py`) with a
  hard timeout and escalation from terminate to kill. Set
  `analysis_isolation = "in_process"` to disable this; the setting exists for
  speed and is not recommended.
- **No document content is executed or rendered.** PDFSafe reads structure only.
  It does not open documents in a viewer, run JavaScript, or resolve remote
  references.
- **Quarantine renames rather than deletes.** A malicious verdict strips the
  `.pdf` association from both the user's copy and the internal copy. Nothing is
  destroyed, because the false-positive rate is not yet characterised.
- **API keys live in the OS credential manager**, never in configuration files.
  PDFSafe ships with no key of its own.
- **PDFSafe makes no network connection unless you ask it to.** AI review and the
  update check are both off by default; with both off the application never
  opens a socket.

## Known limitations

These are documented rather than fixed, and are not vulnerabilities:

- **Roughly 0.5% of ordinary documents are classified malicious and quarantined**
  (measured over 9,109 real documents; see the README). Known clusters are
  legacy US government publications that use `/Launch` to trigger printing, and
  Adobe rich-media samples. This is far above a commercial scanner and is the
  main reason quarantine renames a file rather than deleting it.
- **Recall is measured against a historical corpus.** Detection of contemporary
  samples is unknown and should be assumed lower — techniques that parse cleanly
  are exactly what a pre-2011 corpus lacks.
- The bundle is unsigned pre-1.0, so SmartScreen will warn.
- `os.chmod` on Windows only clears the write bit; quarantine relies on the
  extension change, not on file permissions.
- Encrypted PDFs cannot be inspected and are reported as such.
- Image-only documents yield no text, so phishing wording in a scan is invisible
  to both the rules and the model.
