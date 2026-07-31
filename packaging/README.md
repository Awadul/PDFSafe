# Building and shipping PDFSafe

## Prerequisites

| Tool | Why | Where |
|---|---|---|
| Python 3.12 (64-bit) | Runtime | python.org |
| Inno Setup 6 | Installer | <https://jrsoftware.org/isdl.php> |
| Windows SDK | `signtool.exe` | Visual Studio Installer → "Windows 11 SDK" |
| Code-signing certificate | Trust | See "Signing" below |

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## Build

```powershell
# Unsigned developer build
.\packaging\build.ps1

# Release build
.\packaging\build.ps1 -CertificateThumbprint A1B2C3D4E5F6... -Clean
```

Output:

```
dist\PDFSafe\                          program directory (~90-120 MB)
dist\installer\PDFSafe-0.1.0-setup.exe single-file installer (~45-60 MB)
dist\installer\latest.json             manifest for the auto-updater
```

## Signing — read this before shipping

An unsigned executable downloaded from the internet triggers **SmartScreen**:
users see "Windows protected your PC" and must click through two dialogs to
run it. For a security product that is close to fatal — the warning contradicts
the value proposition.

Certificate options, in order of how quickly users stop seeing warnings:

| Type | Cost/year | SmartScreen behaviour |
|---|---|---|
| **EV code signing** | ~$300-500 | Trusted immediately |
| **OV code signing** | ~$200-400 | Warns until reputation accrues (weeks to months, driven by download volume) |
| Unsigned | — | Warns forever |

EV certificates require the private key to live on a hardware token (or in a
cloud HSM such as Azure Trusted Signing), which means release builds must run
somewhere that token is available — a self-hosted runner, or a manual signing
step. Plan the release pipeline around that constraint rather than discovering
it the week you want to ship.

Both the executable and the installer are signed, and both are timestamped
(`/tr`) so signatures stay valid after the certificate expires.

## Antivirus false positives

PyInstaller bundles get flagged by heuristic engines regularly. This build
already avoids the worst triggers:

- **one-dir, not one-file** — one-file unpacks to `%TEMP%` on every launch, a
  pattern shared with actual droppers
- **no UPX** — packed executables are treated as suspicious almost universally
- **populated version resource** — anonymous binaries score worse
- **no elevation request** — `uac_admin=False`

If a vendor still flags a release, submit it to them directly (Microsoft:
<https://www.microsoft.com/wdsi/filesubmission>). Signing plus consistent
publisher identity across releases is what durably fixes this.

## Update hosting

**The update check ships disabled.** There is no published feed yet, and a check
that fails on every launch trains people to ignore the log. Enable it once the
manifest below is live.

`build.ps1` writes `latest.json`. Commit it to `updates/latest.json` and attach
the installer to a GitHub release, so the two URLs become:

```
https://raw.githubusercontent.com/Awadul/PDFSafe/main/updates/latest.json
https://github.com/Awadul/PDFSafe/releases/latest/download/PDFSafe-0.1.0-setup.exe
```

The client requires HTTPS for both the manifest and the download, verifies the
declared SHA-256, and checks the installer's Authenticode signature before
offering to run it. A hash alone proves nothing if the attacker controls the
server that published it — the signature is the part that matters, so do not
ship an unsigned installer through this channel.

## Release checklist

1. Bump `version` in `pyproject.toml`
2. `ruff check src tests ; ruff format --check src tests ; mypy src ; pytest -q`
3. `.\packaging\build.ps1 -CertificateThumbprint <thumbprint> -Clean`
4. Install the artifact on a clean Windows VM and verify:
   - installs without an admin prompt
   - launches, scans a benign PDF and a synthetic malicious one
   - tray icon, notifications and "Scan with PDFSafe" context entry work
   - uninstall removes the program and asks about scan history
5. Upload the installer and `latest.json`
6. Verify a previous version offers and applies the update
7. Tag the commit

## Cross-platform

macOS and Linux builds are not wired up. The engine is portable — `paths.py`
resolves per-platform directories and `credentials.py` uses Keychain and Secret
Service — but shipping them means a `.app` bundle with notarisation, and an
AppImage or Flatpak. Neither is a small task; treat them as separate projects
rather than a flag on this build.
