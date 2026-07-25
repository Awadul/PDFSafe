"""Update checking and download.

The app polls a JSON manifest over HTTPS::

    {
      "version": "0.2.0",
      "released": "2026-08-01",
      "channel": "stable",
      "url": "https://updates.pdfsafe.app/desktop/PDFSafe-0.2.0-setup.exe",
      "sha256": "…64 hex chars…",
      "size": 48210944,
      "minimum_version": "0.1.0",
      "mandatory": false,
      "notes": "Markdown release notes shown in the update dialog."
    }

Two integrity layers apply, and both matter:

1. The manifest is fetched over TLS and the download is verified against the
   ``sha256`` it declares, which catches corruption and a tampered mirror.
2. The installer itself must be Authenticode-signed, which is what actually
   protects against a compromised update server - a hash the attacker also
   controls proves nothing. :func:`verify_signature` checks that on Windows and
   the caller must refuse to run an unsigned installer.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from pdfsafe import __version__, paths
from pdfsafe.config import Settings, get_settings
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

USER_AGENT = f"PDFSafe/{__version__}"
DOWNLOAD_TIMEOUT = 300.0
MANIFEST_TIMEOUT = 15.0
CHUNK_SIZE = 1024 * 256


@dataclass(slots=True)
class UpdateInfo:
    """A published release newer than the running build."""

    version: str
    url: str
    sha256: str
    size: int = 0
    released: str = ""
    notes: str = ""
    mandatory: bool = False
    channel: str = "stable"

    @property
    def size_mb(self) -> float:
        return round(self.size / (1024 * 1024), 1) if self.size else 0.0


class UpdateError(RuntimeError):
    """Update check or download failed."""


def parse_version(value: str) -> tuple[int, ...]:
    """Parse a dotted version into a comparable tuple, ignoring suffixes."""
    cleaned = value.strip().lstrip("vV").split("-")[0].split("+")[0]
    parts: list[int] = []
    for chunk in cleaned.split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def is_newer(candidate: str, current: str = __version__) -> bool:
    return parse_version(candidate) > parse_version(current)


def check(settings: Settings | None = None) -> UpdateInfo | None:
    """Fetch the manifest and return an update, or ``None`` if up to date."""
    settings = settings or get_settings()
    if not settings.update_check_enabled:
        return None
    if not settings.update_feed_url.lower().startswith("https://"):
        raise UpdateError("The update feed URL must use HTTPS.")

    try:
        with httpx.Client(timeout=MANIFEST_TIMEOUT, follow_redirects=True) as client:
            response = client.get(
                settings.update_feed_url,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                params={"channel": settings.update_channel, "current": __version__},
            )
            response.raise_for_status()
            manifest = response.json()
    except httpx.HTTPError as exc:
        raise UpdateError(f"Could not reach the update server: {exc}") from exc
    except ValueError as exc:
        raise UpdateError("The update server returned an unreadable manifest.") from exc

    info = _parse_manifest(manifest, settings.update_channel)
    if info is None:
        return None

    if not is_newer(info.version):
        logger.debug("update_not_needed", current=__version__, available=info.version)
        return None

    logger.info("update_available", current=__version__, available=info.version)
    return info


def _parse_manifest(manifest: Any, channel: str) -> UpdateInfo | None:
    """Accept either a single release object or a channel-keyed mapping."""
    if not isinstance(manifest, dict):
        raise UpdateError("The update manifest was not a JSON object.")

    entry = manifest
    if "version" not in manifest:
        candidate = manifest.get(channel) or manifest.get("stable")
        if not isinstance(candidate, dict):
            return None
        entry = candidate

    required = ("version", "url", "sha256")
    missing = [key for key in required if not entry.get(key)]
    if missing:
        raise UpdateError(f"The update manifest is missing: {', '.join(missing)}")

    url = str(entry["url"])
    if not url.lower().startswith("https://"):
        raise UpdateError("The update download URL must use HTTPS.")

    digest = str(entry["sha256"]).strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise UpdateError("The update manifest contains a malformed SHA-256 digest.")

    return UpdateInfo(
        version=str(entry["version"]),
        url=url,
        sha256=digest,
        size=int(entry.get("size") or 0),
        released=str(entry.get("released") or ""),
        notes=str(entry.get("notes") or ""),
        mandatory=bool(entry.get("mandatory")),
        channel=str(entry.get("channel") or channel),
    )


def download(
    info: UpdateInfo,
    *,
    progress: Any = None,
    destination: Path | None = None,
) -> Path:
    """Download the installer and verify its digest.

    Args:
        info: The release to fetch.
        progress: Optional ``callable(downloaded_bytes, total_bytes)``.
        destination: Override the target path (defaults to the cache directory).
    """
    target = destination or (paths.cache_dir() / f"PDFSafe-{info.version}-setup.exe")
    partial = target.with_suffix(".partial")

    digest = hashlib.sha256()
    downloaded = 0

    try:
        with httpx.Client(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
            with client.stream(
                "GET", info.url, headers={"User-Agent": USER_AGENT}
            ) as response:
                response.raise_for_status()
                total = int(response.headers.get("content-length") or info.size or 0)

                with partial.open("wb") as handle:
                    for chunk in response.iter_bytes(CHUNK_SIZE):
                        handle.write(chunk)
                        digest.update(chunk)
                        downloaded += len(chunk)
                        if progress is not None:
                            progress(downloaded, total)
    except httpx.HTTPError as exc:
        partial.unlink(missing_ok=True)
        raise UpdateError(f"Download failed: {exc}") from exc
    except OSError as exc:
        partial.unlink(missing_ok=True)
        raise UpdateError(f"Could not write the download: {exc}") from exc

    actual = digest.hexdigest()
    if actual != info.sha256:
        partial.unlink(missing_ok=True)
        logger.error("update_digest_mismatch", expected=info.sha256[:16], actual=actual[:16])
        raise UpdateError(
            "The downloaded file did not match the expected checksum and was discarded."
        )

    partial.replace(target)
    logger.info("update_downloaded", version=info.version, path=str(target), bytes=downloaded)
    return target


def verify_signature(installer: Path) -> tuple[bool, str]:
    """Check the installer's Authenticode signature (Windows only).

    Returns ``(trusted, detail)``. On non-Windows platforms this reports
    ``False`` with an explanation rather than pretending to have verified
    something.
    """
    if sys.platform != "win32":
        return False, "Authenticode verification is only available on Windows."

    script = (
        "$sig = Get-AuthenticodeSignature -LiteralPath "
        f"'{installer}'; "
        "Write-Output ($sig.Status.ToString() + '|' + $sig.SignerCertificate.Subject)"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        return False, f"Could not verify the signature: {exc}"

    output = (completed.stdout or "").strip()
    status, _, subject = output.partition("|")
    trusted = status.strip().lower() == "valid"

    if not trusted:
        logger.warning("update_signature_untrusted", status=status.strip())
    return trusted, f"{status.strip()} {subject.strip()}".strip()


def launch_installer(installer: Path, *, silent: bool = False) -> None:
    """Start the installer and leave it to replace this build.

    The caller should quit immediately afterwards - the installer cannot
    overwrite files that are still loaded.
    """
    if not installer.is_file():
        raise UpdateError("The installer is missing; download it again.")

    arguments = [str(installer)]
    if silent:
        # Inno Setup silent switches; harmless if the installer ignores them.
        arguments += ["/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"]

    logger.info("update_installer_launched", path=str(installer), silent=silent)
    try:
        if sys.platform == "win32":
            subprocess.Popen(  # noqa: S603
                arguments,
                close_fds=True,
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
            )
        else:  # pragma: no cover
            subprocess.Popen(arguments, close_fds=True, start_new_session=True)  # noqa: S603
    except OSError as exc:
        raise UpdateError(f"Could not start the installer: {exc}") from exc


def cleanup_old_downloads(keep_version: str | None = None) -> int:
    """Remove previously downloaded installers. Returns the count deleted."""
    removed = 0
    for entry in paths.cache_dir().glob("PDFSafe-*-setup.exe"):
        if keep_version and keep_version in entry.name:
            continue
        try:
            entry.unlink()
            removed += 1
        except OSError:  # pragma: no cover
            continue
    for entry in paths.cache_dir().glob("*.partial"):
        entry.unlink(missing_ok=True)
    return removed
