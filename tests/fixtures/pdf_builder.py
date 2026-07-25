"""Hand-built PDF fixtures.

Files are assembled byte by byte rather than with a library so the tests can
produce structures a well-behaved writer would refuse to emit - hex-escaped
names, appended payloads, shifted headers and so on.

Nothing here is executable malware. The "payloads" are inert marker strings
that merely match the detectors. They are also *assembled at runtime* from
fragments rather than written as literals, because endpoint antivirus tends to
quarantine source files that contain recognisable signature strings, which
would silently delete this file from a developer's checkout.
"""

from __future__ import annotations

from textwrap import dedent

# --------------------------------------------------------------------------
# Signature fragments, joined at runtime so no complete signature appears as a
# literal in this file.
# --------------------------------------------------------------------------
_PE_MAGIC = "".join(chr(c) for c in (0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00))
_NOP_SLED = "%" + "u90" + "90" + "%" + "u90" + "90"
_SHELL_NAME = "cmd" + ".exe"
_EXPLOIT_API = "util." + "printf"


def _assemble(objects: list[str], root_ref: str = "1 0 R", *, header: str = "%PDF-1.7") -> bytes:
    """Build a minimal but structurally valid PDF from object bodies."""
    prefix = f"{header}\n%\xe2\xe3\xcf\xd3\n"

    offsets: list[int] = []
    body = ""
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(prefix) + len(body))
        body += f"{index} 0 obj\n{obj.strip()}\nendobj\n"

    xref_offset = len(prefix) + len(body)

    xref = f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    for offset in offsets:
        xref += f"{offset:010d} 00000 n \n"

    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root {root_ref} >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    )
    return (prefix + body + xref + trailer).encode("latin-1")


def benign_pdf(text: str = "Quarterly invoice. Total due: 1,240.00 EUR.") -> bytes:
    """An ordinary one-page document with a little text and no active content."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
    return _assemble(
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            "/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
            f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ]
    )


def javascript_pdf(script: str = "app.alert('hello');") -> bytes:
    """Document-level JavaScript reached through /Names, executed on open."""
    return _assemble(
        [
            "<< /Type /Catalog /Pages 2 0 R /Names << /JavaScript 4 0 R >> >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            "<< /Names [(script) 5 0 R] >>",
            f"<< /S /JavaScript /JS ({script}) >>",
        ]
    )


def openaction_js_pdf(script: str | None = None) -> bytes:
    """Obfuscated JavaScript wired to /OpenAction - the classic dropper shape."""
    if script is None:
        script = (
            f"var a = unescape('{_NOP_SLED}');"
            "var b = eval(String.fromCharCode(97,108,101,114,116));"
            "var c = '';"
            "for (var i = 0; i < 400; i++) { c += a; }"
            f"{_EXPLOIT_API}('%45000f', 1);"
        )
    return _assemble(
        [
            "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            f"<< /S /JavaScript /JS ({script}) >>",
        ]
    )


def launch_action_pdf(target: str | None = None) -> bytes:
    """A /Launch action pointing at a shell - inert here, but the real pattern."""
    target = target or _SHELL_NAME
    return _assemble(
        [
            "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            f"<< /S /Launch /F ({target}) /Win << /F ({target}) /P (/c echo test) >> >>",
        ]
    )


def obfuscated_names_pdf() -> bytes:
    """Hex-escaped names: /J#61vaScript is /JavaScript to a reader."""
    return _assemble(
        [
            "<< /Type /Catalog /Pages 2 0 R /Op#65nAction 4 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            "<< /S /J#61vaScript /J#53 (eval(unescape('%u4141'))) >>",
        ]
    )


def phishing_pdf(url: str = "http://185.220.101.7/verify") -> bytes:
    """A link annotation to a raw-IP host with credential-harvest phrasing."""
    text = "Your account will be suspended. Sign in to view the secure document."
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
    return _assemble(
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            "/Annots [6 0 R] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            f"<< /Type /Annot /Subtype /Link /Rect [72 700 400 730] "
            f"/A << /S /URI /URI ({url}) >> >>",
        ]
    )


def embedded_executable_pdf() -> bytes:
    """An /EmbeddedFile whose bytes start with a PE signature."""
    payload = _PE_MAGIC + "PDFSAFE-TEST-MARKER-NOT-A-REAL-BINARY"
    return _assemble(
        [
            "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            "<< /Names [(invoice.exe) 5 0 R] >>",
            "<< /Type /Filespec /F (invoice.exe) /UF (invoice.exe) /EF << /F 6 0 R >> >>",
            f"<< /Type /EmbeddedFile /Length {len(payload)} >>\n"
            f"stream\n{payload}\nendstream",
        ]
    )


def appended_payload_pdf(trailing: int = 4096) -> bytes:
    """A valid PDF with a large blob appended after %%EOF."""
    return benign_pdf() + b"\n" + (b"PDFSAFE-APPENDED-BLOB" * (trailing // 21 + 1))


def shifted_header_pdf(padding: int = 64) -> bytes:
    """A PDF whose header does not start at offset 0."""
    return b"A" * padding + benign_pdf()


def corrupt_pdf() -> bytes:
    """Bytes that claim to be a PDF but cannot be parsed."""
    return b"%PDF-1.4\n" + b"\x00\xff" * 512 + b"\ntrailer\n<< /Root 9 0 R >>\n%%EOF\n"


def not_a_pdf() -> bytes:
    """A plain text file, used to test upload validation."""
    return dedent(
        """\
        This is not a PDF. It is a text file that happens to be uploaded to a
        PDF scanner, which should reject it before analysis begins.
        """
    ).encode()


ALL_BUILDERS = {
    "benign": benign_pdf,
    "javascript": javascript_pdf,
    "openaction_js": openaction_js_pdf,
    "launch_action": launch_action_pdf,
    "obfuscated_names": obfuscated_names_pdf,
    "phishing": phishing_pdf,
    "embedded_executable": embedded_executable_pdf,
    "appended_payload": appended_payload_pdf,
    "shifted_header": shifted_header_pdf,
    "corrupt": corrupt_pdf,
}
