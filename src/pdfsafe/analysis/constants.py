"""Signature tables used by the analysis engine.

Kept in one module so detections can be tuned without touching parsing logic.
"""

from __future__ import annotations

from typing import Final

ANALYZER_VERSION: Final = "1.0.0"

PDF_HEADER: Final = b"%PDF-"
PDF_EOF: Final = b"%%EOF"
MAX_HEADER_SEARCH_BYTES: Final = 1024

# ---------------------------------------------------------------------------
# Raw byte keywords (pdfid-style). Counted against the whole file, including
# object streams, so obfuscated names are also caught by the hex-escape check.
# ---------------------------------------------------------------------------
PDF_KEYWORDS: Final[tuple[str, ...]] = (
    "obj",
    "endobj",
    "stream",
    "endstream",
    "xref",
    "trailer",
    "startxref",
    "/Page",
    "/Encrypt",
    "/ObjStm",
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/AcroForm",
    "/JBIG2Decode",
    "/RichMedia",
    "/Launch",
    "/EmbeddedFile",
    "/XFA",
    "/URI",
    "/SubmitForm",
    "/GoToR",
    "/GoToE",
    "/Colors",
    "/Filter",
    "/FlateDecode",
    "/ASCIIHexDecode",
    "/ASCII85Decode",
    "/LZWDecode",
    "/RunLengthDecode",
    "/DCTDecode",
    "/CCITTFaxDecode",
    "/Crypt",
    "/Sound",
    "/Movie",
    "/Annots",
    "/FileAttachment",
    "/ObjRef",
)

#: Keywords whose mere presence is worth reporting.
ACTIVE_CONTENT_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "/JS",
        "/JavaScript",
        "/AA",
        "/OpenAction",
        "/Launch",
        "/EmbeddedFile",
        "/XFA",
        "/RichMedia",
        "/SubmitForm",
        "/GoToE",
        "/GoToR",
        "/Sound",
        "/Movie",
    }
)

# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------
#: Tokens that are common in weaponised PDF JavaScript.
JS_SUSPICIOUS_TOKENS: Final[tuple[str, ...]] = (
    "eval",
    "unescape",
    "decodeURI",
    "decodeURIComponent",
    "String.fromCharCode",
    "fromCharCode",
    "app.launchURL",
    "app.alert",
    "app.setTimeOut",
    "app.execMenuItem",
    "this.exportDataObject",
    "this.importDataObject",
    "this.submitForm",
    "this.getAnnots",
    "this.getURL",
    "util.printf",
    "util.byteToChar",
    "Collab.collectEmailInfo",
    "Collab.getIcon",
    "media.newPlayer",
    "spell.customDictionaryOpen",
    "getIcon",
    "escape(",
    "ActiveXObject",
    "WScript",
    "Shell.Application",
    "cmd.exe",
    "powershell",
    "XMLHttpRequest",
    "atob",
    "btoa",
    "arguments.callee",
    "heapLib",
    "sprayHeap",
    "%u9090",
    "\\x90\\x90",
    "shellcode",
)

#: Tokens that on their own strongly imply exploitation rather than automation.
JS_CRITICAL_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "util.printf",
        "Collab.collectEmailInfo",
        "Collab.getIcon",
        "media.newPlayer",
        "spell.customDictionaryOpen",
        "heapLib",
        "sprayHeap",
        "%u9090",
        "shellcode",
        "powershell",
        "cmd.exe",
        "ActiveXObject",
        "WScript",
    }
)

#: Known CVE lures keyed by the API they abuse.
JS_CVE_HINTS: Final[dict[str, str]] = {
    "util.printf": "CVE-2008-2992",
    "Collab.collectEmailInfo": "CVE-2007-5659",
    "Collab.getIcon": "CVE-2009-0927",
    "media.newPlayer": "CVE-2009-4324",
    "spell.customDictionaryOpen": "CVE-2009-1493",
    "getAnnots": "CVE-2009-1492",
}

# ---------------------------------------------------------------------------
# Embedded files
# ---------------------------------------------------------------------------
EXECUTABLE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".exe",
        ".dll",
        ".scr",
        ".com",
        ".pif",
        ".cpl",
        ".msi",
        ".msp",
        ".jar",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".lnk",
        ".reg",
        ".sh",
        ".elf",
        ".app",
        ".apk",
        ".iso",
        ".img",
        ".vhd",
        ".chm",
        ".sys",
        ".scf",
        ".inf",
    }
)

ARCHIVE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {".zip", ".rar", ".7z", ".cab", ".ace", ".gz", ".bz2", ".xz", ".tar", ".lzh"}
)

OFFICE_MACRO_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".doc", ".xls", ".ppt", ".rtf"}
)

#: Leading bytes -> human readable type, used to catch renamed attachments.
MAGIC_SIGNATURES: Final[tuple[tuple[bytes, str], ...]] = (
    (b"MZ", "dos/pe-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"\xca\xfe\xba\xbe", "mach-o/java-class"),
    (b"\xfe\xed\xfa\xce", "mach-o"),
    (b"\xfe\xed\xfa\xcf", "mach-o-64"),
    (b"PK\x03\x04", "zip-container"),
    (b"Rar!\x1a\x07", "rar-archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z-archive"),
    (b"\xd0\xcf\x11\xe0", "ole2-compound"),
    (b"{\\rtf", "rtf-document"),
    (b"#!/", "script-shebang"),
    (b"%PDF-", "pdf"),
    (b"\x1f\x8b", "gzip"),
    (b"ITSF", "chm-help"),
    (b"MSCF", "cab-archive"),
)

# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------
URL_SHORTENER_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at",
        "rb.gy",
        "tiny.cc",
        "bl.ink",
        "s.id",
        "t.ly",
        "shorte.st",
        "adf.ly",
        "bc.vc",
        "clck.ru",
        "v.gd",
    }
)

SUSPICIOUS_TLDS: Final[frozenset[str]] = frozenset(
    {
        ".zip",
        ".mov",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".top",
        ".xyz",
        ".click",
        ".link",
        ".work",
        ".loan",
        ".download",
        ".stream",
        ".review",
        ".country",
        ".kim",
        ".science",
        ".party",
        ".gdn",
        ".men",
        ".date",
    }
)

DANGEROUS_URI_SCHEMES: Final[frozenset[str]] = frozenset(
    {"file", "javascript", "data", "smb", "ftp", "telnet", "vbscript", "ms-msdt", "search-ms"}
)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
HIGH_ENTROPY_THRESHOLD: Final = 7.5
JS_HIGH_ENTROPY_THRESHOLD: Final = 5.2
LONG_JS_LINE_THRESHOLD: Final = 1000
MANY_INCREMENTAL_UPDATES: Final = 3
LARGE_TRAILING_BYTES: Final = 1024
MAX_TEXT_EXCERPT_CHARS: Final = 4000
MAX_EMBEDDED_SAMPLE_BYTES: Final = 4096
