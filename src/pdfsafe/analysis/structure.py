"""Structural PDF parsing.

Two complementary passes are performed:

1. :func:`scan_raw` - a byte-level pass that never trusts the parser. It counts
   pdfid-style keywords (after resolving ``#xx`` name obfuscation), locates the
   header, counts incremental updates and measures trailing data. This catches
   files that are deliberately malformed so that parsers disagree.
2. :func:`parse_document` - a pikepdf pass that walks the object graph to
   recover JavaScript, automatic actions, embedded files, annotations and
   document metadata.

Both passes are defensive: any exception is captured into ``parse_errors``
rather than aborting the scan, because a file that breaks the parser is itself
a signal.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from typing import Any

from pdfsafe.analysis.constants import (
    MAX_EMBEDDED_SAMPLE_BYTES,
    MAX_HEADER_SEARCH_BYTES,
    MAX_TEXT_EXCERPT_CHARS,
    PDF_EOF,
    PDF_HEADER,
    PDF_KEYWORDS,
)
from pdfsafe.analysis.utils import (
    decode_name_escapes,
    identify_magic,
    md5_hex,
    safe_text,
    sha256_hex,
    shannon_entropy,
)
from pdfsafe.config import get_settings
from pdfsafe.logging import get_logger
from pdfsafe.schemas.analysis import (
    ActionFinding,
    DocumentMetadata,
    EmbeddedFileFinding,
    JavaScriptFinding,
    StructureSummary,
)

logger = get_logger(__name__)

_OBJ_RE = re.compile(rb"\d+\s+\d+\s+obj\b")
_STREAM_RE = re.compile(rb"\bstream\b")
_FILTER_RE = re.compile(
    rb"/(FlateDecode|ASCIIHexDecode|ASCII85Decode|LZWDecode|RunLengthDecode|DCTDecode|CCITTFaxDecode|JBIG2Decode|JPXDecode|Crypt)"
)
_HEX_OBFUSCATED_NAME_RE = re.compile(rb"/[A-Za-z0-9]*#[0-9A-Fa-f]{2}")

#: Action dictionary keys that execute without user interaction.
AUTO_TRIGGERS = {"/OpenAction", "/AA"}

#: Additional-action trigger names, mapped to a readable label.
AA_TRIGGERS = {
    "/O": "PageOpen",
    "/C": "PageClose",
    "/WC": "WillClose",
    "/WS": "WillSave",
    "/DS": "DidSave",
    "/WP": "WillPrint",
    "/DP": "DidPrint",
    "/E": "MouseEnter",
    "/X": "MouseExit",
    "/D": "MouseDown",
    "/U": "MouseUp",
    "/Fo": "Focus",
    "/Bl": "Blur",
    "/K": "Keystroke",
    "/F": "Format",
    "/V": "Validate",
    "/Cc": "Calculate",
}


@dataclass(slots=True)
class RawScan:
    """Result of the byte-level pass."""

    keyword_counts: dict[str, int] = field(default_factory=dict)
    header_offset: int = 0
    pdf_version: str | None = None
    eof_count: int = 0
    incremental_updates: int = 0
    eof_trailing_bytes: int = 0
    entropy: float = 0.0
    obfuscated_names: int = 0
    object_count: int = 0
    stream_count: int = 0
    filters: dict[str, int] = field(default_factory=dict)
    has_header: bool = True


def scan_raw(data: bytes) -> RawScan:
    """Byte-level structural pass; never raises."""
    result = RawScan()
    result.entropy = round(shannon_entropy(data), 4)

    header_index = data[:MAX_HEADER_SEARCH_BYTES].find(PDF_HEADER)
    if header_index < 0:
        result.has_header = False
    else:
        result.header_offset = header_index
        version_slice = data[header_index + len(PDF_HEADER) : header_index + len(PDF_HEADER) + 3]
        try:
            result.pdf_version = version_slice.decode("ascii", errors="ignore").strip()
        except Exception:  # pragma: no cover - defensive
            result.pdf_version = None

    normalised = decode_name_escapes(data)
    result.obfuscated_names = len(_HEX_OBFUSCATED_NAME_RE.findall(data))

    counts: dict[str, int] = {}
    for keyword in PDF_KEYWORDS:
        occurrences = normalised.count(keyword.encode("latin-1"))
        if occurrences:
            counts[keyword] = occurrences
    result.keyword_counts = counts

    result.object_count = len(_OBJ_RE.findall(normalised))
    result.stream_count = len(_STREAM_RE.findall(normalised))

    filters: dict[str, int] = {}
    for match in _FILTER_RE.findall(normalised):
        name = match.decode("ascii")
        filters[name] = filters.get(name, 0) + 1
    result.filters = filters

    eof_positions = [m.start() for m in re.finditer(re.escape(PDF_EOF), data)]
    result.eof_count = len(eof_positions)
    result.incremental_updates = max(0, len(eof_positions) - 1)
    if eof_positions:
        last = eof_positions[-1] + len(PDF_EOF)
        trailing = data[last:].strip(b"\r\n \t")
        result.eof_trailing_bytes = len(trailing)

    return result


# ---------------------------------------------------------------------------
# pikepdf pass
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ParsedDocument:
    """Everything recovered by the object-graph walk."""

    structure: StructureSummary
    metadata: DocumentMetadata
    javascript: list[JavaScriptFinding] = field(default_factory=list)
    actions: list[ActionFinding] = field(default_factory=list)
    embedded_files: list[EmbeddedFileFinding] = field(default_factory=list)
    raw_uri_targets: list[tuple[str, str]] = field(default_factory=list)
    text_excerpt: str = ""
    parse_errors: list[str] = field(default_factory=list)


def parse_document(data: bytes, raw: RawScan) -> ParsedDocument:
    """Walk the PDF object graph with pikepdf. Errors are collected, not raised."""
    settings = get_settings()
    structure = StructureSummary(
        pdf_version=raw.pdf_version,
        object_count=raw.object_count,
        stream_count=raw.stream_count,
        filters=raw.filters,
        incremental_updates=raw.incremental_updates,
        eof_trailing_bytes=raw.eof_trailing_bytes,
        header_offset=raw.header_offset,
    )
    parsed = ParsedDocument(structure=structure, metadata=DocumentMetadata())

    try:
        import pikepdf
    except ImportError as exc:  # pragma: no cover
        parsed.parse_errors.append(f"pikepdf unavailable: {exc}")
        return parsed

    pdf = None
    try:
        pdf = pikepdf.open(io.BytesIO(data), suppress_warnings=True)
    except pikepdf.PasswordError:
        structure.is_encrypted = True
        parsed.parse_errors.append("encrypted: document requires a password")
        return parsed
    except Exception as exc:
        parsed.parse_errors.append(f"open failed: {type(exc).__name__}: {exc}")
        return parsed

    try:
        _walk(pdf, parsed, settings.extract_max_objects, settings.extract_max_js_chars)
    except Exception as exc:  # pragma: no cover - defensive
        parsed.parse_errors.append(f"walk failed: {type(exc).__name__}: {exc}")
    finally:
        try:
            pdf.close()
        except Exception:  # pragma: no cover
            pass

    return parsed


def _walk(pdf: Any, parsed: ParsedDocument, max_objects: int, max_js_chars: int) -> None:
    structure = parsed.structure

    structure.is_encrypted = bool(pdf.is_encrypted)
    if structure.is_encrypted:
        try:
            structure.encryption_method = str(pdf.encryption.stream_method)
        except Exception:
            structure.encryption_method = "unknown"
    try:
        structure.is_linearized = bool(pdf.is_linearized)
    except Exception:
        structure.is_linearized = False
    try:
        structure.page_count = len(pdf.pages)
    except Exception as exc:
        parsed.parse_errors.append(f"page count unavailable: {exc}")
    if not structure.pdf_version:
        structure.pdf_version = str(getattr(pdf, "pdf_version", "") or "") or None

    trailer = getattr(pdf, "trailer", None)
    if trailer is not None:
        try:
            structure.trailer_keys = [str(k) for k in trailer.keys()]
            structure.has_xref_stream = (
                "/XRefStm" in structure.trailer_keys or "/Type" in structure.trailer_keys
            )
        except Exception:
            pass

    root = getattr(pdf, "Root", None)
    if root is not None:
        _inspect_root(root, parsed, max_js_chars)

    _collect_metadata(pdf, parsed)
    _collect_attachments(pdf, parsed)
    _collect_page_level(pdf, parsed, max_js_chars)
    _scan_objects(pdf, parsed, max_objects, max_js_chars)
    _extract_text(pdf, parsed)

    # Derived flags
    structure.has_openaction = any(a.kind == "/OpenAction" for a in parsed.actions)
    structure.has_names_javascript = any(f.location.startswith("/Names") for f in parsed.javascript)


def _inspect_root(root: Any, parsed: ParsedDocument, max_js_chars: int) -> None:
    structure = parsed.structure

    try:
        structure.has_acroform = "/AcroForm" in root
        if structure.has_acroform:
            acroform = root["/AcroForm"]
            structure.has_xfa = "/XFA" in acroform
    except Exception as exc:
        parsed.parse_errors.append(f"acroform inspection failed: {exc}")

    # /OpenAction - runs as soon as the document is opened.
    try:
        if "/OpenAction" in root:
            action = root["/OpenAction"]
            parsed.actions.append(
                ActionFinding(
                    kind="/OpenAction",
                    trigger="DocumentOpen",
                    target=safe_text(_action_target(action)),
                    auto_executes=True,
                    details={"subtype": safe_text(_dict_get(action, "/S"))},
                )
            )
            _harvest_js(action, "/OpenAction", parsed, max_js_chars)
    except Exception as exc:
        parsed.parse_errors.append(f"openaction inspection failed: {exc}")

    # Document-level additional actions.
    try:
        if "/AA" in root:
            _harvest_additional_actions(root["/AA"], "/Root/AA", parsed, max_js_chars)
    except Exception as exc:
        parsed.parse_errors.append(f"document /AA inspection failed: {exc}")

    # /Names /JavaScript - document-level scripts executed at load time.
    try:
        names = root.get("/Names") if hasattr(root, "get") else None
        if names is not None and "/JavaScript" in names:
            _harvest_name_tree(names["/JavaScript"], "/Names/JavaScript", parsed, max_js_chars)
    except Exception as exc:
        parsed.parse_errors.append(f"name tree inspection failed: {exc}")


def _harvest_name_tree(node: Any, location: str, parsed: ParsedDocument, max_js_chars: int) -> None:
    try:
        if "/Names" in node:
            entries = list(node["/Names"])
            for index in range(1, len(entries), 2):
                _harvest_js(entries[index], location, parsed, max_js_chars)
        if "/Kids" in node:
            for kid in node["/Kids"]:
                _harvest_name_tree(kid, location, parsed, max_js_chars)
    except Exception as exc:
        parsed.parse_errors.append(f"name tree walk failed at {location}: {exc}")


def _harvest_additional_actions(
    aa_dict: Any, location: str, parsed: ParsedDocument, max_js_chars: int
) -> None:
    try:
        for key in aa_dict.keys():
            trigger = AA_TRIGGERS.get(str(key), str(key))
            action = aa_dict[key]
            parsed.actions.append(
                ActionFinding(
                    kind="/AA",
                    trigger=trigger,
                    target=safe_text(_action_target(action)),
                    auto_executes=trigger in {"PageOpen", "PageClose", "WillClose", "DocumentOpen"},
                    details={"location": location, "subtype": safe_text(_dict_get(action, "/S"))},
                )
            )
            _harvest_js(action, f"{location}{key}", parsed, max_js_chars)
            _record_action_kind(action, location, parsed)
    except Exception as exc:
        parsed.parse_errors.append(f"additional action walk failed at {location}: {exc}")


def _record_action_kind(action: Any, location: str, parsed: ParsedDocument) -> None:
    """Record /Launch, /URI, /SubmitForm, /GoToR style actions."""
    subtype = safe_text(_dict_get(action, "/S"))
    if not subtype:
        return
    if subtype in {
        "/Launch",
        "/URI",
        "/SubmitForm",
        "/GoToR",
        "/GoToE",
        "/Movie",
        "/Sound",
        "/Rendition",
    }:
        target = safe_text(_action_target(action))
        parsed.actions.append(
            ActionFinding(
                kind=subtype,
                trigger=location,
                target=target,
                auto_executes=subtype in {"/Launch", "/GoToE"},
                details={"location": location},
            )
        )
        if subtype in {"/URI", "/SubmitForm", "/GoToR"} and target:
            parsed.raw_uri_targets.append((target, f"action:{subtype}"))


def _action_target(action: Any) -> Any:
    for key in ("/URI", "/F", "/Win", "/D", "/JS"):
        value = _dict_get(action, key)
        if value is not None:
            if key == "/JS":
                return "<javascript>"
            if key == "/Win":
                return _dict_get(value, "/F") or value
            return value
    return None


def _dict_get(obj: Any, key: str) -> Any:
    try:
        if key in obj:
            return obj[key]
    except Exception:
        return None
    return None


def _harvest_js(container: Any, location: str, parsed: ParsedDocument, max_js_chars: int) -> None:
    """Extract a /JS payload (string or stream) from ``container``."""
    try:
        payload = _dict_get(container, "/JS")
        if payload is None:
            return
        code = _stringify_js(payload)
        if not code:
            return
        if sum(f.length for f in parsed.javascript) > max_js_chars:
            parsed.parse_errors.append("javascript extraction budget exhausted")
            return
        truncated = len(code) > max_js_chars
        parsed.javascript.append(
            JavaScriptFinding(
                location=location,
                length=len(code),
                sha256=sha256_hex(code.encode("utf-8", errors="ignore")),
                code=code[:max_js_chars],
                truncated=truncated,
            )
        )
    except Exception as exc:
        parsed.parse_errors.append(f"javascript extraction failed at {location}: {exc}")


def _stringify_js(payload: Any) -> str:
    try:
        read_bytes = getattr(payload, "read_bytes", None)
        if callable(read_bytes):
            res = read_bytes()
            if isinstance(res, (bytes, bytearray)):
                return res.decode("utf-8", errors="replace")
    except Exception:
        pass
    try:
        return str(payload)
    except Exception:  # pragma: no cover
        return ""


def _collect_metadata(pdf: Any, parsed: ParsedDocument) -> None:
    fields = {
        "/Title": "title",
        "/Author": "author",
        "/Subject": "subject",
        "/Keywords": "keywords",
        "/Creator": "creator",
        "/Producer": "producer",
        "/CreationDate": "creation_date",
        "/ModDate": "modification_date",
    }
    values: dict[str, Any] = {}
    extra: dict[str, Any] = {}
    try:
        docinfo = pdf.docinfo
        for key in docinfo.keys():
            text = safe_text(docinfo[key])
            attr = fields.get(str(key))
            if attr:
                values[attr] = text
            else:
                extra[str(key)] = text
    except Exception as exc:
        parsed.parse_errors.append(f"docinfo unavailable: {exc}")

    try:
        with pdf.open_metadata(update_docinfo=False) as meta:
            for key, value in dict(meta).items():
                extra.setdefault(f"xmp:{key}", safe_text(value, limit=256))
    except Exception:
        pass

    parsed.metadata = DocumentMetadata(**values, extra=extra)


def _collect_attachments(pdf: Any, parsed: ParsedDocument) -> None:
    from pathlib import PurePosixPath

    try:
        attachments = pdf.attachments
    except Exception as exc:
        parsed.parse_errors.append(f"attachments unavailable: {exc}")
        return

    try:
        names = list(attachments.keys())
    except Exception:
        return

    for name in names:
        try:
            spec = attachments[name]
            stream = spec.get_file()
            payload = stream.read_bytes()
            sample = payload[:MAX_EMBEDDED_SAMPLE_BYTES]
            suffix = PurePosixPath(str(name)).suffix.lower()
            parsed.embedded_files.append(
                EmbeddedFileFinding(
                    name=str(name),
                    mime_type=safe_text(getattr(stream, "mime_type", None), limit=128) or None,
                    size=len(payload),
                    sha256=sha256_hex(payload),
                    extension=suffix or None,
                    magic_bytes=identify_magic(sample),
                    entropy=round(shannon_entropy(sample), 4),
                )
            )
        except Exception as exc:
            parsed.parse_errors.append(f"attachment '{name}' unreadable: {exc}")


def _collect_page_level(pdf: Any, parsed: ParsedDocument, max_js_chars: int) -> None:
    try:
        pages = list(pdf.pages)
    except Exception:
        return

    for index, page in enumerate(pages[:512]):
        location = f"/Page[{index}]"
        try:
            if "/AA" in page:
                _harvest_additional_actions(page["/AA"], f"{location}/AA", parsed, max_js_chars)
        except Exception:
            pass
        try:
            annots = page.get("/Annots") if hasattr(page, "get") else None
            if annots is None:
                continue
            for annot in list(annots)[:512]:
                _inspect_annotation(annot, location, parsed, max_js_chars)
        except Exception as exc:
            parsed.parse_errors.append(f"annotation walk failed on page {index}: {exc}")


def _inspect_annotation(
    annot: Any, location: str, parsed: ParsedDocument, max_js_chars: int
) -> None:
    try:
        subtype = safe_text(_dict_get(annot, "/Subtype"))
        action = _dict_get(annot, "/A")
        if action is not None:
            _record_action_kind(action, f"{location}/Annot{subtype}", parsed)
            _harvest_js(action, f"{location}/Annot{subtype}/A", parsed, max_js_chars)
        aa = _dict_get(annot, "/AA")
        if aa is not None:
            _harvest_additional_actions(aa, f"{location}/Annot/AA", parsed, max_js_chars)
        if subtype == "/FileAttachment":
            parsed.actions.append(
                ActionFinding(
                    kind="/FileAttachment",
                    trigger=location,
                    target=safe_text(_dict_get(annot, "/FS")),
                    auto_executes=False,
                )
            )
        if subtype in {"/RichMedia", "/Screen", "/Movie", "/Sound", "/3D"}:
            parsed.actions.append(
                ActionFinding(kind=subtype, trigger=location, auto_executes=False)
            )
    except Exception:
        return


def _scan_objects(pdf: Any, parsed: ParsedDocument, max_objects: int, max_js_chars: int) -> None:
    """Sweep every indirect object for artefacts missed by the targeted walks."""
    seen_js = {f.sha256 for f in parsed.javascript}
    try:
        objects = pdf.objects
    except Exception:
        return

    object_stream_seen = False
    for index, obj in enumerate(objects):
        if index >= max_objects:
            parsed.parse_errors.append("object scan budget exhausted")
            break
        try:
            if not hasattr(obj, "keys"):
                continue
            keys = {str(k) for k in obj.keys()}
            if "/Type" in keys and safe_text(obj["/Type"]) == "/ObjStm":
                object_stream_seen = True
            if "/JS" in keys:
                before = len(parsed.javascript)
                _harvest_js(obj, f"/Object[{index}]", parsed, max_js_chars)
                for finding in parsed.javascript[before:]:
                    if finding.sha256 in seen_js:
                        parsed.javascript.remove(finding)
                    else:
                        seen_js.add(finding.sha256 or "")
                        finding.object_id = str(index)
            if "/Launch" in keys or safe_text(obj.get("/S", None)) == "/Launch":
                parsed.actions.append(
                    ActionFinding(
                        kind="/Launch",
                        trigger=f"/Object[{index}]",
                        target=safe_text(_dict_get(obj, "/F")),
                        auto_executes=True,
                        object_id=str(index),
                    )
                )
            if "/URI" in keys:
                uri = safe_text(obj["/URI"], limit=2048)
                if uri:
                    parsed.raw_uri_targets.append((uri, "object"))
        except Exception:
            continue

    parsed.structure.has_object_streams = object_stream_seen


def _extract_text(pdf: Any, parsed: ParsedDocument) -> None:
    """Pull a short text excerpt for the LLM (social-engineering lures)."""
    try:
        from pypdf import PdfReader
    except ImportError:  # pragma: no cover
        return
    try:
        buffer = io.BytesIO()
        pdf.save(buffer)
        buffer.seek(0)
        reader = PdfReader(buffer)
        chunks: list[str] = []
        for page in reader.pages[:5]:
            chunks.append(page.extract_text() or "")
            if sum(len(c) for c in chunks) >= MAX_TEXT_EXCERPT_CHARS:
                break
        text = "\n".join(chunks).strip()
        parsed.text_excerpt = re.sub(r"\s+", " ", text)[:MAX_TEXT_EXCERPT_CHARS]
    except Exception as exc:
        parsed.parse_errors.append(f"text extraction failed: {exc}")


def file_hashes(data: bytes) -> tuple[str, str]:
    """Return ``(sha256, md5)`` for the raw file."""
    return sha256_hex(data), md5_hex(data)
