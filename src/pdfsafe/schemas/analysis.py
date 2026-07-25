"""Schemas describing static-analysis output.

These models are the boundary between the parsing layer and everything else:
the scoring engine, the database, the API and the LLM prompt all consume them.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from pdfsafe.enums import Severity


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False, str_strip_whitespace=True)


class IndicatorResult(_Model):
    """A single suspicious trait with its contribution to the risk score."""

    code: str = Field(description="Stable machine-readable id, e.g. PDF_JS_AUTO_EXEC")
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    weight: int = Field(default=0, ge=0, le=100)
    category: str = "structure"
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_technique: str | None = None

    def as_prompt_line(self) -> str:
        return f"[{self.severity.value.upper()}|w={self.weight}] {self.code}: {self.title}"


class JavaScriptFinding(_Model):
    """Embedded JavaScript recovered from the document."""

    location: str = Field(description="Where it was found, e.g. /Names/JavaScript or /OpenAction")
    object_id: str | None = None
    length: int = 0
    sha256: str | None = None
    code: str = Field(default="", description="Possibly truncated source")
    truncated: bool = False
    suspicious_tokens: list[str] = Field(default_factory=list)
    entropy: float | None = None
    obfuscation_score: float = Field(default=0.0, ge=0.0, le=1.0)


class ActionFinding(_Model):
    """An automatic or interactive action declared in the document."""

    kind: str = Field(description="/OpenAction, /AA, /Launch, /SubmitForm, /URI, /GoToR, ...")
    trigger: str | None = Field(default=None, description="e.g. WillClose, PageOpen")
    target: str | None = None
    object_id: str | None = None
    auto_executes: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class EmbeddedFileFinding(_Model):
    """A file attached inside the PDF."""

    name: str
    mime_type: str | None = None
    size: int = 0
    sha256: str | None = None
    extension: str | None = None
    is_executable_type: bool = False
    magic_bytes: str | None = None
    entropy: float | None = None


class URLFinding(_Model):
    """A URL extracted from annotations, actions, JavaScript or raw streams."""

    url: str
    scheme: str = ""
    host: str = ""
    source: str = "unknown"
    is_ip_literal: bool = False
    is_shortener: bool = False
    is_punycode: bool = False
    suspicious_tld: bool = False
    port: int | None = None


class YaraMatch(_Model):
    """A YARA rule that fired against the raw bytes."""

    rule: str
    namespace: str = "default"
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
    strings: list[str] = Field(default_factory=list)


class DocumentMetadata(_Model):
    """Document information dictionary / XMP fields."""

    title: str | None = None
    author: str | None = None
    subject: str | None = None
    keywords: str | None = None
    creator: str | None = None
    producer: str | None = None
    creation_date: str | None = None
    modification_date: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class StructureSummary(_Model):
    """Low-level structural facts about the file."""

    pdf_version: str | None = None
    page_count: int | None = None
    object_count: int = 0
    stream_count: int = 0
    filters: dict[str, int] = Field(default_factory=dict)
    is_encrypted: bool = False
    encryption_method: str | None = None
    is_linearized: bool = False
    has_xref_stream: bool = False
    has_object_streams: bool = False
    incremental_updates: int = 0
    trailer_keys: list[str] = Field(default_factory=list)
    has_acroform: bool = False
    has_xfa: bool = False
    has_openaction: bool = False
    has_names_javascript: bool = False
    eof_trailing_bytes: int = 0
    header_offset: int = 0
    max_object_depth: int = 0


class StaticAnalysisResult(_Model):
    """Everything the parsing layer produced for one file."""

    # identity
    sha256: str
    md5: str
    file_size: int
    detected_type: str | None = None
    analyzer_version: str = "1.0.0"
    analysis_ms: int = 0

    # structure
    structure: StructureSummary = Field(default_factory=StructureSummary)
    metadata: DocumentMetadata = Field(default_factory=DocumentMetadata)
    keyword_counts: dict[str, int] = Field(default_factory=dict)
    entropy: float | None = None

    # findings
    javascript: list[JavaScriptFinding] = Field(default_factory=list)
    actions: list[ActionFinding] = Field(default_factory=list)
    embedded_files: list[EmbeddedFileFinding] = Field(default_factory=list)
    urls: list[URLFinding] = Field(default_factory=list)
    yara_matches: list[YaraMatch] = Field(default_factory=list)

    # text
    text_excerpt: str = ""

    # scoring (filled in by the heuristics engine)
    indicators: list[IndicatorResult] = Field(default_factory=list)

    # non-fatal problems encountered while parsing
    parse_errors: list[str] = Field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        from pdfsafe.enums import max_severity

        return max_severity([i.severity for i in self.indicators])

    @property
    def has_active_content(self) -> bool:
        return bool(self.javascript) or any(a.auto_executes for a in self.actions)
