"""Optional OCR for image-only documents.

A scanned document contains no extractable text, so every text-based signal in
PDFSafe is blind to it: phishing wording is invisible to the rules and to the
model, and ``PDF_MINIMAL_DOC_WITH_ACTIVE_CONTENT`` cannot tell a scanned form
from a dropper, because both look like a page with nothing on it.

**This changes the threat model, which is why it is off by default.**

Everywhere else PDFSafe reads structure and never renders. OCR requires
rasterising a page, which means running a rendering engine over
attacker-controlled input - and rasterisers have their own history of memory
corruption bugs. Three things contain that:

* it only runs inside the spawned parser child, never in the UI process
* it is capped by page count, resolution and character budget
* it is opt-in, so a user who does not need it is not exposed to it

The dependencies are an extra (``pip install pdfsafe[ocr]``) rather than part of
the default install, so the shipped bundle does not carry a rendering engine and
OCR models that most users will never invoke.

Nothing here raises. If a dependency is missing or a page will not render, the
result is empty text and the document is analysed exactly as it is today.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from pdfsafe.logging import get_logger

logger = get_logger(__name__)

#: Rasterising at print resolution is unnecessary for reading a phishing lure
#: and multiplies both the work and the memory a hostile page can demand.
MAX_DPI = 200


@dataclass(slots=True)
class OcrResult:
    """Text recovered from page images, plus how it was obtained."""

    text: str = ""
    pages_processed: int = 0
    engine: str = ""

    def __bool__(self) -> bool:
        return bool(self.text.strip())


#: Where the common Windows installers put Tesseract. The UB-Mannheim build -
#: the one `winget install UB-Mannheim.TesseractOCR` provides - does not add
#: itself to PATH unless the user ticks a box during setup, so "installed" and
#: "findable" are routinely different states. Reporting "not installed" to
#: somebody who just installed it is a bad answer.
_TESSERACT_CANDIDATES = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe",
    "/usr/bin/tesseract",
    "/usr/local/bin/tesseract",
    "/opt/homebrew/bin/tesseract",
)


def _locate_tesseract() -> str | None:
    """Find the binary when it is not on PATH. Honours an explicit override."""
    from pdfsafe.config import get_settings

    configured = get_settings().ocr_tesseract_path.strip()
    if configured and Path(configured).is_file():
        return configured

    for candidate in _TESSERACT_CANDIDATES:
        path = Path(os.path.expandvars(candidate))
        if path.is_file():
            return str(path)
    return None


def _tesseract_ready() -> bool:
    """Whether the Tesseract *binary* is callable, not merely importable.

    ``import pytesseract`` succeeds with no Tesseract installed - it is a thin
    subprocess wrapper, and the failure only appears when you ask it to read
    something. Probing the version here turns "OCR silently produced nothing"
    into "OCR is not installed", which is the difference between a bug report
    and a setup instruction.

    If PATH lookup fails, the usual install directories are searched before
    giving up, because the standard Windows installer does not modify PATH.
    """
    try:
        import pytesseract
    except ImportError:
        return False

    try:
        pytesseract.get_tesseract_version()
    except Exception:
        located = _locate_tesseract()
        if located is None:
            return False
        pytesseract.pytesseract.tesseract_cmd = located
        try:
            pytesseract.get_tesseract_version()
        except Exception:
            return False
        logger.info("tesseract_located_off_path", path=located)
    return True


def _rapidocr_ready() -> bool:
    try:
        import rapidocr_onnxruntime  # noqa: F401
    except ImportError:
        return False
    return True


def available(preference: str = "auto") -> tuple[bool, str]:
    """Whether OCR can run, and which engine would be used.

    Tesseract is preferred in ``auto`` mode. Both work, and for reading a
    phishing lure their accuracy difference does not matter - but Tesseract is
    one audited Apache-2.0 binary, where RapidOCR brings OpenCV, ONNX Runtime
    and opaque model weights. In a tool whose job is to inspect hostile input,
    the smaller and more auditable dependency wins a tie.

    Returns ``(False, reason)`` rather than raising so a missing optional
    dependency is reported as a note on the scan instead of a failed scan.
    """
    try:
        import pypdfium2  # noqa: F401
    except ImportError:
        return False, "pypdfium2 is not installed (pip install 'pdfsafe[ocr-tesseract]')"

    if preference == "tesseract":
        return (True, "tesseract") if _tesseract_ready() else (False, "tesseract is not installed")
    if preference == "rapidocr":
        return (True, "rapidocr") if _rapidocr_ready() else (False, "rapidocr is not installed")

    if _tesseract_ready():
        return True, "tesseract"
    if _rapidocr_ready():
        return True, "rapidocr"

    return False, (
        "no OCR engine available - install Tesseract "
        "(winget install UB-Mannheim.TesseractOCR) and pip install 'pdfsafe[ocr-tesseract]', "
        "or pip install 'pdfsafe[ocr-rapidocr]'"
    )


def _render_pages(data: bytes, *, max_pages: int, dpi: int) -> list[object]:
    """Rasterise the first ``max_pages`` pages to PIL images.

    Uses pypdfium2 rather than poppler or pdf2image: it ships as a self-contained
    wheel with no system package to install, which matters for a frozen Windows
    build where an external binary would have to be located at runtime.
    """
    import pypdfium2

    scale = min(dpi, MAX_DPI) / 72.0
    document = pypdfium2.PdfDocument(data)
    try:
        images = []
        for index in range(min(len(document), max_pages)):
            page = document[index]
            try:
                images.append(page.render(scale=scale).to_pil())
            finally:
                page.close()
        return images
    finally:
        document.close()


@lru_cache(maxsize=1)
def _rapidocr_reader() -> Any:
    """Load the ONNX models once per process, not once per document.

    ``RapidOCR()`` loads three models - detection, classification, recognition -
    and builds an onnxruntime session for each. That is tens of seconds of work,
    and constructing it inside the read loop paid that cost for every single
    file. Cached here it is paid once per worker process.
    """
    # onnxruntime defaults to one thread per core. The benchmark runs several
    # worker processes, so each spawning a full thread pool oversubscribes the
    # CPU badly - the threads spend their time contending rather than working.
    # Must be set before onnxruntime is first imported in this process.
    os.environ.setdefault("OMP_NUM_THREADS", "1")

    from rapidocr_onnxruntime import RapidOCR

    return RapidOCR()


def _read(images: list[object], engine: str) -> str:
    if engine == "rapidocr":
        import numpy

        reader = _rapidocr_reader()
        chunks: list[str] = []
        for image in images:
            result, _ = reader(numpy.array(image))
            if result:
                chunks.extend(str(line[1]) for line in result)
        return "\n".join(chunks)

    import pytesseract

    return "\n".join(pytesseract.image_to_string(image) for image in images)


def extract_text(
    data: bytes,
    *,
    max_pages: int = 3,
    dpi: int = 150,
    max_chars: int = 4000,
    engine_preference: str = "auto",
) -> OcrResult:
    """Recover text from a document's page images. Never raises.

    Args:
        data: Raw file bytes.
        max_pages: Hard cap on pages rendered. A phishing lure is on page one;
            a 500-page scan should not cost 500 renders.
        dpi: Rasterisation resolution, clamped to :data:`MAX_DPI`.
        max_chars: Truncation budget for the returned text.
        engine_preference: ``auto``, ``tesseract`` or ``rapidocr``.
    """
    ready, engine = available(engine_preference)
    if not ready:
        # WARNING, not debug. Reaching here means the user explicitly enabled
        # OCR - the pipeline does not call this otherwise - so "no engine
        # installed" is a misconfiguration, not a routine condition.
        #
        # It was debug once, and the consequence was a full corpus run that
        # produced results identical to having OCR switched off. Nothing in the
        # output distinguished "OCR found no extra text" from "OCR never ran",
        # and a 9x speed difference was attributed to the engine rather than to
        # the engine being absent.
        logger.warning(
            "ocr_requested_but_unavailable",
            reason=engine,
            requested_engine=engine_preference,
            impact="documents will be analysed as if OCR were disabled",
        )
        return OcrResult()

    try:
        images = _render_pages(data, max_pages=max_pages, dpi=dpi)
    except Exception as exc:
        logger.warning("ocr_render_failed", error=f"{type(exc).__name__}: {exc}")
        return OcrResult()

    if not images:
        return OcrResult()

    try:
        text = _read(images, engine)
    except Exception as exc:
        logger.warning("ocr_read_failed", engine=engine, error=f"{type(exc).__name__}: {exc}")
        return OcrResult()

    return OcrResult(text=text[:max_chars].strip(), pages_processed=len(images), engine=engine)
