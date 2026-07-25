"""Domain exception hierarchy.

API error handlers map these onto HTTP responses, so business code never has to
import ``fastapi`` to signal a failure.
"""

from __future__ import annotations

from typing import Any


class PDFSafeError(Exception):
    """Base class for all PDFSafe errors."""

    code: str = "pdfsafe_error"
    http_status: int = 500
    message: str = "An unexpected error occurred."

    def __init__(self, message: str | None = None, /, **details: Any) -> None:
        self.message = message or self.message
        self.details: dict[str, Any] = details
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


# ------------------------------------------------------------- ingestion ----
class ValidationError(PDFSafeError):
    code = "validation_error"
    http_status = 422
    message = "The request payload is invalid."


class FileTooLargeError(ValidationError):
    code = "file_too_large"
    http_status = 413
    message = "The uploaded file exceeds the configured size limit."


class UnsupportedFileTypeError(ValidationError):
    code = "unsupported_file_type"
    http_status = 415
    message = "Only PDF files are accepted."


class CorruptPDFError(PDFSafeError):
    code = "corrupt_pdf"
    http_status = 422
    message = "The file could not be parsed as a PDF."


# ---------------------------------------------------------------- domain ----
class ScanNotFoundError(PDFSafeError):
    code = "scan_not_found"
    http_status = 404
    message = "No scan exists with that identifier."


class DuplicateScanError(PDFSafeError):
    code = "duplicate_scan"
    http_status = 409
    message = "This file has already been submitted."


# --------------------------------------------------------------- analysis ---
class AnalysisError(PDFSafeError):
    code = "analysis_error"
    http_status = 500
    message = "Static analysis failed."


class AnalysisTimeoutError(AnalysisError):
    code = "analysis_timeout"
    http_status = 504
    message = "Static analysis exceeded the configured timeout."


# --------------------------------------------------------------------- ai ---
class AIProviderError(PDFSafeError):
    code = "ai_provider_error"
    http_status = 502
    message = "The AI provider could not be reached."


class AIResponseError(AIProviderError):
    code = "ai_response_invalid"
    message = "The AI provider returned an unusable response."


class AIBudgetExceededError(AIProviderError):
    code = "ai_budget_exceeded"
    http_status = 429
    message = "The configured AI token budget has been exhausted."


class AINotConfiguredError(AIProviderError):
    code = "ai_not_configured"
    http_status = 503
    message = "No AI provider is configured."


# -------------------------------------------------------------- transport ---
class AuthenticationError(PDFSafeError):
    code = "unauthorized"
    http_status = 401
    message = "A valid API key is required."


class RateLimitExceededError(PDFSafeError):
    code = "rate_limited"
    http_status = 429
    message = "Too many requests."


class StorageError(PDFSafeError):
    code = "storage_error"
    http_status = 500
    message = "The file could not be stored or retrieved."
