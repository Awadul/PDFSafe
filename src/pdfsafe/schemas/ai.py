"""Schemas for the AI triage layer."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from pdfsafe.enums import Verdict


class AIVerdict(BaseModel):
    """Normalised structured output every provider must produce.

    The JSON schema derived from this model is handed to the provider as a tool
    definition, so responses are validated rather than parsed heuristically.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    verdict: Verdict = Field(description="Overall judgement for the document.")
    risk_score: int = Field(ge=0, le=100, description="0 = certainly benign, 100 = certainly malicious.")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the verdict.")
    summary: str = Field(max_length=1000, description="One-paragraph analyst-facing summary.")
    reasoning: str = Field(default="", description="Which evidence drove the verdict.")
    attack_techniques: list[str] = Field(
        default_factory=list,
        description="Observed techniques, e.g. 'JavaScript auto-execution', 'embedded executable'.",
    )
    indicators_of_compromise: list[str] = Field(
        default_factory=list, description="Concrete IOCs: URLs, hashes, file names."
    )
    recommended_action: Literal["allow", "review", "quarantine", "block"] = "review"
    false_positive_risk: Literal["low", "medium", "high"] = "medium"

    @field_validator("verdict", mode="before")
    @classmethod
    def _coerce_verdict(cls, value: object) -> object:
        if isinstance(value, str):
            normalised = value.strip().lower().replace(" ", "_").replace("-", "_")
            aliases = {
                "benign": "clean",
                "safe": "clean",
                "no_threat": "clean",
                "low": "low_risk",
                "lowrisk": "low_risk",
                "medium": "suspicious",
                "potentially_malicious": "suspicious",
                "high": "malicious",
                "malware": "malicious",
                "inconclusive": "unknown",
            }
            return aliases.get(normalised, normalised)
        return value

    @field_validator("risk_score", mode="before")
    @classmethod
    def _clamp_score(cls, value: object) -> object:
        if isinstance(value, int | float):
            return max(0, min(100, int(value)))
        return value


class EvidenceBundle(BaseModel):
    """The compact, token-budgeted payload sent to the LLM.

    Raw PDF bytes are never sent. Only derived, textual evidence is shared, and
    embedded JavaScript is truncated to a configured budget.
    """

    model_config = ConfigDict(extra="forbid")

    file_summary: dict[str, Any]
    structure: dict[str, Any]
    metadata: dict[str, Any]
    keyword_counts: dict[str, int]
    heuristic_score: int
    heuristic_verdict: Verdict
    indicators: list[dict[str, Any]]
    javascript_snippets: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    embedded_files: list[dict[str, Any]] = Field(default_factory=list)
    urls: list[dict[str, Any]] = Field(default_factory=list)
    yara_matches: list[dict[str, Any]] = Field(default_factory=list)
    text_excerpt: str = ""
    truncation_notes: list[str] = Field(default_factory=list)


class AICallResult(BaseModel):
    """Provider response plus accounting information."""

    model_config = ConfigDict(extra="forbid")

    verdict: AIVerdict | None = None
    provider: str
    model: str
    succeeded: bool = True
    error_message: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int | None = None
    cost_usd: float | None = None
    raw_response: dict[str, Any] = Field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return (self.prompt_tokens or 0) + (self.completion_tokens or 0)
