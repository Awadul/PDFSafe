"""Provider abstraction.

Adding a new backend means subclassing :class:`LLMProvider`, implementing
``_invoke`` and registering it. Nothing else in the codebase needs to change.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from pdfsafe.exceptions import AIProviderError, AIResponseError
from pdfsafe.logging import get_logger
from pdfsafe.metrics import ai_calls_total, ai_latency_seconds, ai_tokens_total
from pdfsafe.schemas.ai import AICallResult, AIVerdict, EvidenceBundle

logger = get_logger(__name__)


class LLMProvider(ABC):
    """Base class for every AI backend."""

    #: Short stable identifier used in config, metrics and the database.
    name: str = "base"

    def __init__(self, *, model: str, max_tokens: int = 2048, timeout: int = 60) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout

    # ------------------------------------------------------------ contract --
    @abstractmethod
    def _invoke(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[dict[str, Any], dict[str, int]]:
        """Call the backend.

        Returns:
            A tuple of ``(parsed_verdict_payload, usage)`` where ``usage`` has
            ``prompt_tokens`` and ``completion_tokens`` keys.

        Raises:
            AIProviderError: transport, auth or rate-limit failures.
            AIResponseError: the model returned something unusable.
        """

    @abstractmethod
    def is_configured(self) -> bool:
        """Whether the provider has everything it needs to run."""

    # -------------------------------------------------------------- public --
    def assess(self, evidence: EvidenceBundle) -> AICallResult:
        """Run one triage call and normalise the outcome.

        Never raises: failures are reported via ``AICallResult.succeeded`` so a
        provider outage degrades the pipeline to heuristics-only rather than
        failing the scan.
        """
        from pdfsafe.ai.prompts import build_system_prompt, build_user_prompt

        started = time.perf_counter()
        system_prompt = build_system_prompt()
        user_prompt = build_user_prompt(evidence)

        try:
            payload, usage = self._invoke(system_prompt, user_prompt)
        except (AIProviderError, AIResponseError) as exc:
            ai_calls_total.labels(provider=self.name, outcome="error").inc()
            logger.warning("ai_call_failed", provider=self.name, model=self.model, error=str(exc))
            return AICallResult(
                provider=self.name,
                model=self.model,
                succeeded=False,
                error_message=str(exc),
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:  # pragma: no cover - defensive
            ai_calls_total.labels(provider=self.name, outcome="error").inc()
            logger.exception("ai_call_crashed", provider=self.name)
            return AICallResult(
                provider=self.name,
                model=self.model,
                succeeded=False,
                error_message=f"{type(exc).__name__}: {exc}",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )

        latency_ms = int((time.perf_counter() - started) * 1000)
        ai_latency_seconds.labels(provider=self.name).observe(latency_ms / 1000)

        try:
            verdict = AIVerdict.model_validate(payload)
        except Exception as exc:
            ai_calls_total.labels(provider=self.name, outcome="invalid").inc()
            logger.warning("ai_response_invalid", provider=self.name, error=str(exc))
            return AICallResult(
                provider=self.name,
                model=self.model,
                succeeded=False,
                error_message=f"Response did not match the expected schema: {exc}",
                latency_ms=latency_ms,
                raw_response=payload,
            )

        prompt_tokens = int(usage.get("prompt_tokens", 0)) or None
        completion_tokens = int(usage.get("completion_tokens", 0)) or None
        if prompt_tokens:
            ai_tokens_total.labels(provider=self.name, kind="prompt").inc(prompt_tokens)
        if completion_tokens:
            ai_tokens_total.labels(provider=self.name, kind="completion").inc(completion_tokens)
        ai_calls_total.labels(provider=self.name, outcome="success").inc()

        logger.info(
            "ai_assessment",
            provider=self.name,
            model=self.model,
            verdict=verdict.verdict.value,
            risk_score=verdict.risk_score,
            confidence=verdict.confidence,
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

        return AICallResult(
            verdict=verdict,
            provider=self.name,
            model=self.model,
            succeeded=True,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            cost_usd=self.estimate_cost(prompt_tokens or 0, completion_tokens or 0),
            raw_response=payload,
        )

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float | None:
        """Optional cost estimate in USD; ``None`` when pricing is unknown."""
        return None

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} model={self.model!r}>"


class NullProvider(LLMProvider):
    """No-op provider: keeps the pipeline running with heuristics only."""

    name = "null"

    def __init__(self) -> None:
        super().__init__(model="none", max_tokens=0, timeout=0)

    def is_configured(self) -> bool:
        return True

    def _invoke(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[dict[str, Any], dict[str, int]]:
        raise AIProviderError("No AI provider is configured; heuristics-only mode.")
