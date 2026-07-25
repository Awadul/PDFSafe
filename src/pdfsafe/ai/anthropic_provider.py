"""Anthropic Claude provider.

Uses tool calling so the model must return a payload matching
:class:`~pdfsafe.schemas.ai.AIVerdict` rather than free-form prose.
"""

from __future__ import annotations

from functools import cached_property
from typing import Any

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from pdfsafe.ai.base import LLMProvider
from pdfsafe.ai.prompts import TOOL_NAME, tool_definition
from pdfsafe.config import get_settings
from pdfsafe.exceptions import AINotConfiguredError, AIProviderError, AIResponseError
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

#: USD per million tokens. Update when pricing changes; used only for reporting.
PRICING: dict[str, tuple[float, float]] = {
    "claude-sonnet-5": (3.00, 15.00),
    "claude-opus-5": (15.00, 75.00),
    "claude-haiku-4-5-20251001": (1.00, 5.00),
}


class AnthropicProvider(LLMProvider):
    """Claude-backed triage."""

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str | None = None,
        max_tokens: int | None = None,
        timeout: int | None = None,
        max_retries: int | None = None,
    ) -> None:
        settings = get_settings()
        super().__init__(
            model=model or settings.anthropic_model,
            max_tokens=max_tokens or settings.anthropic_max_tokens,
            timeout=timeout or settings.ai_timeout_seconds,
        )
        self._api_key = api_key
        self._max_retries = max_retries if max_retries is not None else settings.ai_max_retries

    # ---------------------------------------------------------------- setup --
    def is_configured(self) -> bool:
        return bool(self._api_key)

    @cached_property
    def _client(self) -> Any:
        if not self._api_key:
            raise AINotConfiguredError("PDFSAFE_ANTHROPIC_API_KEY is not set")
        try:
            from anthropic import Anthropic
        except ImportError as exc:  # pragma: no cover
            raise AINotConfiguredError("The 'anthropic' package is not installed") from exc
        return Anthropic(
            api_key=self._api_key,
            timeout=float(self.timeout),
            max_retries=0,  # retries are handled by tenacity so they are observable
        )

    # ----------------------------------------------------------------- call --
    def _invoke(self, system_prompt: str, user_prompt: str) -> tuple[dict[str, Any], dict[str, int]]:
        response = self._create_message(system_prompt, user_prompt)

        payload = self._extract_tool_input(response)
        usage = {
            "prompt_tokens": int(getattr(response.usage, "input_tokens", 0) or 0),
            "completion_tokens": int(getattr(response.usage, "output_tokens", 0) or 0),
        }
        return payload, usage

    def _create_message(self, system_prompt: str, user_prompt: str) -> Any:
        @retry(
            stop=stop_after_attempt(max(1, self._max_retries)),
            wait=wait_exponential(multiplier=1, min=1, max=20),
            retry=retry_if_exception_type(AIProviderError),
            reraise=True,
        )
        def _call() -> Any:
            try:
                return self._client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_prompt}],
                    tools=[tool_definition()],
                    tool_choice={"type": "tool", "name": TOOL_NAME},
                )
            except Exception as exc:
                raise self._translate(exc) from exc

        return _call()

    @staticmethod
    def _translate(exc: Exception) -> Exception:
        """Map SDK exceptions onto the PDFSafe hierarchy."""
        try:
            import anthropic
        except ImportError:  # pragma: no cover
            return AIProviderError(str(exc))

        if isinstance(exc, anthropic.AuthenticationError | anthropic.PermissionDeniedError):
            return AINotConfiguredError(f"Anthropic rejected the credentials: {exc}")
        if isinstance(exc, anthropic.BadRequestError):
            return AIResponseError(f"Anthropic rejected the request: {exc}")
        if isinstance(
            exc,
            anthropic.RateLimitError
            | anthropic.APIConnectionError
            | anthropic.APITimeoutError
            | anthropic.InternalServerError,
        ):
            return AIProviderError(f"Anthropic call failed (retryable): {exc}")
        if isinstance(exc, anthropic.APIStatusError):
            return AIProviderError(f"Anthropic returned {exc.status_code}: {exc}")
        return AIProviderError(f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _extract_tool_input(response: Any) -> dict[str, Any]:
        for block in getattr(response, "content", []) or []:
            if getattr(block, "type", None) == "tool_use" and getattr(block, "name", "") == TOOL_NAME:
                data = getattr(block, "input", None)
                if isinstance(data, dict):
                    return data
        stop_reason = getattr(response, "stop_reason", None)
        raise AIResponseError(
            f"Model did not call {TOOL_NAME} (stop_reason={stop_reason})",
        )

    # ---------------------------------------------------------------- cost ---
    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float | None:
        pricing = PRICING.get(self.model)
        if not pricing:
            return None
        input_rate, output_rate = pricing
        return round(
            (prompt_tokens / 1_000_000) * input_rate + (completion_tokens / 1_000_000) * output_rate,
            6,
        )


def build_from_settings() -> AnthropicProvider:
    """Build the provider, preferring the OS credential store over the environment."""
    from pdfsafe.credentials import resolve_api_key

    settings = get_settings()
    api_key = resolve_api_key("anthropic", settings.anthropic_api_key.get_secret_value())
    return AnthropicProvider(api_key=api_key)
