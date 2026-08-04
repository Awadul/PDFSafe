"""Bring-your-own endpoint provider (OpenAI-compatible Chat Completions).

Works with OpenAI, Azure OpenAI, Together, Groq, OpenRouter, vLLM, Ollama's
compatibility layer, or an internal gateway - anything that speaks
``POST {base_url}/chat/completions`` and supports either tool calling or JSON
output. Configure it with::

    PDFSAFE_AI_PROVIDER=custom
    PDFSAFE_CUSTOM_AI_BASE_URL=https://your-gateway.example.com/v1
    PDFSAFE_CUSTOM_AI_API_KEY=...
    PDFSAFE_CUSTOM_AI_MODEL=your-model-name
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from pdfsafe.ai.base import LLMProvider
from pdfsafe.ai.prompts import TOOL_NAME, openai_tool_definition
from pdfsafe.config import get_settings
from pdfsafe.exceptions import AINotConfiguredError, AIProviderError, AIResponseError
from pdfsafe.logging import get_logger

logger = get_logger(__name__)

# 529 is non-standard but widely used by inference providers (NVIDIA NIM,
# Anthropic) for "capacity is full right now". It is the most transient error
# there is, and omitting it made every occurrence permanent: 6 of 10 calls in
# one run failed on the first attempt at a status that clears in seconds.
_RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}


class CustomOpenAICompatibleProvider(LLMProvider):
    """Chat-completions provider with graceful degradation.

    Tool calling is attempted first. If the endpoint does not support tools, the
    provider falls back to JSON-mode and finally to extracting the first JSON
    object from the reply, so simple self-hosted models still work.
    """

    name = "custom"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str = "",
        model: str = "",
        max_tokens: int | None = None,
        timeout: int | None = None,
        max_retries: int | None = None,
        use_tools: bool = True,
        reasoning_effort: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        settings = get_settings()
        super().__init__(
            model=model or settings.custom_ai_model,
            max_tokens=max_tokens or settings.custom_ai_max_tokens,
            timeout=timeout or settings.ai_timeout_seconds,
        )
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._max_retries = max_retries if max_retries is not None else settings.ai_max_retries
        self.use_tools = use_tools
        self.reasoning_effort = (
            reasoning_effort
            if reasoning_effort is not None
            else settings.custom_ai_reasoning_effort
        )
        self.extra_headers = extra_headers or {}

    def is_configured(self) -> bool:
        return bool(self.base_url and self.model)

    # ----------------------------------------------------------------- call --
    def _invoke(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[dict[str, Any], dict[str, int]]:
        if not self.is_configured():
            raise AINotConfiguredError(
                "PDFSAFE_CUSTOM_AI_BASE_URL and PDFSAFE_CUSTOM_AI_MODEL must be set"
            )

        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        # A thinking model spends this budget reasoning and then has nothing left
        # to answer with, returning an empty message that looks exactly like a
        # parse failure. Suppress the reasoning rather than widen the parser -
        # no parser can recover text the model never emitted.
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        if self.use_tools:
            body["tools"] = [openai_tool_definition()]
            body["tool_choice"] = {"type": "function", "function": {"name": TOOL_NAME}}
        else:
            body["response_format"] = {"type": "json_object"}

        try:
            data = self._post(body)
        except AIResponseError as exc:
            # Reasoning control is not universal: Gemini and the o-series accept
            # it, gpt-4o and most self-hosted gateways reject the whole request.
            # The endpoint is the authority on what it supports, so ask it once
            # rather than making the operator configure it correctly - a setting
            # that must be right for the call to work at all is a setting that
            # will be wrong.
            if "reasoning_effort" not in str(exc) or not self.reasoning_effort:
                raise
            logger.info("custom_provider_dropping_reasoning_effort", model=self.model)
            self.reasoning_effort = ""
            body.pop("reasoning_effort", None)
            data = self._post(body)

        payload = self._extract_payload(data)
        usage_block = data.get("usage") or {}
        usage = {
            "prompt_tokens": int(usage_block.get("prompt_tokens", 0) or 0),
            "completion_tokens": int(usage_block.get("completion_tokens", 0) or 0),
        }
        return payload, usage

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        @retry(
            stop=stop_after_attempt(max(1, self._max_retries)),
            # Congestion clears on the scale of seconds to tens of seconds, so
            # three attempts inside three seconds is not patience, it is three
            # ways of asking at the same moment.
            wait=wait_exponential(multiplier=2, min=2, max=45),
            retry=retry_if_exception_type(AIProviderError),
            reraise=True,
        )
        def _call() -> dict[str, Any]:
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(
                        f"{self.base_url}/chat/completions", json=body, headers=headers
                    )
            except httpx.HTTPError as exc:
                raise AIProviderError(f"Request to {self.base_url} failed: {exc}") from exc

            # A 429 means either "too fast" (worth retrying) or "out of quota"
            # (not). Retrying an exhausted quota spends three requests against
            # the very budget that ran out, so a 150-file run consumed 450.
            # Distinguish them by what the body says.
            if response.status_code == 429 and _quota_exhausted(response.text):
                raise AIResponseError(
                    "Provider quota exhausted - not a rate limit, so retrying would "
                    f"only consume more of it: {response.text[:200]}"
                )
            if response.status_code in _RETRYABLE_STATUS:
                raise AIProviderError(
                    f"Endpoint returned {response.status_code}: {response.text[:300]}"
                )
            if response.status_code == 401 or response.status_code == 403:
                raise AINotConfiguredError(
                    f"Endpoint rejected the credentials ({response.status_code})"
                )
            if response.status_code >= 400:
                raise AIResponseError(
                    f"Endpoint returned {response.status_code}: {response.text[:300]}"
                )
            try:
                parsed: dict[str, Any] = response.json()
            except ValueError as exc:
                raise AIResponseError("Endpoint returned a non-JSON body") from exc
            return parsed

        return _call()

    # -------------------------------------------------------------- parsing --
    @staticmethod
    def _extract_payload(data: dict[str, Any]) -> dict[str, Any]:
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIResponseError("Response did not contain choices[0].message") from exc

        # Truncation and content filtering both surface downstream as "no JSON
        # found", which sends the reader to the parser when the fault is in the
        # request. Name the real cause here; a diagnosis that points at the wrong
        # layer costs more than no diagnosis at all.
        finish = str(choice.get("finish_reason") or "")
        reasoning_tokens = int(
            ((data.get("usage") or {}).get("completion_tokens_details") or {}).get(
                "reasoning_tokens", 0
            )
            or 0
        )
        if finish in {"length", "max_tokens"} and not (
            message.get("tool_calls") or (message.get("content") or "").strip()
        ):
            hint = (
                f" The model spent {reasoning_tokens} tokens reasoning, leaving none for the"
                " answer; set custom_ai_reasoning_effort=none or raise custom_ai_max_tokens."
                if reasoning_tokens
                else " Raise custom_ai_max_tokens."
            )
            raise AIResponseError(f"Response was truncated before any verdict.{hint}")
        if finish == "content_filter":
            raise AIResponseError(
                "Provider's content filter blocked the response. Malware evidence can "
                "trigger this; the file was not analysed by the model."
            )

        # 1. Tool call.
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            if function.get("name") == TOOL_NAME:
                arguments = function.get("arguments")
                if isinstance(arguments, dict):
                    return arguments
                if isinstance(arguments, str):
                    return _loads(arguments)

        # 2. Legacy function_call.
        function_call = message.get("function_call")
        if isinstance(function_call, dict) and function_call.get("arguments"):
            return _loads(str(function_call["arguments"]))

        # 3. Plain content: JSON mode, or JSON embedded in prose.
        content = message.get("content")
        if isinstance(content, list):  # some gateways return content parts
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        if isinstance(content, str) and content.strip():
            return _loads(content)

        raise AIResponseError("Response contained neither a tool call nor JSON content")


def _quota_exhausted(body: str) -> bool:
    """Tell a spent quota apart from a request arriving too quickly.

    Providers overload 429 for both. The distinction matters because backing
    off fixes one and worsens the other.
    """
    lowered = body.lower()
    # "billing" alone was too eager: Groq appends an upgrade link ending in
    # /settings/billing to ordinary per-minute rate limits, so every one of them
    # was misread as an exhausted allowance and never retried - turning a wait
    # of a few seconds into a permanent failure. Match the claim, not the URL.
    if "per minute" in lowered or "tokens per minute" in lowered or "tpm" in lowered:
        return False
    return any(
        phrase in lowered
        for phrase in (
            "exceeded your current quota",
            "quota_exceeded",
            "insufficient_quota",
            "quota exceeded",
            "billing details",
        )
    )


def _loads(text: str) -> dict[str, Any]:
    """Parse JSON, tolerating code fences and surrounding prose."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.split("\n", 1)[-1] if "\n" in cleaned else cleaned
    try:
        value = json.loads(cleaned)
    except ValueError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end <= start:
            raise AIResponseError("Could not locate a JSON object in the response") from None
        try:
            value = json.loads(cleaned[start : end + 1])
        except ValueError as exc:
            raise AIResponseError(f"Response was not valid JSON: {exc}") from exc

    if not isinstance(value, dict):
        raise AIResponseError("Response JSON was not an object")
    return value


def build_from_settings() -> CustomOpenAICompatibleProvider:
    """Build the provider, preferring the OS credential store over the environment."""
    from pdfsafe.credentials import resolve_api_key

    settings = get_settings()
    return CustomOpenAICompatibleProvider(
        base_url=settings.custom_ai_base_url,
        api_key=resolve_api_key("custom", settings.custom_ai_api_key.get_secret_value()),
        model=settings.custom_ai_model,
        reasoning_effort=settings.custom_ai_reasoning_effort,
    )
