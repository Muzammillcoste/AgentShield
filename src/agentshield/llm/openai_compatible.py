"""Real LLM client for OpenAI-compatible chat-completions APIs (e.g. Groq) with native tools.

The HTTP layer sits behind a small `ChatTransport` seam: production uses the official
`openai` SDK (with SDK retries disabled, so every attempt is visible to our own retry loop);
tests use an in-memory transport. Model reasoning is never stored: `<think>` blocks are
stripped from content and a separate `reasoning` field is ignored (only its size is counted).
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

import openai

from agentshield.llm.protocol import LLMError, LLMErrorKind
from agentshield.llm.settings import ResolvedModelSettings
from agentshield.schemas.llm import (
    ChatMessage,
    FinishReason,
    GenerationConfig,
    MessageRole,
    ModelResponse,
    ModelToolCall,
    ProviderKind,
    ToolSchema,
    Usage,
)

_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_THINK_OPEN = re.compile(r"<think>.*\Z", re.DOTALL | re.IGNORECASE)
_FINISH = {
    "stop": FinishReason.STOP,
    "tool_calls": FinishReason.TOOL_CALLS,
    "length": FinishReason.LENGTH,
    "content_filter": FinishReason.CONTENT_FILTER,
}


class ChatTransport(Protocol):
    def create_chat_completion(
        self, request: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, str]]: ...

    def list_models(self) -> list[dict[str, Any]]: ...


def rate_limit_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Keep only non-secret rate-limit headers (lower-cased names)."""
    out = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered.startswith("x-ratelimit-") or lowered == "retry-after":
            out[lowered] = str(value)
    return out


def redact(text: str, secret: str | None) -> str:
    if secret and len(secret) >= 8:
        text = text.replace(secret, "[REDACTED]")
    return text


def _error_code(body: object) -> str | None:
    if isinstance(body, dict):
        inner = body.get("error", body)
        if isinstance(inner, dict) and isinstance(inner.get("code"), str):
            return str(inner["code"])
    return None


def _retry_after(headers: Mapping[str, str]) -> float | None:
    value = headers.get("retry-after")
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def map_sdk_error(exc: Exception, secret: str | None = None) -> LLMError:
    """Translate an `openai` SDK exception into a normalized `LLMError`."""
    message = redact(str(exc), secret)[:500]
    if isinstance(exc, openai.APITimeoutError):
        return LLMError(LLMErrorKind.TIMEOUT, message)
    if isinstance(exc, openai.APIConnectionError):
        return LLMError(LLMErrorKind.CONNECTION, message)
    if isinstance(exc, openai.APIResponseValidationError):
        return LLMError(LLMErrorKind.RESPONSE_PARSE, message)
    if isinstance(exc, openai.APIStatusError):
        status = exc.status_code
        headers = rate_limit_headers(dict(exc.response.headers))
        code = _error_code(exc.body)
        kwargs: dict[str, Any] = {"status_code": status, "headers": headers}
        if status == 429:
            return LLMError(
                LLMErrorKind.RATE_LIMIT, message, retry_after_s=_retry_after(headers), **kwargs
            )
        if status in (401, 403):
            return LLMError(LLMErrorKind.AUTH, message, **kwargs)
        if code == "tool_use_failed":
            # The model produced an unparseable tool call; retrying the same prompt is
            # unlikely to help and would spend quota, so it ends the episode as parse_error.
            return LLMError(LLMErrorKind.RESPONSE_PARSE, message, retryable=False, **kwargs)
        if status == 404:
            return LLMError(LLMErrorKind.CONFIGURATION, message, **kwargs)
        if 400 <= status < 500:
            return LLMError(LLMErrorKind.BAD_REQUEST, message, **kwargs)
        if status >= 500:
            return LLMError(LLMErrorKind.SERVER, message, **kwargs)
    return LLMError(LLMErrorKind.UNKNOWN, message)


class OpenAISDKTransport:
    """Production transport over the official `openai` SDK (SDK-level retries disabled)."""

    def __init__(self, settings: ResolvedModelSettings) -> None:
        if settings.api_key is None or settings.base_url is None:
            raise LLMError(LLMErrorKind.CONFIGURATION, "real provider needs api key and base URL")
        self._secret = settings.api_key.get_secret_value()
        self._client = openai.OpenAI(
            api_key=self._secret,
            base_url=settings.base_url,
            max_retries=0,
            timeout=settings.generation.timeout_s,
        )

    def create_chat_completion(
        self, request: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        try:
            raw = self._client.chat.completions.with_raw_response.create(**request)
            completion = raw.parse()
        except openai.OpenAIError as exc:
            raise map_sdk_error(exc, self._secret) from None
        return completion.model_dump(mode="json"), dict(raw.headers)

    def list_models(self) -> list[dict[str, Any]]:
        try:
            return [model.model_dump(mode="json") for model in self._client.models.list()]
        except openai.OpenAIError as exc:
            raise map_sdk_error(exc, self._secret) from None


def strip_reasoning(content: str | None) -> tuple[str | None, int]:
    """Remove `<think>` blocks (complete or truncated). Returns (text, removed_chars)."""
    if not content:
        return content, 0
    cleaned = _THINK_BLOCK.sub("", content)
    cleaned = _THINK_OPEN.sub("", cleaned)
    removed = len(content) - len(cleaned)
    return cleaned.strip() or None, removed


def parse_arguments(arguments_json: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(arguments_json)
        if isinstance(value, str):  # some models double-encode the arguments object
            value = json.loads(value)
    except (json.JSONDecodeError, TypeError) as exc:
        return None, f"arguments are not valid JSON: {exc.msg if hasattr(exc, 'msg') else exc}"
    if not isinstance(value, dict):
        return None, "arguments must be a JSON object"
    return value, None


def message_to_wire(message: ChatMessage) -> dict[str, Any]:
    wire: dict[str, Any] = {"role": message.role.value}
    if message.role is MessageRole.TOOL:
        wire["tool_call_id"] = message.tool_call_id
        wire["content"] = message.content or ""
        return wire
    if message.content is not None or not message.tool_calls:
        wire["content"] = message.content or ""
    if message.tool_calls:
        wire["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {"name": call.name, "arguments": call.arguments_json},
            }
            for call in message.tool_calls
        ]
    return wire


def tool_to_wire(tool: ToolSchema) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
        },
    }


class OpenAICompatibleClient:
    """`LLMClient` for real providers. Never substitutes fake output on failure."""

    def __init__(
        self,
        settings: ResolvedModelSettings,
        transport: ChatTransport | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        if settings.provider != "openai_compatible":
            raise LLMError(LLMErrorKind.CONFIGURATION, "settings are not for a real provider")
        self._settings = settings
        self._transport = transport or OpenAISDKTransport(settings)
        self._clock = clock

    @property
    def provider_kind(self) -> ProviderKind:
        return ProviderKind.REAL

    @property
    def model_id(self) -> str:
        return self._settings.model_id

    def build_request(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSchema],
        config: GenerationConfig,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "model": self._settings.model_id,
            "messages": [message_to_wire(m) for m in messages],
            self._settings.max_tokens_param: config.max_output_tokens,
            "timeout": config.timeout_s,
        }
        if tools:
            request["tools"] = [tool_to_wire(t) for t in tools]
            request["tool_choice"] = config.tool_choice
            if config.parallel_tool_calls is not None:
                request["parallel_tool_calls"] = config.parallel_tool_calls
        for name in ("temperature", "top_p", "seed"):
            value = getattr(config, name)
            if value is not None:
                request[name] = value
        if self._settings.extra_body:
            request["extra_body"] = dict(self._settings.extra_body)
        return request

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSchema],
        config: GenerationConfig,
    ) -> ModelResponse:
        request = self.build_request(messages, tools, config)
        started = self._clock()
        data, headers = self._transport.create_chat_completion(request)
        latency_ms = (self._clock() - started) * 1000
        return self.parse_response(data, headers, latency_ms)

    def parse_response(
        self, data: dict[str, Any], headers: Mapping[str, str], latency_ms: float
    ) -> ModelResponse:
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(LLMErrorKind.RESPONSE_PARSE, "response contained no choices")
        message = choices[0].get("message") or {}
        text, removed = strip_reasoning(message.get("content"))
        removed += len(message.get("reasoning") or "")

        calls = []
        for index, raw_call in enumerate(message.get("tool_calls") or []):
            function = raw_call.get("function") or {}
            arguments_json = function.get("arguments") or ""
            arguments, error = parse_arguments(arguments_json)
            calls.append(
                ModelToolCall(
                    id=raw_call.get("id") or f"call-{index}",
                    name=function.get("name") or "",
                    arguments_json=arguments_json,
                    arguments=arguments,
                    parse_error=error,
                )
            )

        usage_data = data.get("usage") or {}
        if "prompt_tokens" in usage_data:
            usage = Usage(
                input_tokens=int(usage_data.get("prompt_tokens") or 0),
                output_tokens=int(usage_data.get("completion_tokens") or 0),
                requests=1,
            )
        else:  # provider omitted usage: mark as unknown rather than inventing numbers
            usage = Usage(input_tokens=0, output_tokens=0, requests=1, estimated=True)

        finish = _FINISH.get(str(choices[0].get("finish_reason")), FinishReason.OTHER)
        return ModelResponse(
            assistant_text=text,
            tool_calls=tuple(calls),
            usage=usage,
            finish_reason=finish,
            model_id=str(data.get("model") or self._settings.model_id),
            provider_kind=ProviderKind.REAL,
            raw_response_id=data.get("id"),
            latency_ms=latency_ms,
            rate_limit_headers=rate_limit_headers(headers),
            reasoning_chars_removed=removed,
        )

    def list_models(self) -> list[dict[str, Any]]:
        return self._transport.list_models()
