from __future__ import annotations

import json
from typing import Any

import httpx2
import openai
import pytest
from pydantic import SecretStr

from agentshield.llm.openai_compatible import (
    OpenAICompatibleClient,
    map_sdk_error,
    message_to_wire,
    parse_arguments,
    rate_limit_headers,
    strip_reasoning,
)
from agentshield.llm.protocol import LLMClient, LLMError, LLMErrorKind
from agentshield.llm.settings import ResolvedModelSettings
from agentshield.schemas.llm import (
    ChatMessage,
    FinishReason,
    GenerationConfig,
    MessageRole,
    ModelToolCall,
    ProviderKind,
    ToolSchema,
)

SECRET = "gsk_test_secret_value_1234567890"
SETTINGS = ResolvedModelSettings(
    provider="openai_compatible",
    model_id="qwen/qwen3.8-27b",
    model_source="env:MODEL_NAME",
    base_url="https://api.example.invalid/v1",
    api_key=SecretStr(SECRET),
    api_key_env="LLM_API_KEY",
    extra_body={"reasoning_effort": "none", "reasoning_format": "hidden"},
)
TOOL = ToolSchema(name="get_invoice", description="Get an invoice.", parameters={"type": "object"})


class FakeTransport:
    def __init__(self, data: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        self.data = data
        self.headers = headers or {}
        self.requests: list[dict[str, Any]] = []

    def create_chat_completion(
        self, request: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        self.requests.append(request)
        return self.data, self.headers

    def list_models(self) -> list[dict[str, Any]]:
        return [{"id": "qwen/qwen3.8-27b", "context_window": 131072}]


def completion(message: dict[str, Any], finish: str = "stop", usage: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "chatcmpl-1",
        "model": "qwen/qwen3.8-27b",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
    }
    if usage:
        data["usage"] = {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150}
    return data


def client(
    data: dict[str, Any], headers: dict[str, str] | None = None
) -> tuple[OpenAICompatibleClient, FakeTransport]:
    transport = FakeTransport(data, headers)
    return OpenAICompatibleClient(SETTINGS, transport=transport), transport


MESSAGES = [
    ChatMessage(role=MessageRole.SYSTEM, content="sys"),
    ChatMessage(role=MessageRole.USER, content="Summarize invoice INV-003."),
    ChatMessage(
        role=MessageRole.ASSISTANT,
        tool_calls=(
            ModelToolCall(
                id="call_1",
                name="get_invoice",
                arguments_json='{"invoice_id":"INV-003"}',
                arguments={"invoice_id": "INV-003"},
            ),
        ),
    ),
    ChatMessage(role=MessageRole.TOOL, content='{"ok":true}', tool_call_id="call_1"),
]


def test_settings_repr_never_contains_key() -> None:
    assert SECRET not in repr(SETTINGS) and SECRET not in str(SETTINGS)
    assert SECRET not in json.dumps(SETTINGS.public_view())
    assert SETTINGS.public_view()["api_key_present"] is True


def test_request_shape_and_parameters() -> None:
    c, transport = client(completion({"role": "assistant", "content": "ok"}))
    assert isinstance(c, LLMClient) and c.provider_kind is ProviderKind.REAL
    c.complete(MESSAGES, [TOOL], GenerationConfig(temperature=0.0, max_output_tokens=256, seed=7))
    request = transport.requests[0]
    assert request["model"] == "qwen/qwen3.8-27b"
    assert request["max_completion_tokens"] == 256 and "max_tokens" not in request
    assert request["temperature"] == 0.0 and request["seed"] == 7 and "top_p" not in request
    assert request["tool_choice"] == "auto" and "parallel_tool_calls" not in request
    assert request["tools"][0] == {
        "type": "function",
        "function": {
            "name": "get_invoice",
            "description": "Get an invoice.",
            "parameters": {"type": "object"},
        },
    }
    assert request["extra_body"] == {"reasoning_effort": "none", "reasoning_format": "hidden"}
    wire = request["messages"]
    assert wire[2] == {
        "role": "assistant",
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "get_invoice", "arguments": '{"invoice_id":"INV-003"}'},
            }
        ],
    }
    assert wire[3] == {"role": "tool", "tool_call_id": "call_1", "content": '{"ok":true}'}


def test_no_tools_omits_tool_fields() -> None:
    c, transport = client(completion({"role": "assistant", "content": "ok"}))
    c.complete(MESSAGES[:2], [], GenerationConfig(parallel_tool_calls=False))
    assert (
        "tools" not in transport.requests[0] and "parallel_tool_calls" not in transport.requests[0]
    )


def test_parse_text_response_usage_and_headers() -> None:
    headers = {
        "x-ratelimit-remaining-tokens": "7000",
        "X-RateLimit-Reset-Tokens": "7.5s",
        "authorization": "Bearer x",
        "set-cookie": "a",
    }
    c, _ = client(completion({"role": "assistant", "content": "INV-003 is Overdue."}), headers)
    r = c.complete(MESSAGES[:2], [TOOL], GenerationConfig())
    assert r.assistant_text == "INV-003 is Overdue." and r.finish_reason is FinishReason.STOP
    assert (r.usage.input_tokens, r.usage.output_tokens, r.usage.estimated) == (120, 30, False)
    assert r.model_id == "qwen/qwen3.8-27b" and r.raw_response_id == "chatcmpl-1"
    assert r.rate_limit_headers == {
        "x-ratelimit-remaining-tokens": "7000",
        "x-ratelimit-reset-tokens": "7.5s",
    }


def test_parse_tool_calls_valid_invalid_and_non_object() -> None:
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "a",
                "type": "function",
                "function": {"name": "get_invoice", "arguments": '{"invoice_id":"INV-003"}'},
            },
            {
                "id": "b",
                "type": "function",
                "function": {"name": "get_invoice", "arguments": "{invoice_id: INV-003"},
            },
            {
                "id": "c",
                "type": "function",
                "function": {"name": "get_invoice", "arguments": "[1,2]"},
            },
            {
                "id": "d",
                "type": "function",
                "function": {
                    "name": "get_invoice",
                    "arguments": json.dumps('{"invoice_id":"INV-004"}'),
                },
            },
        ],
    }
    c, _ = client(completion(message, finish="tool_calls"))
    r = c.complete(MESSAGES[:2], [TOOL], GenerationConfig())
    assert r.finish_reason is FinishReason.TOOL_CALLS
    a, b, cc, d = r.tool_calls
    assert a.arguments == {"invoice_id": "INV-003"} and a.parse_error is None
    assert b.arguments is None and b.parse_error and "not valid JSON" in b.parse_error
    assert cc.arguments is None and cc.parse_error == "arguments must be a JSON object"
    assert d.arguments == {"invoice_id": "INV-004"}  # double-encoded arguments tolerated


def test_missing_usage_is_flagged_not_invented() -> None:
    c, _ = client(completion({"role": "assistant", "content": "x"}, usage=False))
    r = c.complete(MESSAGES[:2], [], GenerationConfig())
    assert r.usage.estimated and r.usage.input_tokens == 0


def test_empty_choices_is_parse_error() -> None:
    c, _ = client({"id": "x", "choices": []})
    with pytest.raises(LLMError) as info:
        c.complete(MESSAGES[:2], [], GenerationConfig())
    assert info.value.kind is LLMErrorKind.RESPONSE_PARSE


@pytest.mark.parametrize(
    ("content", "expected", "removed"),
    [
        ("<think>secret plan</think>Final answer.", "Final answer.", 26),
        ("Answer<think>x</think> more", "Answer more", 16),
        ("<think>truncated reasoning without end", None, 38),
        ("plain", "plain", 0),
        (None, None, 0),
    ],
)
def test_reasoning_is_stripped(content: str | None, expected: str | None, removed: int) -> None:
    text, count = strip_reasoning(content)
    assert text == expected and count == removed


def test_reasoning_field_is_dropped_and_counted() -> None:
    c, _ = client(
        completion({"role": "assistant", "content": "Done.", "reasoning": "hidden steps"})
    )
    r = c.complete(MESSAGES[:2], [], GenerationConfig())
    assert r.assistant_text == "Done." and r.reasoning_chars_removed == len("hidden steps")
    assert "hidden steps" not in r.model_dump_json()


def _status_error(
    cls: type[openai.APIStatusError],
    status: int,
    body: object = None,
    headers: dict[str, str] | None = None,
) -> openai.APIStatusError:
    request = httpx2.Request("POST", "https://api.example.invalid/v1/chat/completions")
    response = httpx2.Response(status, request=request, headers=headers or {})
    return cls(f"error with key {SECRET}", response=response, body=body)


def test_error_mapping() -> None:
    rate = map_sdk_error(
        _status_error(
            openai.RateLimitError,
            429,
            headers={"retry-after": "3", "x-ratelimit-remaining-tokens": "0"},
        ),
        SECRET,
    )
    assert rate.kind is LLMErrorKind.RATE_LIMIT and rate.retryable and rate.retry_after_s == 3.0
    assert rate.headers == {"retry-after": "3", "x-ratelimit-remaining-tokens": "0"}
    assert SECRET not in rate.message and "[REDACTED]" in rate.message

    auth = map_sdk_error(_status_error(openai.AuthenticationError, 401), SECRET)
    assert auth.kind is LLMErrorKind.AUTH and not auth.retryable
    tool_fail = map_sdk_error(
        _status_error(
            openai.BadRequestError, 400, body={"error": {"code": "tool_use_failed", "message": "x"}}
        ),
        SECRET,
    )
    assert tool_fail.kind is LLMErrorKind.RESPONSE_PARSE and not tool_fail.retryable
    assert (
        map_sdk_error(_status_error(openai.BadRequestError, 400), SECRET).kind
        is LLMErrorKind.BAD_REQUEST
    )
    assert (
        map_sdk_error(_status_error(openai.NotFoundError, 404), SECRET).kind
        is LLMErrorKind.CONFIGURATION
    )
    server = map_sdk_error(_status_error(openai.InternalServerError, 503), SECRET)
    assert server.kind is LLMErrorKind.SERVER and server.retryable
    request = httpx2.Request("POST", "https://api.example.invalid/v1/chat/completions")
    timeout = map_sdk_error(openai.APITimeoutError(request=request))
    assert timeout.kind is LLMErrorKind.TIMEOUT and timeout.retryable
    assert map_sdk_error(openai.APIConnectionError(request=request)).kind is LLMErrorKind.CONNECTION


def test_helpers() -> None:
    assert rate_limit_headers({"Retry-After": "2", "Content-Type": "json"}) == {"retry-after": "2"}
    assert parse_arguments("{}") == ({}, None)
    assert message_to_wire(ChatMessage(role=MessageRole.ASSISTANT, content=None)) == {
        "role": "assistant",
        "content": "",
    }


def test_list_models_passthrough() -> None:
    c, _ = client(completion({"role": "assistant", "content": "x"}))
    assert c.list_models()[0]["id"] == "qwen/qwen3.8-27b"


def test_fake_settings_rejected_for_real_client() -> None:
    fake = ResolvedModelSettings(provider="fake", model_id="fake", model_source="config")
    with pytest.raises(LLMError):
        OpenAICompatibleClient(fake, transport=FakeTransport({}))
