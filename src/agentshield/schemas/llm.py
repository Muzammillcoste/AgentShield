"""Provider-neutral chat, tool-call and usage contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from agentshield.schemas.common import StrictModel


class ProviderKind(StrEnum):
    """`fake` output is for software testing only and never counts as research evidence."""

    FAKE = "fake"
    REAL = "real"


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ModelToolCall(StrictModel):
    id: str
    name: str
    arguments_json: str
    arguments: dict[str, Any] | None = None
    parse_error: str | None = None


class ChatMessage(StrictModel):
    role: MessageRole
    content: str | None = None
    tool_calls: tuple[ModelToolCall, ...] = ()
    tool_call_id: str | None = None

    @model_validator(mode="after")
    def _check_role_fields(self) -> ChatMessage:
        if self.role is MessageRole.TOOL and not self.tool_call_id:
            raise ValueError("tool messages require tool_call_id")
        if self.role is not MessageRole.TOOL and self.tool_call_id:
            raise ValueError("only tool messages may set tool_call_id")
        if self.tool_calls and self.role is not MessageRole.ASSISTANT:
            raise ValueError("only assistant messages may carry tool_calls")
        return self


class ToolSchema(StrictModel):
    name: str
    description: str
    parameters: dict[str, Any]


class Usage(StrictModel):
    input_tokens: Annotated[int, Field(ge=0)] = 0
    output_tokens: Annotated[int, Field(ge=0)] = 0
    requests: Annotated[int, Field(ge=0)] = 1
    # True when counts are approximations (fake provider) rather than provider-reported.
    estimated: bool = False

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            requests=self.requests + other.requests,
            estimated=self.estimated or other.estimated,
        )


class FinishReason(StrEnum):
    STOP = "stop"
    TOOL_CALLS = "tool_calls"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"
    OTHER = "other"


class ModelResponse(StrictModel):
    assistant_text: str | None = None
    tool_calls: tuple[ModelToolCall, ...] = ()
    usage: Usage
    finish_reason: FinishReason
    model_id: str
    provider_kind: ProviderKind
    raw_response_id: str | None = None
    latency_ms: Annotated[float, Field(ge=0)] = 0.0
    # Non-secret provider rate-limit headers (x-ratelimit-*, retry-after) for throttling.
    rate_limit_headers: dict[str, str] = Field(default_factory=dict)
    # Characters of model reasoning removed before the text entered the transcript.
    reasoning_chars_removed: Annotated[int, Field(ge=0)] = 0


class GenerationConfig(StrictModel):
    """Sampling settings. Temperature/seed are recorded, never treated as determinism."""

    temperature: Annotated[float, Field(ge=0, le=2)] | None = 0.0
    top_p: Annotated[float, Field(gt=0, le=1)] | None = None
    max_output_tokens: Annotated[int, Field(ge=1, le=32768)] = 1024
    seed: int | None = None
    timeout_s: Annotated[float, Field(gt=0, le=600)] = 60.0
    tool_choice: Literal["auto", "none", "required"] = "auto"
    # None = do not send the parameter (not every model/provider supports it).
    parallel_tool_calls: bool | None = None
