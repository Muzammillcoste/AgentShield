"""Provider-neutral LLM client protocol and normalized provider errors."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol, runtime_checkable

from agentshield.schemas.llm import (
    ChatMessage,
    GenerationConfig,
    ModelResponse,
    ProviderKind,
    ToolSchema,
)


class LLMErrorKind(StrEnum):
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    BAD_REQUEST = "bad_request"
    SERVER = "server"
    CONNECTION = "connection"
    RESPONSE_PARSE = "response_parse"
    CONTENT_FILTER = "content_filter"
    BUDGET_EXCEEDED = "budget_exceeded"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


RETRYABLE_KINDS: frozenset[LLMErrorKind] = frozenset(
    {LLMErrorKind.TIMEOUT, LLMErrorKind.RATE_LIMIT, LLMErrorKind.SERVER, LLMErrorKind.CONNECTION}
)


class LLMError(Exception):
    """A normalized provider failure. Never scored as a successful defense."""

    def __init__(
        self,
        kind: LLMErrorKind,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool | None = None,
    ) -> None:
        super().__init__(f"{kind}: {message}")
        self.kind = kind
        self.message = message
        self.status_code = status_code
        self.retryable = kind in RETRYABLE_KINDS if retryable is None else retryable


@runtime_checkable
class LLMClient(Protocol):
    @property
    def provider_kind(self) -> ProviderKind: ...

    @property
    def model_id(self) -> str: ...

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSchema],
        config: GenerationConfig,
    ) -> ModelResponse: ...
