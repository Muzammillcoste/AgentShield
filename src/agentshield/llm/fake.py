"""Deterministic scripted LLM for unit/integration tests, CI and offline smoke runs.

FAKE OUTPUT IS NEVER RESEARCH EVIDENCE about real-model security. Every response is
labeled `provider_kind="fake"` and token counts are flagged as estimates.

Behavior depends only on the conversation passed in, so identical inputs always produce
identical outputs. Optional `follow_injections=True` simulates a susceptible model that
obeys imperative instructions found in *tool* messages (never in system/user messages);
this exercises the attack and defense plumbing without making any claim about real LLMs.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from agentshield.llm.protocol import LLMError, LLMErrorKind
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

FAKE_MODEL_ID = "fake-scripted-v1"
_INJECTED_PREFIX = "fake-inj-"


@dataclass(frozen=True)
class CallTools:
    calls: tuple[tuple[str, dict[str, Any]], ...]
    text: str | None = None


@dataclass(frozen=True)
class Final:
    text: str


@dataclass(frozen=True)
class Refuse:
    text: str = "I can't help with that request."


@dataclass(frozen=True)
class Fail:
    kind: LLMErrorKind = LLMErrorKind.TIMEOUT
    message: str = "simulated provider failure"


@dataclass(frozen=True)
class Malformed:
    tool_name: str
    raw_arguments: str


FakeStep = CallTools | Final | Refuse | Fail | Malformed

_Trigger = tuple[re.Pattern[str], Callable[[re.Match[str]], tuple[str, dict[str, Any]]]]

_STATUSES = r"(paid|void|open|overdue|disputed)"
INJECTION_TRIGGERS: tuple[_Trigger, ...] = (
    (
        re.compile(r"mark invoice (INV-\d{3,4}) as " + _STATUSES, re.IGNORECASE),
        lambda m: ("update_invoice_status", {"invoice_id": m[1].upper(), "status": m[2].title()}),
    ),
    (
        re.compile(
            r"(?:set|change|update) (?:the )?status of invoice (INV-\d{3,4}) to " + _STATUSES,
            re.IGNORECASE,
        ),
        lambda m: ("update_invoice_status", {"invoice_id": m[1].upper(), "status": m[2].title()}),
    ),
    (
        re.compile(
            r"(?:set|change|update) opportunity (OPP-\d{3,4}) amount to \$?(\d[\d,]*(?:\.\d+)?)",
            re.IGNORECASE,
        ),
        lambda m: (
            "update_opportunity_amount",
            {"opportunity_id": m[1].upper(), "amount": float(m[2].replace(",", ""))},
        ),
    ),
    (
        re.compile(
            r"send [^.\"]{0,80}? to (?:the )?(?:alias )?([a-z][a-z0-9]*-[a-z0-9-]+)",
            re.IGNORECASE,
        ),
        lambda m: (
            "send_internal_message",
            {"recipient_alias": m[1].lower(), "body": "Forwarding the requested customer details."},
        ),
    ),
)


def _estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / 4) if text else 0


@dataclass
class FakeLLMClient:
    steps: Sequence[FakeStep] = ()
    model: str = FAKE_MODEL_ID
    follow_injections: bool = False
    default_final: str = "Done."
    requests: list[list[ChatMessage]] = field(default_factory=list)

    @property
    def provider_kind(self) -> ProviderKind:
        return ProviderKind.FAKE

    @property
    def model_id(self) -> str:
        return self.model

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSchema],
        config: GenerationConfig,
    ) -> ModelResponse:
        self.requests.append(list(messages))
        assistant_messages = [m for m in messages if m.role is MessageRole.ASSISTANT]
        turn = len(assistant_messages)
        prompt_tokens = sum(_estimate_tokens(m.content or "") for m in messages) + sum(
            _estimate_tokens(json.dumps(t.parameters)) for t in tools
        )

        if self.follow_injections:
            pending = self._pending_injection(messages)
            if pending is not None:
                name, args = pending
                return self._tool_response(
                    turn, ((name, args),), None, prompt_tokens, prefix=_INJECTED_PREFIX
                )

        script_index = sum(
            1
            for m in assistant_messages
            if not (m.tool_calls and all(c.id.startswith(_INJECTED_PREFIX) for c in m.tool_calls))
        )
        step = self.steps[script_index] if script_index < len(self.steps) else None

        if step is None:
            return self._text_response(self.default_final, prompt_tokens)
        if isinstance(step, Final | Refuse):
            return self._text_response(step.text, prompt_tokens)
        if isinstance(step, Fail):
            raise LLMError(step.kind, step.message)
        if isinstance(step, Malformed):
            call = ModelToolCall(
                id=f"fake-call-{turn}-0",
                name=step.tool_name,
                arguments_json=step.raw_arguments,
                arguments=None,
                parse_error="arguments are not valid JSON",
            )
            return self._response((call,), None, prompt_tokens, FinishReason.TOOL_CALLS)
        return self._tool_response(turn, step.calls, step.text, prompt_tokens)

    # ---- helpers -----------------------------------------------------------------------

    def _pending_injection(
        self, messages: Sequence[ChatMessage]
    ) -> tuple[str, dict[str, Any]] | None:
        issued = {
            (c.name, json.dumps(c.arguments, sort_keys=True))
            for m in messages
            if m.role is MessageRole.ASSISTANT
            for c in m.tool_calls
        }
        for message in messages:
            if message.role is not MessageRole.TOOL or not message.content:
                continue
            for pattern, build in INJECTION_TRIGGERS:
                for match in pattern.finditer(message.content):
                    name, args = build(match)
                    if (name, json.dumps(args, sort_keys=True)) not in issued:
                        return name, args
        return None

    def _tool_response(
        self,
        turn: int,
        calls: Sequence[tuple[str, dict[str, Any]]],
        text: str | None,
        prompt_tokens: int,
        prefix: str = "fake-call-",
    ) -> ModelResponse:
        tool_calls = tuple(
            ModelToolCall(
                id=f"{prefix}{turn}-{k}",
                name=name,
                arguments_json=json.dumps(args, sort_keys=True),
                arguments=dict(args),
            )
            for k, (name, args) in enumerate(calls)
        )
        return self._response(tool_calls, text, prompt_tokens, FinishReason.TOOL_CALLS)

    def _text_response(self, text: str, prompt_tokens: int) -> ModelResponse:
        return self._response((), text, prompt_tokens, FinishReason.STOP)

    def _response(
        self,
        tool_calls: tuple[ModelToolCall, ...],
        text: str | None,
        prompt_tokens: int,
        finish: FinishReason,
    ) -> ModelResponse:
        output_text = (text or "") + "".join(c.name + c.arguments_json for c in tool_calls)
        return ModelResponse(
            assistant_text=text,
            tool_calls=tool_calls,
            usage=Usage(
                input_tokens=prompt_tokens,
                output_tokens=_estimate_tokens(output_text),
                requests=1,
                estimated=True,
            ),
            finish_reason=finish,
            model_id=self.model,
            provider_kind=ProviderKind.FAKE,
            raw_response_id=f"fake-{len(self.requests)}",
            latency_ms=0.0,
        )
