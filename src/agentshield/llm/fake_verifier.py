"""Deterministic offline stand-in for the D6 verifier model (tests / fake runs only).

It reads the review JSON and ALLOWs a proposed write/send only if the target id (or
recipient) and the new value literally appear in the user's request; otherwise DENY.
Never research evidence about real verifier models.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

from agentshield.llm.resilience import estimate_prompt_tokens, estimate_tokens
from agentshield.schemas.llm import (
    ChatMessage,
    FinishReason,
    GenerationConfig,
    MessageRole,
    ModelResponse,
    ProviderKind,
    ToolSchema,
    Usage,
)

FAKE_VERIFIER_MODEL_ID = "fake-verifier-v1"


def _verdict(review: dict[str, object]) -> tuple[str, str]:
    request = str(review.get("user_request", "")).lower()
    action = review.get("proposed_action")
    if not isinstance(action, dict):
        return "ABSTAIN", "no proposed action"
    args = action.get("arguments") or {}
    if not isinstance(args, dict):
        return "ABSTAIN", "unreadable arguments"
    target = str(
        args.get("invoice_id") or args.get("opportunity_id") or args.get("recipient_alias") or ""
    ).lower()
    if not target or target not in request:
        return "DENY", "target not mentioned in the user's request"
    value = args.get("status", args.get("amount"))
    if value is not None:
        text_ok = str(value).lower() in request
        number_ok = False
        try:  # amounts arrive normalized, e.g. "185000.00"
            number = float(str(value))
            numbers = {
                float(n.replace(",", "")) for n in re.findall(r"\d[\d,]*(?:\.\d+)?", request)
            }
            number_ok = number in numbers
        except ValueError:
            pass
        if not (text_ok or number_ok):
            return "DENY", "value not requested"
    return "ALLOW", "matches the user's request"


@dataclass
class HeuristicFakeVerifier:
    model: str = FAKE_VERIFIER_MODEL_ID

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
        user = next((m.content or "" for m in messages if m.role is MessageRole.USER), "{}")
        try:
            review = json.loads(user)
        except json.JSONDecodeError:
            review = {}
        decision, reason = _verdict(review if isinstance(review, dict) else {})
        text = json.dumps({"decision": decision, "reason": reason})
        return ModelResponse(
            assistant_text=text,
            usage=Usage(
                input_tokens=estimate_prompt_tokens(messages, tools),
                output_tokens=estimate_tokens(text),
                estimated=True,
            ),
            finish_reason=FinishReason.STOP,
            model_id=self.model,
            provider_kind=ProviderKind.FAKE,
        )
