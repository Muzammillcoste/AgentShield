"""Rule-based offline agent for end-to-end fake runs (CLI smoke runs, golden tests, CI).

It reads the user request with its own simple patterns (independent of the trusted scope
grammar), calls the obvious tools one per turn, and writes a factual summary of the tool
results. With `follow_injections=True` it also obeys imperative text found in tool messages.

FAKE OUTPUT IS NEVER RESEARCH EVIDENCE: it exists to exercise the pipeline offline.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from agentshield.llm.fake import INJECTED_CALL_PREFIX, find_pending_injection
from agentshield.llm.resilience import estimate_prompt_tokens, estimate_tokens
from agentshield.schemas.domain import OPEN_CASE_STATUSES, UNPAID_INVOICE_STATUSES
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

HEURISTIC_MODEL_ID = "fake-heuristic-v1"

_ID = {
    "cus": re.compile(r"\bCUS-\d{3,4}\b", re.IGNORECASE),
    "inv": re.compile(r"\bINV-\d{3,4}\b", re.IGNORECASE),
    "opp": re.compile(r"\bOPP-\d{3,4}\b", re.IGNORECASE),
}
_STATUS = re.compile(r"\b(paid|void|open|overdue|disputed)\b", re.IGNORECASE)
_WRITE_VERB = re.compile(r"\b(mark|change|set|update|flip)\b", re.IGNORECASE)
_AMOUNT = re.compile(r"\bto \$?(\d[\d,]*(?:\.\d+)?)", re.IGNORECASE)
_SEND_TO = re.compile(r"\bsend\b.*\bto ([a-z][a-z0-9-]*-[a-z0-9-]+)", re.IGNORECASE)

Call = tuple[str, dict[str, Any]]


def _first(kind: str, text: str) -> str | None:
    match = _ID[kind].search(text)
    return match.group(0).upper() if match else None


def plan_calls(request: str) -> tuple[list[Call], str | None]:
    """Calls to make (in order) and an optional alias to send a summary to."""
    reads, alias = _plan(request)
    cus = _first("cus", request)
    # Compound "summarize ..., then <write> ..." requests: do the summary read first.
    if cus and "summar" in request.lower() and not alias:
        first = (
            "list_cases" if "case" in request.lower() else "list_invoices",
            {"customer_id": cus},
        )
        if first not in reads:
            reads = [first, *reads]
    return reads, alias


def _plan(request: str) -> tuple[list[Call], str | None]:
    cus, inv, opp = _first("cus", request), _first("inv", request), _first("opp", request)
    send = _SEND_TO.search(request)
    lowered = request.lower()
    if send and cus:
        reads = [
            ("get_customer", {"customer_id": cus}),
            ("list_invoices", {"customer_id": cus}),
            ("list_cases", {"customer_id": cus}),
        ]
        return reads, send.group(1).lower()
    status = _STATUS.search(request)
    if inv and status and _WRITE_VERB.search(request):
        return [
            ("get_invoice", {"invoice_id": inv}),
            ("update_invoice_status", {"invoice_id": inv, "status": status.group(1).title()}),
        ], None
    amount = _AMOUNT.search(request)
    if (opp and amount and _WRITE_VERB.search(request)) or (opp and "amount" in lowered and amount):
        value = float(amount.group(1).replace(",", ""))
        return [
            ("get_opportunity", {"opportunity_id": opp}),
            ("update_opportunity_amount", {"opportunity_id": opp, "amount": value}),
        ], None
    if opp:
        return [("get_opportunity", {"opportunity_id": opp})], None
    if cus and "case" in lowered:
        return [("list_cases", {"customer_id": cus})], None
    if cus and "invoice" in lowered:
        return [("list_invoices", {"customer_id": cus})], None
    if cus:
        return [
            ("get_customer", {"customer_id": cus}),
            ("list_invoices", {"customer_id": cus}),
            ("list_cases", {"customer_id": cus}),
        ], None
    if inv:
        return [("get_invoice", {"invoice_id": inv})], None
    return [], None


def _tool_payloads(messages: Sequence[ChatMessage]) -> list[tuple[str, dict[str, Any]]]:
    """(tool name, parsed payload) for every tool message that is valid JSON."""
    names = {c.id: c.name for m in messages for c in m.tool_calls}
    out = []
    for message in messages:
        if message.role is not MessageRole.TOOL or not message.content:
            continue
        content = message.content
        start, end = content.find("{"), content.rfind("}")  # tolerate provenance wrappers
        if start < 0 or end < start:
            continue
        try:
            payload = json.loads(content[start : end + 1])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            out.append((names.get(message.tool_call_id or "", ""), payload))
    return out


def summarize(request: str, messages: Sequence[ChatMessage]) -> str:
    lowered = request.lower()
    lines: list[str] = []
    for tool, payload in _tool_payloads(messages):
        data = payload.get("data")
        if not payload.get("ok"):
            error = payload.get("error") or {}
            lines.append(f"Could not complete {tool}: {error.get('code', 'error')}.")
            continue
        if not isinstance(data, dict):
            continue
        if tool == "list_invoices":
            for inv in data.get("invoices", []):
                if "unpaid" in lowered and inv["status"] not in UNPAID_INVOICE_STATUSES:
                    continue
                lines.append(
                    f"{inv['invoice_id']}: {inv['status']}, {inv['total']} {inv['currency']}, "
                    f"due {inv['due_date']}"
                )
        elif tool == "list_cases":
            for case in data.get("cases", []):
                if "open" in lowered and case["status"] not in OPEN_CASE_STATUSES:
                    continue
                lines.append(
                    f"{case['case_id']} ({case['status']}, {case['priority']}): {case['subject']}"
                )
        elif tool == "get_customer":
            lines.append(f"{data['customer_id']}: {data['name']} ({data['tier']})")
        elif tool == "get_opportunity":
            lines.append(
                f"{data['opportunity_id']}: {data['name']}, amount {data['amount']}, "
                f"stage {data['stage']}"
            )
        elif tool == "get_invoice" and not _WRITE_VERB.search(request):
            lines.append(
                f"{data['invoice_id']}: {data['status']}, {data['total']} {data['currency']}"
            )
        elif tool == "update_invoice_status":
            lines.append(
                f"Updated {data['invoice_id']} status from {data['previous_status']} "
                f"to {data['status']}."
            )
        elif tool == "update_opportunity_amount":
            lines.append(
                f"Updated {data['opportunity_id']} amount from "
                f"{data['previous_amount']} to {data['amount']}."
            )
        elif tool == "send_internal_message":
            lines.append(f"Sent message {data['message_id']} to {data['recipient_alias']}.")
    return "\n".join(lines) or "No matching records found."


@dataclass
class HeuristicFakeAgent:
    follow_injections: bool = False
    model: str = HEURISTIC_MODEL_ID
    requests: int = field(default=0)

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
        self.requests += 1
        turn = sum(1 for m in messages if m.role is MessageRole.ASSISTANT)
        prompt_tokens = estimate_prompt_tokens(messages, tools)
        request = next((m.content or "" for m in messages if m.role is MessageRole.USER), "")

        if self.follow_injections:
            pending = find_pending_injection(messages)
            if pending is not None:
                return self._call(f"{INJECTED_CALL_PREFIX}{turn}-0", pending, prompt_tokens)

        issued = {
            (c.name, json.dumps(c.arguments, sort_keys=True))
            for m in messages
            for c in m.tool_calls
        }
        reads, send_alias = plan_calls(request)
        for name, args in reads:
            if (name, json.dumps(args, sort_keys=True)) not in issued:
                return self._call(f"fake-call-{turn}-0", (name, args), prompt_tokens)
        if send_alias and not any(name == "send_internal_message" for name, _ in issued):
            body = "Customer summary: " + summarize(request, messages).replace("\n", "; ")
            call = ("send_internal_message", {"recipient_alias": send_alias, "body": body[:3900]})
            return self._call(f"fake-call-{turn}-0", call, prompt_tokens)

        text = summarize(request, messages)
        return self._response((), text, prompt_tokens, FinishReason.STOP)

    def _call(self, call_id: str, call: Call, prompt_tokens: int) -> ModelResponse:
        name, args = call
        tool_call = ModelToolCall(
            id=call_id,
            name=name,
            arguments_json=json.dumps(args, sort_keys=True),
            arguments=dict(args),
        )
        return self._response((tool_call,), None, prompt_tokens, FinishReason.TOOL_CALLS)

    def _response(
        self,
        calls: tuple[ModelToolCall, ...],
        text: str | None,
        prompt_tokens: int,
        finish: FinishReason,
    ) -> ModelResponse:
        out = (text or "") + "".join(c.name + c.arguments_json for c in calls)
        return ModelResponse(
            assistant_text=text,
            tool_calls=calls,
            usage=Usage(
                input_tokens=prompt_tokens,
                output_tokens=estimate_tokens(out),
                requests=1,
                estimated=True,
            ),
            finish_reason=finish,
            model_id=self.model,
            provider_kind=ProviderKind.FAKE,
            raw_response_id=f"fake-heuristic-{self.requests}",
        )
