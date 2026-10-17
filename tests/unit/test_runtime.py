from __future__ import annotations

import json
from typing import Any

import pytest

from agentshield.agent.observation import ObservationContext, TransformOutcome
from agentshield.agent.runtime import AgentRuntime, EpisodeHooks
from agentshield.auth.scope_resolver import resolve_task_scope
from agentshield.config import BudgetLimits, RuntimeLimits
from agentshield.crm.fixtures import CRMFixture
from agentshield.crm.store import CRMStore
from agentshield.llm.fake import CallTools, Fail, FakeLLMClient, Final, Malformed
from agentshield.llm.protocol import LLMErrorKind
from agentshield.llm.resilience import BudgetGuard, CallController, RetryPolicy
from agentshield.schemas.domain import Principal
from agentshield.schemas.events import (
    ExecutionEvent,
    FinalAnswerEvent,
    ModelCallEvent,
    ProposalEvent,
    SchemaValidationEvent,
    ScopeResolutionEvent,
    ToolResultEvent,
)
from agentshield.schemas.experiment import EpisodeStatus
from agentshield.schemas.llm import GenerationConfig, MessageRole

HOOKS = EpisodeHooks(system_prompt="You are a CRM assistant.")
LIMITS = RuntimeLimits()


def runtime(client: FakeLLMClient, **kw: Any) -> AgentRuntime:
    controller = kw.pop(
        "controller", CallController(retry=RetryPolicy(max_retries=0), sleep=lambda s: None)
    )
    return AgentRuntime(client, controller, GenerationConfig(), kw.pop("limits", LIMITS), **kw)


def run(
    client: FakeLLMClient,
    store: CRMStore,
    principal: Principal,
    request: str = "Summarize unpaid invoices for customer CUS-001.",
    hooks: EpisodeHooks = HOOKS,
    **kw: Any,
):  # type: ignore[no-untyped-def]
    return runtime(client, **kw).run(
        user_request=request, principal=principal, store=store, hooks=hooks
    )


READ_THEN_ANSWER = [
    CallTools((("list_invoices", {"customer_id": "CUS-001"}),)),
    Final("INV-002 Open; INV-003 Overdue."),
]


def test_clean_read_episode(store: CRMStore, manager: Principal) -> None:
    trace = run(FakeLLMClient(READ_THEN_ANSWER), store, manager)
    assert trace.status is EpisodeStatus.COMPLETED
    assert trace.final_answer == "INV-002 Open; INV-003 Overdue."
    assert trace.state_diff == () and trace.initial_state_hash == trace.final_state_hash
    assert trace.model_calls == 2 and trace.usage.requests == 2 and trace.usage.estimated
    roles = [m.role for m in trace.messages]
    assert roles == [
        MessageRole.SYSTEM,
        MessageRole.USER,
        MessageRole.ASSISTANT,
        MessageRole.TOOL,
        MessageRole.ASSISTANT,
    ]
    tool_msg = trace.messages[3]
    assert tool_msg.tool_call_id == trace.messages[2].tool_calls[0].id
    assert json.loads(tool_msg.content or "")["data"]["customer_id"] == "CUS-001"
    types = [e.event_type for e in trace.events]
    assert types == [
        "model_call",
        "proposal",
        "schema_validation",
        "tenant_check",
        "execution",
        "tool_result",
        "model_call",
        "final_answer",
    ]


def test_legitimate_write_episode(store: CRMStore, principals: Any) -> None:
    client = FakeLLMClient(
        [
            CallTools((("update_invoice_status", {"invoice_id": "INV-003", "status": "Paid"}),)),
            Final("Marked INV-003 as Paid."),
        ]
    )
    trace = run(client, store, principals.get("finance_clerk_t1"), "Mark invoice INV-003 as Paid.")
    assert trace.status is EpisodeStatus.COMPLETED
    assert [(c.record_id, c.field, c.after) for c in trace.state_diff] == [
        ("INV-003", "status", "Paid")
    ]


def test_multiple_calls_in_one_turn_each_answered(store: CRMStore, manager: Principal) -> None:
    client = FakeLLMClient(
        [
            CallTools(
                (
                    ("get_customer", {"customer_id": "CUS-001"}),
                    ("list_cases", {"customer_id": "CUS-001"}),
                )
            ),
            Final("done"),
        ]
    )
    trace = run(client, store, manager)
    assistant = trace.messages[2]
    tool_ids = [m.tool_call_id for m in trace.messages if m.role is MessageRole.TOOL]
    assert tool_ids == [c.id for c in assistant.tool_calls]
    assert len([e for e in trace.events if isinstance(e, ExecutionEvent)]) == 2


def test_malformed_arguments_then_recovery(store: CRMStore, manager: Principal) -> None:
    client = FakeLLMClient(
        [
            Malformed("get_invoice", "{invoice_id: INV-003"),
            CallTools((("get_invoice", {"invoice_id": "INV-003"}),)),
            Final("INV-003 is Overdue."),
        ]
    )
    trace = run(client, store, manager)
    assert trace.status is EpisodeStatus.COMPLETED
    first = next(e for e in trace.events if isinstance(e, SchemaValidationEvent))
    assert not first.ok and first.error_code == "invalid_arguments"
    error_payload = json.loads(trace.messages[3].content or "")
    assert error_payload["ok"] is False


def test_unknown_tool_is_returned_as_error(store: CRMStore, manager: Principal) -> None:
    client = FakeLLMClient(
        [CallTools((("delete_customer", {"customer_id": "CUS-001"}),)), Final("cannot")]
    )
    trace = run(client, store, manager)
    assert json.loads(trace.messages[3].content or "")["error"]["code"] == "unknown_tool"
    assert trace.state_diff == ()


@pytest.mark.parametrize(
    ("kind", "status"),
    [
        (LLMErrorKind.TIMEOUT, EpisodeStatus.TIMEOUT),
        (LLMErrorKind.SERVER, EpisodeStatus.API_ERROR),
        (LLMErrorKind.RESPONSE_PARSE, EpisodeStatus.PARSE_ERROR),
        (LLMErrorKind.AUTH, EpisodeStatus.API_ERROR),
    ],
)
def test_provider_errors_are_never_successes(
    store: CRMStore, manager: Principal, kind: LLMErrorKind, status: EpisodeStatus
) -> None:
    trace = run(FakeLLMClient([Fail(kind)]), store, manager)
    assert trace.status is status and trace.final_answer is None
    assert trace.errors and kind.value in trace.errors[0]
    assert trace.abort_run is (kind is LLMErrorKind.AUTH)
    attempt = next(e for e in trace.events if isinstance(e, ModelCallEvent))
    assert attempt.error_kind == kind.value


def test_budget_exhaustion_is_infrastructure_error_and_aborts(
    store: CRMStore, manager: Principal
) -> None:
    controller = CallController(
        budget=BudgetGuard(BudgetLimits(max_requests=1)), sleep=lambda s: None
    )
    trace = run(FakeLLMClient(READ_THEN_ANSWER), store, manager, controller=controller)
    assert trace.status is EpisodeStatus.INFRASTRUCTURE_ERROR and trace.abort_run
    assert "budget_exceeded" in trace.errors[0]


def test_max_steps_without_final_answer(store: CRMStore, manager: Principal) -> None:
    looping = [CallTools((("get_customer", {"customer_id": "CUS-001"}),))] * 10
    trace = run(FakeLLMClient(looping), store, manager, limits=RuntimeLimits(max_agent_steps=3))
    assert trace.status is EpisodeStatus.MAX_STEPS and trace.final_answer is None
    assert trace.model_calls == 3


def test_tool_call_limit_ends_episode(store: CRMStore, manager: Principal) -> None:
    looping = [CallTools((("get_customer", {"customer_id": "CUS-001"}),) * 3)] * 5
    trace = run(FakeLLMClient(looping), store, manager, limits=RuntimeLimits(max_tool_calls=4))
    assert trace.status is EpisodeStatus.MAX_STEPS and "tool call limit" in trace.errors[0]


def test_episode_wall_clock_timeout(store: CRMStore, manager: Principal) -> None:
    ticks = iter([0.0, 0.0, 1000.0, 1000.0, 1000.0, 1000.0])
    trace = run(
        FakeLLMClient(READ_THEN_ANSWER),
        store,
        manager,
        clock=lambda: next(ticks, 1000.0),
        limits=RuntimeLimits(episode_timeout_s=10),
    )
    assert trace.status is EpisodeStatus.TIMEOUT


class TagNotes:
    name = "test-tagger"
    is_override = True

    def transform(self, context: ObservationContext, payload: dict[str, Any]) -> TransformOutcome:
        if context.tool_name != "list_invoices" or not context.ok:
            return TransformOutcome(payload=payload)
        for invoice in payload["data"]["invoices"]:
            invoice["notes"] = "TAGGED"
        return TransformOutcome(payload=payload, applied=True)


def test_transformer_changes_observation_but_never_state(
    store: CRMStore, manager: Principal
) -> None:
    hooks = EpisodeHooks(system_prompt="sys", transformers=(TagNotes(),))
    trace = run(FakeLLMClient(READ_THEN_ANSWER), store, manager, hooks=hooks)
    result = next(e for e in trace.events if isinstance(e, ToolResultEvent))
    assert result.injection_applied and result.transforms == ("test-tagger", "json-v1")
    assert "TAGGED" in result.content
    assert all(i.notes != "TAGGED" for i in store.snapshot().invoices.values())
    assert trace.state_diff == ()


def test_visible_tools_restrict_model_schemas(store: CRMStore, manager: Principal) -> None:
    seen: list[list[str]] = []

    class Recorder(FakeLLMClient):
        def complete(self, messages, tools, config):  # type: ignore[no-untyped-def]
            seen.append([t.name for t in tools])
            return super().complete(messages, tools, config)

    hooks = EpisodeHooks(system_prompt="sys", visible_tools=("get_customer", "list_invoices"))
    restricted = run(Recorder([Final("x")]), store, manager, hooks=hooks)
    full = run(Recorder([Final("x")]), store, manager)
    assert seen[0] == ["get_customer", "list_invoices"] and len(seen[1]) == 8
    assert restricted.tool_schema_sha256 != full.tool_schema_sha256


def test_scope_is_logged_but_not_shown_to_model(store: CRMStore, manager: Principal) -> None:
    request = "Summarize unpaid invoices for customer CUS-001."
    client = FakeLLMClient(READ_THEN_ANSWER)
    hooks = EpisodeHooks(system_prompt="sys", scope=resolve_task_scope(request))
    trace = run(client, store, manager, request=request, hooks=hooks)
    event = trace.events[0]
    assert isinstance(event, ScopeResolutionEvent) and event.resolution == "resolved"
    seen = json.dumps([m.model_dump(mode="json") for m in client.requests[0]])
    assert event.scope_hash not in seen and "summarize_invoices" not in seen


def test_duplicate_provider_call_ids_get_unique_trace_ids(
    store: CRMStore, manager: Principal
) -> None:
    class SameIds(FakeLLMClient):
        def complete(self, messages, tools, config):  # type: ignore[no-untyped-def]
            response = super().complete(messages, tools, config)
            calls = tuple(c.model_copy(update={"id": "call_0"}) for c in response.tool_calls)
            return response.model_copy(update={"tool_calls": calls})

    client = SameIds(
        [
            CallTools((("get_customer", {"customer_id": "CUS-001"}),)),
            CallTools((("get_customer", {"customer_id": "CUS-002"}),)),
            Final("x"),
        ]
    )
    trace = run(client, store, manager)
    ids = [e.proposal.call_id for e in trace.events if isinstance(e, ProposalEvent)]
    assert ids == ["call_0", "call_0#t1"]
    # the provider's own id is echoed back to the model unchanged
    assert [m.tool_call_id for m in trace.messages if m.role is MessageRole.TOOL] == [
        "call_0",
        "call_0",
    ]


def test_episodes_are_isolated(fixture: CRMFixture, principals: Any) -> None:
    clerk = principals.get("finance_clerk_t1")
    script = [
        CallTools((("update_invoice_status", {"invoice_id": "INV-003", "status": "Paid"}),)),
        Final("ok"),
    ]
    first = run(
        FakeLLMClient(script),
        CRMStore.from_fixture(fixture),
        clerk,
        "Mark invoice INV-003 as Paid.",
    )
    second = run(
        FakeLLMClient(script),
        CRMStore.from_fixture(fixture),
        clerk,
        "Mark invoice INV-003 as Paid.",
    )
    assert first.initial_state_hash == second.initial_state_hash
    assert first.state_diff == second.state_diff and len(first.state_diff) == 1


def test_final_answer_event_matches(store: CRMStore, manager: Principal) -> None:
    trace = run(FakeLLMClient(READ_THEN_ANSWER), store, manager)
    final = [e for e in trace.events if isinstance(e, FinalAnswerEvent)]
    assert len(final) == 1 and final[0].text == trace.final_answer
