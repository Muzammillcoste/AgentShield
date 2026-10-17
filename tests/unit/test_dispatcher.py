from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from agentshield.crm.dispatcher import (
    ActionRequest,
    DispatchStatus,
    GateDecision,
    ToolDispatcher,
)
from agentshield.crm.store import CRMStore
from agentshield.schemas.domain import InvoiceStatus, Principal
from agentshield.schemas.events import (
    DecisionEvent,
    DecisionKind,
    EventLog,
    ExecutionEvent,
    SchemaValidationEvent,
    TenantCheckEvent,
    TenantCheckOutcome,
    ToolCallProposal,
)


@dataclass
class StubGate:
    gate_id: str
    decision: DecisionKind
    reason: str = "stub"
    shadow_after_deny: bool = False
    seen: list[ActionRequest] = field(default_factory=list)

    def evaluate(self, request: ActionRequest) -> GateDecision:
        self.seen.append(request)
        return GateDecision(decision=self.decision, reason_code=self.reason)


class ExplodingGate:
    gate_id = "D6"

    def evaluate(self, request: ActionRequest) -> GateDecision:
        raise RuntimeError("verifier crashed")


def proposal(
    name: str, args: dict[str, Any] | None, call_id: str = "c1", **kw: Any
) -> ToolCallProposal:
    return ToolCallProposal(call_id=call_id, tool_name=name, args=args, agent_turn=0, **kw)


def make(
    store: CRMStore, principal: Principal, gates: tuple[Any, ...] = (), **kw: Any
) -> tuple[ToolDispatcher, EventLog]:
    log = EventLog()
    return ToolDispatcher(store, principal, log, gates, **kw), log


WRITE = ("update_invoice_status", {"invoice_id": "INV-003", "status": "Paid"})


def test_unknown_tool_is_invalid_and_logged(store: CRMStore, manager: Principal) -> None:
    d, log = make(store, manager)
    out = d.dispatch(proposal("delete_customer", {"customer_id": "CUS-001"}))
    assert out.status is DispatchStatus.INVALID and not out.executed
    event = log.of_type(SchemaValidationEvent)[0]
    assert not event.ok and event.error_code == "unknown_tool"
    assert not log.of_type(ExecutionEvent)


@pytest.mark.parametrize(
    "args",
    [
        None,  # unparseable JSON
        {"invoice_id": "INV-3", "status": "Paid"},  # malformed id
        {"invoice_id": "INV-003", "status": "Settled"},  # invalid enum
        {"invoice_id": "INV-003"},  # missing field
        {"invoice_id": "INV-003", "status": "Paid", "tenant_id": "T2"},  # extra field
    ],
)
def test_schema_validation_rejects_bad_args(
    store: CRMStore, manager: Principal, args: dict[str, Any] | None
) -> None:
    d, _ = make(store, manager)
    before = store.snapshot().state_hash()
    out = d.dispatch(
        proposal(
            "update_invoice_status",
            args,
            arguments_parse_error="bad json" if args is None else None,
        )
    )
    assert out.status is DispatchStatus.INVALID
    assert out.payload["error"]["code"] == "invalid_arguments"
    assert store.snapshot().state_hash() == before


def test_baseline_executes_write_with_full_event_order(store: CRMStore, manager: Principal) -> None:
    d, log = make(store, manager)
    out = d.dispatch(proposal(*WRITE))
    assert out.status is DispatchStatus.EXECUTED and out.executed
    assert store.invoice("INV-003").status is InvoiceStatus.PAID  # type: ignore[union-attr]
    kinds = [e.event_type for e in log.events]
    assert kinds == ["proposal", "schema_validation", "tenant_check", "execution"]
    assert [e.seq for e in log.events] == [0, 1, 2, 3]
    assert log.of_type(ExecutionEvent)[0].state_changes[0].after == "Paid"


def test_tenant_observed_but_not_enforced_in_baseline(store: CRMStore, manager: Principal) -> None:
    d, log = make(store, manager)
    out = d.dispatch(proposal("get_invoice", {"invoice_id": "INV-049"}))  # T2 record
    assert out.status is DispatchStatus.EXECUTED
    check = log.of_type(TenantCheckEvent)[0]
    assert check.outcome is TenantCheckOutcome.MISMATCH and check.enforced is False
    assert check.target_tenant_id == "T2"


def test_tenant_check_for_alias_and_missing_target(store: CRMStore, manager: Principal) -> None:
    d, log = make(store, manager)
    d.dispatch(
        proposal(
            "send_internal_message", {"recipient_alias": "meridian-finance", "body": "x"}, "c1"
        )
    )
    d.dispatch(proposal("get_invoice", {"invoice_id": "INV-999"}, "c2"))
    outcomes = [e.outcome for e in log.of_type(TenantCheckEvent)]
    assert outcomes == [TenantCheckOutcome.MISMATCH, TenantCheckOutcome.TARGET_MISSING]


def test_gate_receives_request_without_scenario_data(store: CRMStore, manager: Principal) -> None:
    gate = StubGate("D5", DecisionKind.ALLOW)
    d, _ = make(store, manager, (gate,))
    d.dispatch(proposal(*WRITE))
    request = gate.seen[0]
    assert request.target_customer_id == "CUS-001" and request.mutated_field == "status"
    assert set(ActionRequest.model_fields) == {
        "call_id",
        "agent_turn",
        "tool_name",
        "access",
        "args",
        "principal",
        "target_ref",
        "target_entity",
        "target_exists",
        "target_tenant_id",
        "target_customer_id",
        "mutated_field",
    }


def test_deny_is_final_and_later_allow_cannot_override(store: CRMStore, manager: Principal) -> None:
    d5 = StubGate("D5", DecisionKind.DENY, "record_not_in_scope")
    d6 = StubGate("D6", DecisionKind.ALLOW)
    d, log = make(store, manager, (d5, d6))
    out = d.dispatch(proposal(*WRITE))
    assert out.status is DispatchStatus.DENIED
    assert out.payload["error"]["reason_code"] == "record_not_in_scope"
    assert store.invoice("INV-003").status is InvoiceStatus.OVERDUE  # type: ignore[union-attr]
    assert d6.seen == []  # not consulted after a deny unless shadow mode
    assert not log.of_type(ExecutionEvent)


def test_shadow_gate_is_logged_but_cannot_change_outcome(
    store: CRMStore, manager: Principal
) -> None:
    d5 = StubGate("D5", DecisionKind.DENY, "wrong_record")
    d6 = StubGate("D6", DecisionKind.ALLOW, shadow_after_deny=True)
    d, log = make(store, manager, (d5, d6))
    out = d.dispatch(proposal(*WRITE))
    assert out.status is DispatchStatus.DENIED
    decisions = log.of_type(DecisionEvent)
    assert [(e.defense_id, e.decision, e.shadow) for e in decisions] == [
        ("D5", DecisionKind.DENY, False),
        ("D6", DecisionKind.ALLOW, True),
    ]


def test_allow_then_deny_also_denies(store: CRMStore, manager: Principal) -> None:
    d, _ = make(
        store, manager, (StubGate("D5", DecisionKind.ALLOW), StubGate("D6", DecisionKind.DENY))
    )
    assert d.dispatch(proposal(*WRITE)).status is DispatchStatus.DENIED


def test_abstain_blocks_writes_but_not_reads(store: CRMStore, manager: Principal) -> None:
    gate = StubGate("D6", DecisionKind.ABSTAIN, "unsure")
    d, _ = make(store, manager, (gate,))
    write = d.dispatch(proposal(*WRITE, call_id="w"))
    assert write.status is DispatchStatus.DENIED
    assert write.payload["error"]["reason_code"] == "abstain_on_high_impact:unsure"
    read = d.dispatch(proposal("get_invoice", {"invoice_id": "INV-003"}, "r"))
    assert read.status is DispatchStatus.EXECUTED


def test_gate_exception_fails_closed(store: CRMStore, manager: Principal) -> None:
    d, log = make(store, manager, (ExplodingGate(),))
    out = d.dispatch(proposal(*WRITE))
    assert (
        out.status is DispatchStatus.DENIED and out.payload["error"]["reason_code"] == "gate_error"
    )
    assert any(e.event_type == "error" for e in log.events)


def test_gate_returning_non_gate_decision_fails_closed(store: CRMStore, manager: Principal) -> None:
    d, _ = make(store, manager, (StubGate("D2", DecisionKind.FLAG),))
    out = d.dispatch(proposal(*WRITE))
    assert out.payload["error"]["reason_code"] == "gate_invalid_decision"


def test_tool_call_limit(store: CRMStore, manager: Principal) -> None:
    d, _ = make(store, manager, max_tool_calls=2)
    for i in range(2):
        assert d.dispatch(proposal("get_customer", {"customer_id": "CUS-001"}, f"c{i}")).executed
    out = d.dispatch(proposal("get_customer", {"customer_id": "CUS-001"}, "c3"))
    assert out.status is DispatchStatus.LIMIT_EXCEEDED


def test_tool_error_is_executed_but_not_ok(store: CRMStore, manager: Principal) -> None:
    d, log = make(store, manager)
    out = d.dispatch(proposal("get_invoice", {"invoice_id": "INV-999"}))
    assert out.status is DispatchStatus.TOOL_ERROR and out.executed
    assert log.of_type(ExecutionEvent)[0].ok is False


def test_scope_hash_recorded_on_decisions(store: CRMStore, manager: Principal) -> None:
    d, log = make(store, manager, (StubGate("D5", DecisionKind.ALLOW),), scope_hash="abc")
    d.dispatch(proposal(*WRITE))
    assert log.of_type(DecisionEvent)[0].scope_snapshot_hash == "abc"
