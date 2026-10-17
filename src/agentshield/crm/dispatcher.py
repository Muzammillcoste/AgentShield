"""Central tool dispatcher: the only path from an agent proposal to the CRM.

Order per call: proposal -> schema validation -> tenant observation -> action gates
(D4/D5/D6 when enabled) -> atomic execution. Gate semantics are deny-precedence:
any DENY is final, ABSTAIN rejects mutating (high-impact) calls, and a gate that raises
fails closed. Later gates can never turn an earlier denial into an ALLOW.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from enum import StrEnum
from typing import Any, Protocol

from pydantic import Field, ValidationError

from agentshield.crm.store import CRMStore
from agentshield.crm.tools import (
    ToolAccess,
    ToolContext,
    ToolErrorCode,
    ToolOutput,
    ToolSpec,
    error_output,
    get_tool,
)
from agentshield.schemas.common import EntityType, StrictModel
from agentshield.schemas.domain import Principal
from agentshield.schemas.events import (
    DecisionEvent,
    DecisionKind,
    ErrorEvent,
    EventLog,
    ExecutionEvent,
    ProposalEvent,
    SchemaValidationEvent,
    TenantCheckEvent,
    TenantCheckOutcome,
    ToolCallProposal,
)


class ActionRequest(StrictModel):
    """Everything a gate may inspect. Contains no scenario labels or tool-output text."""

    call_id: str
    agent_turn: int
    tool_name: str
    access: ToolAccess
    args: dict[str, Any]
    principal: Principal
    target_ref: str
    target_entity: EntityType | None
    target_exists: bool
    target_tenant_id: str | None
    target_customer_id: str | None
    mutated_field: str | None


class GateDecision(StrictModel):
    decision: DecisionKind
    reason_code: str
    details: dict[str, Any] = Field(default_factory=dict)


class ActionGate(Protocol):
    gate_id: str

    def evaluate(self, request: ActionRequest) -> GateDecision: ...


class DispatchStatus(StrEnum):
    EXECUTED = "executed"
    TOOL_ERROR = "tool_error"
    DENIED = "denied"
    INVALID = "invalid"
    LIMIT_EXCEEDED = "limit_exceeded"


class DispatchOutcome(StrictModel):
    call_id: str
    tool_name: str
    status: DispatchStatus
    payload: dict[str, Any]
    output: ToolOutput | None = None

    @property
    def executed(self) -> bool:
        return self.status in (DispatchStatus.EXECUTED, DispatchStatus.TOOL_ERROR)


DENIAL_MESSAGE = "This action is not permitted for the current request."


class ToolDispatcher:
    def __init__(
        self,
        store: CRMStore,
        principal: Principal,
        event_log: EventLog,
        gates: Sequence[ActionGate] = (),
        *,
        max_tool_calls: int = 16,
        scope_hash: str | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._store = store
        self._principal = principal
        self._log = event_log
        self._gates = tuple(gates)
        self._max_tool_calls = max_tool_calls
        self._scope_hash = scope_hash
        self._clock = clock
        self._calls = 0
        self._context = ToolContext(principal_id=principal.id, tenant_id=principal.tenant_id)

    @property
    def calls_dispatched(self) -> int:
        return self._calls

    def dispatch(self, proposal: ToolCallProposal) -> DispatchOutcome:
        self._log.emit(ProposalEvent, proposal=proposal)
        self._calls += 1
        if self._calls > self._max_tool_calls:
            self._log.emit(
                DecisionEvent,
                defense_id="runtime",
                decision=DecisionKind.DENY,
                reason_code="tool_call_limit_exceeded",
                call_id=proposal.call_id,
            )
            return self._fail(
                proposal,
                DispatchStatus.LIMIT_EXCEEDED,
                ToolErrorCode.LIMIT_EXCEEDED,
                "Tool call limit for this request reached.",
            )

        spec = get_tool(proposal.tool_name)
        if spec is None:
            return self._invalid(proposal, ToolErrorCode.UNKNOWN_TOOL, "Unknown tool.")
        if proposal.args is None:
            detail = proposal.arguments_parse_error or "arguments were not valid JSON"
            return self._invalid(proposal, ToolErrorCode.INVALID_ARGUMENTS, detail)
        try:
            args = spec.args_model.model_validate(proposal.args)
        except ValidationError as exc:
            return self._invalid(proposal, ToolErrorCode.INVALID_ARGUMENTS, _summarize(exc))
        self._log.emit(SchemaValidationEvent, call_id=proposal.call_id, ok=True)

        with self._store.lock:
            request = self._build_request(proposal, spec, args.model_dump(mode="json"))
            self._log_tenant_check(request)
            blocking = self._run_gates(request)
            if blocking is not None:
                return DispatchOutcome(
                    call_id=proposal.call_id,
                    tool_name=proposal.tool_name,
                    status=DispatchStatus.DENIED,
                    payload={
                        "ok": False,
                        "error": {
                            "code": ToolErrorCode.ACTION_DENIED,
                            "message": DENIAL_MESSAGE,
                            "reason_code": blocking,
                        },
                    },
                )
            started = self._clock()
            try:
                output = spec.handler(self._store, self._context, args)
            except Exception as exc:  # defensive: a handler bug must not crash the episode
                self._log.emit(ErrorEvent, kind="tool_handler_error", message=repr(exc))
                output = error_output(ToolErrorCode.INTERNAL_ERROR, "Internal tool error.")
            self._log.emit(
                ExecutionEvent,
                call_id=proposal.call_id,
                tool_name=spec.name,
                args=request.args,
                ok=output.ok,
                error_code=output.error_code,
                state_changes=output.state_changes,
                duration_ms=(self._clock() - started) * 1000,
            )
        return DispatchOutcome(
            call_id=proposal.call_id,
            tool_name=spec.name,
            status=DispatchStatus.EXECUTED if output.ok else DispatchStatus.TOOL_ERROR,
            payload=output.payload(),
            output=output,
        )

    # ---- internals ---------------------------------------------------------------------

    def _build_request(
        self, proposal: ToolCallProposal, spec: ToolSpec, args: dict[str, Any]
    ) -> ActionRequest:
        target_ref = str(args[spec.target_arg])
        if spec.target_entity is None:  # recipient alias
            alias = self._store.alias(target_ref)
            target_exists = alias is not None
            target_tenant = alias.tenant_id if alias else None
            target_customer = None
        else:
            target_exists = self._store.get(target_ref) is not None
            target_tenant = self._store.tenant_of(target_ref)
            target_customer = self._store.customer_of(target_ref)
        return ActionRequest(
            call_id=proposal.call_id,
            agent_turn=proposal.agent_turn,
            tool_name=spec.name,
            access=spec.access,
            args=args,
            principal=self._principal,
            target_ref=target_ref,
            target_entity=spec.target_entity,
            target_exists=target_exists,
            target_tenant_id=target_tenant,
            target_customer_id=target_customer,
            mutated_field=spec.mutated_field,
        )

    def _log_tenant_check(self, request: ActionRequest) -> None:
        if not request.target_exists:
            outcome = TenantCheckOutcome.TARGET_MISSING
        elif request.target_tenant_id == request.principal.tenant_id:
            outcome = TenantCheckOutcome.MATCH
        else:
            outcome = TenantCheckOutcome.MISMATCH
        enforced = any(getattr(gate, "enforces_tenant", False) for gate in self._gates)
        self._log.emit(
            TenantCheckEvent,
            call_id=request.call_id,
            principal_tenant_id=request.principal.tenant_id,
            target_ref=request.target_ref,
            target_tenant_id=request.target_tenant_id,
            outcome=outcome,
            enforced=enforced,
        )

    def _run_gates(self, request: ActionRequest) -> str | None:
        """Return the blocking reason code, or None if every gate allowed the call."""
        blocking: str | None = None
        for gate in self._gates:
            shadow = blocking is not None
            if shadow and not getattr(gate, "shadow_after_deny", False):
                continue
            started = self._clock()
            try:
                result = gate.evaluate(request)
            except Exception as exc:  # fail closed
                self._log.emit(ErrorEvent, kind="gate_error", message=f"{gate.gate_id}: {exc!r}")
                result = GateDecision(decision=DecisionKind.DENY, reason_code="gate_error")
            if result.decision not in (DecisionKind.ALLOW, DecisionKind.DENY, DecisionKind.ABSTAIN):
                result = GateDecision(
                    decision=DecisionKind.DENY, reason_code="gate_invalid_decision"
                )
            self._log.emit(
                DecisionEvent,
                defense_id=gate.gate_id,
                decision=result.decision,
                reason_code=result.reason_code,
                call_id=request.call_id,
                scope_snapshot_hash=self._scope_hash,
                duration_ms=(self._clock() - started) * 1000,
                shadow=shadow,
                details=result.details,
            )
            if shadow:
                continue
            if result.decision is DecisionKind.DENY:
                blocking = result.reason_code
            elif result.decision is DecisionKind.ABSTAIN and request.access is not ToolAccess.READ:
                blocking = f"abstain_on_high_impact:{result.reason_code}"
        return blocking

    def _invalid(
        self, proposal: ToolCallProposal, code: ToolErrorCode, detail: str
    ) -> DispatchOutcome:
        self._log.emit(
            SchemaValidationEvent,
            call_id=proposal.call_id,
            ok=False,
            error_code=code,
            detail=detail,
        )
        return self._fail(proposal, DispatchStatus.INVALID, code, detail)

    def _fail(
        self,
        proposal: ToolCallProposal,
        status: DispatchStatus,
        code: ToolErrorCode,
        message: str,
    ) -> DispatchOutcome:
        return DispatchOutcome(
            call_id=proposal.call_id,
            tool_name=proposal.tool_name,
            status=status,
            payload={"ok": False, "error": {"code": code, "message": message}},
        )


def _summarize(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors(include_url=False, include_input=False):
        location = ".".join(str(p) for p in err["loc"]) or "arguments"
        parts.append(f"{location}: {err['msg']}")
    return "; ".join(parts)[:500]
