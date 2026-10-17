"""Trace events. Proposed, decided, executed and observed actions are kept distinct."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field

from agentshield.schemas.common import EntityType, JsonScalar, StrictModel


class StateChange(StrictModel):
    """One field-level difference between two CRM states."""

    entity: EntityType
    record_id: str
    field: str
    change: Literal["created", "updated", "deleted"]
    before: JsonScalar = None
    after: JsonScalar = None


class ToolCallProposal(StrictModel):
    """A tool call proposed by the agent model. An untrusted proposal, never a grant."""

    call_id: str
    tool_name: str
    args: dict[str, Any] | None
    raw_arguments: str | None = None
    arguments_parse_error: str | None = None
    agent_turn: Annotated[int, Field(ge=0)]


class DecisionKind(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ABSTAIN = "abstain"
    FLAG = "flag"
    QUARANTINE = "quarantine"
    ANNOTATE = "annotate"


class TenantCheckOutcome(StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"
    TARGET_MISSING = "target_missing"
    NOT_APPLICABLE = "not_applicable"


class _Event(StrictModel):
    seq: Annotated[int, Field(ge=0)]


class ScopeResolutionEvent(_Event):
    event_type: Literal["scope_resolution"] = "scope_resolution"
    scope_hash: str
    resolution: str
    matched_rules: tuple[str, ...]
    failure_reason: str | None = None


class ModelCallEvent(_Event):
    event_type: Literal["model_call"] = "model_call"
    agent_turn: int
    model_id: str
    provider_kind: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    usage_estimated: bool = False
    latency_ms: float
    finish_reason: str | None = None
    raw_response_id: str | None = None
    n_tool_calls: int = 0
    error_kind: str | None = None
    error_message: str | None = None
    attempt: int = 1
    waited_s: float = 0.0
    reasoning_chars_removed: int = 0
    rate_limit_headers: dict[str, str] = Field(default_factory=dict)


class ProposalEvent(_Event):
    event_type: Literal["proposal"] = "proposal"
    proposal: ToolCallProposal


class SchemaValidationEvent(_Event):
    event_type: Literal["schema_validation"] = "schema_validation"
    call_id: str
    ok: bool
    error_code: str | None = None
    detail: str | None = None


class TenantCheckEvent(_Event):
    """Tenant confinement observation, logged separately from schema validation and policy.

    `enforced` is False unless a defense (D5) acted on it; the baseline only observes.
    """

    event_type: Literal["tenant_check"] = "tenant_check"
    call_id: str
    principal_tenant_id: str
    target_ref: str | None
    target_tenant_id: str | None
    outcome: TenantCheckOutcome
    enforced: bool = False


class DecisionEvent(_Event):
    event_type: Literal["decision"] = "decision"
    defense_id: str
    decision: DecisionKind
    reason_code: str
    call_id: str | None = None
    scope_snapshot_hash: str | None = None
    duration_ms: float = 0.0
    shadow: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ExecutionEvent(_Event):
    """A tool call that actually ran against the sandbox (successfully or with a tool error)."""

    event_type: Literal["execution"] = "execution"
    call_id: str
    tool_name: str
    args: dict[str, Any]
    ok: bool
    error_code: str | None = None
    state_changes: tuple[StateChange, ...] = ()
    duration_ms: float = 0.0


class ToolResultEvent(_Event):
    """Exactly what the agent was shown for a call, after any injection/D2/D3 transforms."""

    event_type: Literal["tool_result"] = "tool_result"
    call_id: str
    content: str
    content_sha256: str
    transforms: tuple[str, ...] = ()
    injection_applied: bool = False


class FinalAnswerEvent(_Event):
    event_type: Literal["final_answer"] = "final_answer"
    text: str


class ErrorEvent(_Event):
    event_type: Literal["error"] = "error"
    kind: str
    message: str


TraceEvent = Annotated[
    ScopeResolutionEvent
    | ModelCallEvent
    | ProposalEvent
    | SchemaValidationEvent
    | TenantCheckEvent
    | DecisionEvent
    | ExecutionEvent
    | ToolResultEvent
    | FinalAnswerEvent
    | ErrorEvent,
    Field(discriminator="event_type"),
]


class EventLog:
    """Append-only, sequence-numbered event log shared by the runtime and the dispatcher."""

    def __init__(self) -> None:
        self._events: list[TraceEvent] = []

    def emit[E: _Event](self, event_cls: type[E], **fields: Any) -> E:
        event = event_cls(seq=len(self._events), **fields)
        self._events.append(event)  # type: ignore[arg-type]
        return event

    @property
    def events(self) -> tuple[TraceEvent, ...]:
        return tuple(self._events)

    def of_type[E: _Event](self, event_cls: type[E]) -> list[E]:
        return [event for event in self._events if isinstance(event, event_cls)]

    def __len__(self) -> int:
        return len(self._events)
