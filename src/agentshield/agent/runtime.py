"""The controlled agent loop: model proposals -> central dispatcher -> observations -> model.

The runtime receives only what an agent legitimately has: the verbatim user request, the
authenticated principal, a per-episode CRM store and the configured hooks (system prompt,
visible tools, action gates, observation pipeline, trusted scope). It never receives scenario
labels or private ground truth. Every model attempt, proposal, decision, execution and
observation is recorded in an append-only event log.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agentshield.agent.observation import (
    JsonObservationSerializer,
    ObservationContext,
    ObservationSerializer,
    PayloadTransformer,
    isolated_copy,
)
from agentshield.auth.scope_resolver import TaskScope
from agentshield.config import RuntimeLimits
from agentshield.crm.dispatcher import ActionGate, DispatchOutcome, DispatchStatus, ToolDispatcher
from agentshield.crm.store import CRMStore, diff_states
from agentshield.crm.tools import TOOL_NAMES, tool_schemas
from agentshield.hashing import sha256_text, stable_hash
from agentshield.llm.protocol import LLMClient, LLMError, LLMErrorKind
from agentshield.llm.resilience import AttemptRecord, CallController
from agentshield.schemas.common import StrictModel
from agentshield.schemas.domain import Principal
from agentshield.schemas.events import (
    EventLog,
    FinalAnswerEvent,
    ModelCallEvent,
    ProposalEvent,
    ScopeResolutionEvent,
    StateChange,
    ToolCallProposal,
    ToolResultEvent,
    TraceEvent,
)
from agentshield.schemas.experiment import EpisodeStatus
from agentshield.schemas.llm import (
    ChatMessage,
    FinishReason,
    GenerationConfig,
    MessageRole,
    ModelToolCall,
    Usage,
)

# Errors after which continuing the run is pointless or unsafe (stop the whole run).
_ABORT_KINDS = {LLMErrorKind.BUDGET_EXCEEDED, LLMErrorKind.AUTH, LLMErrorKind.CONFIGURATION}

_STATUS_FOR_ERROR = {
    LLMErrorKind.TIMEOUT: EpisodeStatus.TIMEOUT,
    LLMErrorKind.RESPONSE_PARSE: EpisodeStatus.PARSE_ERROR,
    LLMErrorKind.BUDGET_EXCEEDED: EpisodeStatus.INFRASTRUCTURE_ERROR,
    LLMErrorKind.CONFIGURATION: EpisodeStatus.INFRASTRUCTURE_ERROR,
}


@dataclass(frozen=True)
class EpisodeHooks:
    """Per-configuration plumbing. Phase 2 baseline: base prompt, all tools, no gates."""

    system_prompt: str
    visible_tools: tuple[str, ...] = TOOL_NAMES
    gates: tuple[ActionGate, ...] = ()
    transformers: tuple[PayloadTransformer, ...] = ()
    serializer: ObservationSerializer = field(default_factory=JsonObservationSerializer)
    scope: TaskScope | None = None


class EpisodeTrace(StrictModel):
    status: EpisodeStatus
    final_answer: str | None
    errors: tuple[str, ...]
    abort_run: bool
    events: tuple[TraceEvent, ...]
    messages: tuple[ChatMessage, ...]
    usage: Usage
    model_calls: int
    served_model_ids: tuple[str, ...]
    initial_state_hash: str
    final_state_hash: str
    state_diff: tuple[StateChange, ...]
    system_prompt_sha256: str
    tool_schema_sha256: str
    started_at: datetime
    ended_at: datetime
    duration_ms: float


class AgentRuntime:
    def __init__(
        self,
        client: LLMClient,
        controller: CallController,
        generation: GenerationConfig,
        limits: RuntimeLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._client = client
        self._controller = controller
        self._generation = generation
        self._limits = limits
        self._clock = clock
        self._now = now

    def run(
        self,
        *,
        user_request: str,
        principal: Principal,
        store: CRMStore,
        hooks: EpisodeHooks,
        max_turns: int | None = None,
    ) -> EpisodeTrace:
        log = EventLog()
        started_at, started = self._now(), self._clock()
        initial = store.snapshot()
        scope_hash = hooks.scope.scope_hash() if hooks.scope else None
        if hooks.scope is not None:
            log.emit(
                ScopeResolutionEvent,
                scope_hash=scope_hash,
                resolution=hooks.scope.resolution.value,
                matched_rules=hooks.scope.matched_rules,
                failure_reason=hooks.scope.failure_reason,
            )
        dispatcher = ToolDispatcher(
            store,
            principal,
            log,
            hooks.gates,
            max_tool_calls=self._limits.max_tool_calls,
            scope_hash=scope_hash,
        )
        tools = tool_schemas(hooks.visible_tools)
        messages = [
            ChatMessage(role=MessageRole.SYSTEM, content=hooks.system_prompt),
            ChatMessage(role=MessageRole.USER, content=user_request),
        ]
        usage = Usage(requests=0)
        served: list[str] = []
        errors: list[str] = []
        final_answer: str | None = None
        status: EpisodeStatus | None = None
        abort_run = False
        model_calls = 0
        seen_call_ids: set[str] = set()
        turns = min(max_turns or self._limits.max_agent_steps, self._limits.max_agent_steps)

        for turn in range(turns):
            if self._clock() - started > self._limits.episode_timeout_s:
                status = EpisodeStatus.TIMEOUT
                errors.append("episode wall-clock timeout")
                break
            try:
                response = self._controller.call(
                    self._client,
                    messages,
                    tools,
                    self._generation,
                    on_attempt=functools.partial(self._log_attempt, log, turn),
                )
            except LLMError as exc:
                status = _STATUS_FOR_ERROR.get(exc.kind, EpisodeStatus.API_ERROR)
                errors.append(f"{exc.kind.value}: {exc.message}")
                abort_run = exc.kind in _ABORT_KINDS or (
                    exc.kind is LLMErrorKind.RATE_LIMIT and not exc.retryable
                )
                break

            model_calls += 1
            usage = usage + response.usage
            served.append(response.model_id)
            messages.append(
                ChatMessage(
                    role=MessageRole.ASSISTANT,
                    content=response.assistant_text,
                    tool_calls=response.tool_calls,
                )
            )
            if not response.tool_calls:
                final_answer = response.assistant_text or ""
                log.emit(FinalAnswerEvent, text=final_answer)
                if response.finish_reason is FinishReason.CONTENT_FILTER:
                    status = EpisodeStatus.API_ERROR
                    errors.append("provider content filter stopped the response")
                else:
                    status = EpisodeStatus.COMPLETED
                if response.finish_reason is FinishReason.LENGTH:
                    errors.append("final answer truncated at max_output_tokens")
                break

            limit_hit = False
            for call in response.tool_calls:
                outcome, content = self._handle_call(
                    call, turn, dispatcher, hooks, log, seen_call_ids
                )
                limit_hit = limit_hit or outcome.status is DispatchStatus.LIMIT_EXCEEDED
                messages.append(
                    ChatMessage(role=MessageRole.TOOL, content=content, tool_call_id=call.id)
                )
            if limit_hit:
                status = EpisodeStatus.MAX_STEPS
                errors.append("tool call limit reached")
                break

        if status is None:
            status = EpisodeStatus.MAX_STEPS
            errors.append("max agent steps reached without a final answer")

        final = store.snapshot()
        return EpisodeTrace(
            status=status,
            final_answer=final_answer,
            errors=tuple(errors),
            abort_run=abort_run,
            events=log.events,
            messages=tuple(messages),
            usage=usage,
            model_calls=model_calls,
            served_model_ids=tuple(dict.fromkeys(served)),
            initial_state_hash=initial.state_hash(),
            final_state_hash=final.state_hash(),
            state_diff=diff_states(initial, final),
            system_prompt_sha256=sha256_text(hooks.system_prompt),
            tool_schema_sha256=stable_hash([t.model_dump() for t in tools]),
            started_at=started_at,
            ended_at=self._now(),
            duration_ms=(self._clock() - started) * 1000,
        )

    # ---- internals ---------------------------------------------------------------------

    def _handle_call(
        self,
        call: ModelToolCall,
        turn: int,
        dispatcher: ToolDispatcher,
        hooks: EpisodeHooks,
        log: EventLog,
        seen_call_ids: set[str],
    ) -> tuple[DispatchOutcome, str]:
        # Provider call ids are echoed back to the model unchanged, but trace ids must be
        # unique within the episode even if a model reuses an id.
        trace_id = call.id if call.id not in seen_call_ids else f"{call.id}#t{turn}"
        seen_call_ids.add(trace_id)
        proposal = ToolCallProposal(
            call_id=trace_id,
            tool_name=call.name,
            args=call.arguments,
            raw_arguments=call.arguments_json,
            arguments_parse_error=call.parse_error,
            agent_turn=turn,
        )
        outcome = dispatcher.dispatch(proposal)
        context = ObservationContext(
            call_id=trace_id,
            tool_name=call.name,
            args=call.arguments or {},
            ok=outcome.payload.get("ok") is True,
            exposed_records=outcome.output.exposed_records if outcome.output else (),
        )
        payload = isolated_copy(outcome.payload)
        applied: list[str] = []
        injected = False
        for transformer in hooks.transformers:
            result = transformer.transform(context, payload)
            payload = result.payload
            if result.applied:
                applied.append(transformer.name)
                injected = injected or bool(getattr(transformer, "is_attack", False))
        content = hooks.serializer.serialize(context, payload)
        log.emit(
            ToolResultEvent,
            call_id=trace_id,
            content=content,
            content_sha256=sha256_text(content),
            transforms=(*applied, hooks.serializer.name),
            injection_applied=injected,
        )
        return outcome, content

    def _log_attempt(self, log: EventLog, turn: int, record: AttemptRecord) -> None:
        response = record.response
        log.emit(
            ModelCallEvent,
            agent_turn=turn,
            model_id=response.model_id if response else self._client.model_id,
            provider_kind=self._client.provider_kind.value,
            input_tokens=response.usage.input_tokens if response else None,
            output_tokens=response.usage.output_tokens if response else None,
            usage_estimated=response.usage.estimated if response else False,
            latency_ms=record.latency_ms,
            finish_reason=response.finish_reason.value if response else None,
            raw_response_id=response.raw_response_id if response else None,
            n_tool_calls=len(response.tool_calls) if response else 0,
            error_kind=record.error_kind.value if record.error_kind else None,
            error_message=record.error_message,
            attempt=record.attempt,
            waited_s=record.waited_s,
            reasoning_chars_removed=response.reasoning_chars_removed if response else 0,
            rate_limit_headers=response.rate_limit_headers if response else {},
        )


def proposals_of(events: Sequence[TraceEvent]) -> list[ToolCallProposal]:
    return [e.proposal for e in events if isinstance(e, ProposalEvent)]
