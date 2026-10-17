"""Benchmark runner: scenarios x configurations x repetitions -> episodes.jsonl.

For each episode: a fresh CRM store from the immutable fixture, the trusted task scope (or,
for ORACLE UPPER BOUND configs only, a scope built from private labels), hooks for the
configuration (D1 prompt, injector -> D2 -> D3/JSON serializer, D4/D5/D6 gates), one agent
episode, and an `EpisodeResult`. The runner sees the public scenario (including its category)
but passes only the request, principal and hooks to the runtime.

Model fallback (owner decision, D-040): episodes are grouped into *scenario blocks* (all
configurations and repetitions of one scenario). A block is always run with a single model.
If the primary model's quota runs out inside a block, the block's partial episodes are moved to
the audit log and the whole block is re-run on the fallback model, which then serves the rest
of the run. Every episode records its model; analysis stratifies by model.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from agentshield.agent.observation import (
    JsonObservationSerializer,
    ObservationSerializer,
    PayloadTransformer,
)
from agentshield.agent.runtime import AgentRuntime, EpisodeHooks, EpisodeTrace
from agentshield.auth.principals import PrincipalDirectory
from agentshield.auth.scope_resolver import TaskScope, resolve_task_scope
from agentshield.benchmark.artifacts import RunWriter, episode_key
from agentshield.config import RuntimeLimits
from agentshield.crm.dispatcher import ActionGate
from agentshield.crm.fixtures import CRMFixture
from agentshield.crm.store import CRMStore
from agentshield.crm.tools import TOOL_NAMES
from agentshield.defenses.d1_system_prompt import apply_d1
from agentshield.defenses.d2_inspector import ToolOutputInspector
from agentshield.defenses.d3_provenance import ProvenanceSerializer
from agentshield.defenses.d4_allowlist import ToolAllowlistGate, visible_tools
from agentshield.defenses.d5_policy import PolicyGate
from agentshield.defenses.d6_action_verifier import ActionVerifierGate
from agentshield.injection.injector import TextOverrideInjector
from agentshield.llm.fake_verifier import HeuristicFakeVerifier
from agentshield.llm.prompts import render_base_prompt
from agentshield.llm.protocol import LLMClient, LLMErrorKind
from agentshield.llm.resilience import CallController
from agentshield.schemas.common import StrictModel
from agentshield.schemas.events import (
    DecisionEvent,
    ExecutionEvent,
    ProposalEvent,
    SchemaValidationEvent,
    TenantCheckEvent,
)
from agentshield.schemas.experiment import DefenseConfig, EpisodeResult
from agentshield.schemas.llm import GenerationConfig, ProviderKind, Usage
from agentshield.schemas.scenario import ScenarioPublic


class UnsupportedInPhaseError(ValueError):
    pass


@dataclass
class ModelSlot:
    """One model's client, call controller (budget + rate limits) and sampling settings."""

    label: str
    client: LLMClient
    controller: CallController
    generation: GenerationConfig


@dataclass
class RunContext:
    run_id: str
    fixture: CRMFixture
    principals: PrincipalDirectory
    client: LLMClient
    controller: CallController
    generation: GenerationConfig
    limits: RuntimeLimits
    dataset_version: str
    fallback: ModelSlot | None = None
    oracle_scopes: Mapping[str, TaskScope] = field(default_factory=dict)

    @property
    def primary(self) -> ModelSlot:
        return ModelSlot("primary", self.client, self.controller, self.generation)


class RunSummary(StrictModel):
    run_id: str
    episodes: int
    statuses: dict[str, int]
    usage: Usage
    aborted: str | None = None
    skipped: int = 0  # episodes already completed in a resumed run
    model_switch: dict[str, Any] | None = None
    episodes_by_model: dict[str, int] = Field(default_factory=dict)


def check_supported(
    scenarios: Sequence[ScenarioPublic],
    configs: Sequence[DefenseConfig],
    oracle_scopes: Mapping[str, TaskScope] | None = None,
) -> None:
    for config in configs:
        if config.d6_settings is not None and config.d6_settings.provider == "real":
            raise UnsupportedInPhaseError(
                f"{config.id}: a separately configured real verifier model is not supported; "
                "use provider 'same_as_agent' or 'fake'."
            )
        if config.is_oracle:
            known = oracle_scopes or {}
            missing = [s.scenario_id for s in scenarios if s.scenario_id not in known]
            if missing:
                raise UnsupportedInPhaseError(
                    f"{config.id} (ORACLE UPPER BOUND) needs private truth for {missing[:5]}"
                )


def verifier_client_for(config: DefenseConfig, agent_client: LLMClient) -> LLMClient:
    settings = config.d6_settings
    if settings is None:
        raise ValueError("D6 is not enabled")
    if settings.provider == "fake" or agent_client.provider_kind is ProviderKind.FAKE:
        return HeuristicFakeVerifier()
    return agent_client  # same_as_agent


def build_hooks(
    config: DefenseConfig,
    scenario: ScenarioPublic,
    fixture: CRMFixture,
    directory: PrincipalDirectory,
    *,
    store: CRMStore,
    slot: ModelSlot,
    oracle_scopes: Mapping[str, TaskScope] | None = None,
) -> EpisodeHooks:
    """Assemble one episode's plumbing. Only the injector sees the scenario's injection spec;
    defenses are built from the configuration, the trusted request and trusted lookups."""
    principal = directory.get(scenario.principal_id)
    if config.is_oracle:
        scope = (oracle_scopes or {})[scenario.scenario_id]
    else:
        scope = resolve_task_scope(scenario.user_request)

    prompt = render_base_prompt(principal, fixture.as_of_date)
    if config.d1:
        prompt = apply_d1(prompt)
    transformers: list[PayloadTransformer] = []
    if scenario.injection is not None:  # attacker text enters before any defense sees it
        transformers.append(TextOverrideInjector(scenario.injection))
    if config.d2:
        transformers.append(ToolOutputInspector(config.d2_mode))
    serializer: ObservationSerializer = (
        ProvenanceSerializer() if config.d3 else JsonObservationSerializer()
    )
    gates: list[ActionGate] = []  # order matters: deny precedence, D6 never overrides D5
    if config.d4:
        gates.append(ToolAllowlistGate(scope))
    if config.d5:
        assert config.d5_granularity is not None
        gates.append(PolicyGate(scope, config.d5_granularity, store))
    if config.d6:
        assert config.d6_settings is not None
        gates.append(
            ActionVerifierGate(
                verifier_client_for(config, slot.client),
                slot.controller,
                config.d6_settings,
                user_request=scenario.user_request,
                principal=principal,
                scope=scope,
            )
        )
    return EpisodeHooks(
        system_prompt=prompt,
        visible_tools=visible_tools(scope) if config.d4 else TOOL_NAMES,
        gates=tuple(gates),
        transformers=tuple(transformers),
        serializer=serializer,
        scope=scope,
    )


def new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"


def to_episode_result(
    ctx: RunContext,
    slot: ModelSlot,
    scenario: ScenarioPublic,
    config: DefenseConfig,
    repetition: int,
    trace: EpisodeTrace,
    hooks: EpisodeHooks,
) -> EpisodeResult:
    events = trace.events
    return EpisodeResult(
        run_id=ctx.run_id,
        scenario_id=scenario.scenario_id,
        config_id=config.id,
        config_hash=config.config_hash(),
        model_id=",".join(trace.served_model_ids) or slot.client.model_id,
        provider_kind=slot.client.provider_kind.value,
        repetition=repetition,
        seed=slot.generation.seed,
        dataset_version=ctx.dataset_version,
        start_time=trace.started_at,
        end_time=trace.ended_at,
        final_answer=trace.final_answer,
        proposed_calls=tuple(e.proposal for e in events if isinstance(e, ProposalEvent)),
        decisions=tuple(
            e
            for e in events
            if isinstance(e, DecisionEvent | SchemaValidationEvent | TenantCheckEvent)
        ),
        executed_calls=tuple(e for e in events if isinstance(e, ExecutionEvent)),
        state_diff=trace.state_diff,
        trace=events,
        usage=trace.usage,
        status=trace.status,
        errors=trace.errors,
        artifact_hashes={
            "system_prompt_sha256": trace.system_prompt_sha256,
            "tool_schema_sha256": trace.tool_schema_sha256,
            "initial_state_hash": trace.initial_state_hash,
            "final_state_hash": trace.final_state_hash,
            "fixture_hash": ctx.fixture.fixture_hash(),
            "scope_hash": hooks.scope.scope_hash() if hooks.scope else "",
            "model_slot": slot.label,
        },
    )


Pending = tuple[str, DefenseConfig, int]
Done = tuple[str, EpisodeResult, EpisodeTrace]


def run_episodes(
    ctx: RunContext,
    scenarios: Sequence[ScenarioPublic],
    configs: Sequence[DefenseConfig],
    repeats: int,
    writer: RunWriter,
    on_episode: Callable[[str, EpisodeResult], None] | None = None,
) -> RunSummary:
    check_supported(scenarios, configs, ctx.oracle_scopes)
    statuses: Counter[str] = Counter()
    by_model: Counter[str] = Counter()
    usage = Usage(requests=0)
    episodes = 0
    slot = ctx.primary
    switch: dict[str, Any] | None = None

    def flush(done: list[Done]) -> None:
        nonlocal episodes, usage
        for key, result, trace in done:
            writer.write_episode(key, result, trace)
            episodes += 1
            statuses[result.status.value] += 1
            by_model[result.model_id] += 1
            usage = usage + result.usage
            if on_episode:
                on_episode(key, result)

    def summary(aborted: str | None = None) -> RunSummary:
        return RunSummary(
            run_id=ctx.run_id,
            episodes=episodes,
            statuses=dict(statuses),
            usage=usage,
            aborted=aborted,
            skipped=len(writer.completed_keys),
            model_switch=switch,
            episodes_by_model=dict(by_model),
        )

    for scenario in scenarios:
        pending: list[Pending] = [
            (episode_key(scenario.scenario_id, config.id, rep), config, rep)
            for config in configs
            for rep in range(repeats)
        ]
        pending = [p for p in pending if p[0] not in writer.completed_keys]
        while pending:
            runtime = AgentRuntime(slot.client, slot.controller, slot.generation, ctx.limits)
            done: list[Done] = []
            stopped: Done | None = None
            for key, config, rep in pending:
                store = CRMStore.from_fixture(ctx.fixture)  # fresh state every episode
                hooks = build_hooks(
                    config,
                    scenario,
                    ctx.fixture,
                    ctx.principals,
                    store=store,
                    slot=slot,
                    oracle_scopes=ctx.oracle_scopes,
                )
                trace = runtime.run(
                    user_request=scenario.user_request,
                    principal=ctx.principals.get(scenario.principal_id),
                    store=store,
                    hooks=hooks,
                    max_turns=scenario.max_turns,
                )
                result = to_episode_result(ctx, slot, scenario, config, rep, trace, hooks)
                if trace.abort_run:
                    stopped = (key, result, trace)
                    break
                done.append((key, result, trace))
            if stopped is None:
                flush(done)
                break

            key, result, trace = stopped
            quota = trace.abort_kind == LLMErrorKind.RATE_LIMIT.value
            if quota and ctx.fallback is not None and slot.label == "primary":
                # Keep the block single-model: archive the partial block, redo it on fallback.
                for partial in (*done, stopped):
                    writer.write_aborted(*partial)
                switch = {
                    "at_scenario": scenario.scenario_id,
                    "from_model": ctx.client.model_id,
                    "to_model": ctx.fallback.client.model_id,
                    "reason": "; ".join(trace.errors),
                    "at": datetime.now(UTC).isoformat(),
                }
                slot = ctx.fallback
                continue
            flush(done)  # completed episodes stay valid; resume continues with the same model
            writer.write_aborted(key, result, trace)
            return summary("; ".join(trace.errors) or "aborted")
    return summary()
