"""Benchmark runner (Phase 2 scope: baseline configuration, clean scenarios).

For each (scenario, config, repetition): a fresh CRM store from the immutable fixture, the
trusted task scope from the verbatim request, hooks for the configuration, one agent episode,
and an `EpisodeResult` appended to `episodes.jsonl`. The runner sees the public scenario
(including its category) but passes only the request, principal and hooks to the runtime.

Phase-2 guard rails: configurations enabling D1-D6 and scenarios carrying an injection are
rejected (defenses and the injector arrive in Phases 3-4), so nothing is silently run
without the component its label promises.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from agentshield.agent.runtime import AgentRuntime, EpisodeHooks, EpisodeTrace
from agentshield.auth.principals import PrincipalDirectory
from agentshield.auth.scope_resolver import resolve_task_scope
from agentshield.benchmark.artifacts import RunWriter, episode_key
from agentshield.config import RuntimeLimits
from agentshield.crm.fixtures import CRMFixture
from agentshield.crm.store import CRMStore
from agentshield.llm.prompts import render_base_prompt
from agentshield.llm.protocol import LLMClient
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
from agentshield.schemas.llm import GenerationConfig, Usage
from agentshield.schemas.scenario import ScenarioPublic


class UnsupportedInPhaseError(ValueError):
    pass


def check_supported(scenarios: Sequence[ScenarioPublic], configs: Sequence[DefenseConfig]) -> None:
    for config in configs:
        if config.enabled or config.is_oracle:
            raise UnsupportedInPhaseError(
                f"{config.id} enables {config.label}; defense modules are implemented in "
                "Phases 3-4. Only baseline configurations (e.g. C00, M00) can run now."
            )
    for scenario in scenarios:
        if scenario.injection is not None:
            raise UnsupportedInPhaseError(
                f"{scenario.scenario_id} carries an injection; the injector is implemented in "
                "Phase 3. Select scenarios without injections (clean)."
            )


def build_hooks(
    config: DefenseConfig,
    scenario: ScenarioPublic,
    fixture: CRMFixture,
    directory: PrincipalDirectory,
) -> EpisodeHooks:
    principal = directory.get(scenario.principal_id)
    return EpisodeHooks(
        system_prompt=render_base_prompt(principal, fixture.as_of_date),
        scope=resolve_task_scope(scenario.user_request),
    )


class RunSummary(StrictModel):
    run_id: str
    episodes: int
    statuses: dict[str, int]
    usage: Usage
    aborted: str | None = None
    skipped: int = 0  # episodes already completed in a resumed run


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


def new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"


def to_episode_result(
    ctx: RunContext,
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
        model_id=",".join(trace.served_model_ids) or ctx.client.model_id,
        provider_kind=ctx.client.provider_kind.value,
        repetition=repetition,
        seed=ctx.generation.seed,
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
        },
    )


def run_episodes(
    ctx: RunContext,
    scenarios: Sequence[ScenarioPublic],
    configs: Sequence[DefenseConfig],
    repeats: int,
    writer: RunWriter,
    on_episode: Callable[[str, EpisodeResult], None] | None = None,
) -> RunSummary:
    check_supported(scenarios, configs)
    statuses: Counter[str] = Counter()
    usage = Usage(requests=0)
    episodes = 0
    runtime = AgentRuntime(ctx.client, ctx.controller, ctx.generation, ctx.limits)
    for scenario in scenarios:
        for config in configs:
            for repetition in range(repeats):
                key = episode_key(scenario.scenario_id, config.id, repetition)
                if key in writer.completed_keys:  # --resume: already completed earlier
                    continue
                hooks = build_hooks(config, scenario, ctx.fixture, ctx.principals)
                store = CRMStore.from_fixture(ctx.fixture)  # fresh state every episode
                trace = runtime.run(
                    user_request=scenario.user_request,
                    principal=ctx.principals.get(scenario.principal_id),
                    store=store,
                    hooks=hooks,
                    max_turns=scenario.max_turns,
                )
                result = to_episode_result(ctx, scenario, config, repetition, trace, hooks)
                if trace.abort_run:
                    # Cut short by a run-level stop: audit copy only, re-run on --resume.
                    writer.write_aborted(key, result, trace)
                    return RunSummary(
                        run_id=ctx.run_id,
                        episodes=episodes,
                        statuses=dict(statuses),
                        usage=usage + result.usage,
                        aborted="; ".join(trace.errors) or "aborted",
                        skipped=len(writer.completed_keys),
                    )
                writer.write_episode(key, result, trace)
                episodes += 1
                statuses[result.status.value] += 1
                usage = usage + result.usage
                if on_episode:
                    on_episode(key, result)
    return RunSummary(
        run_id=ctx.run_id,
        episodes=episodes,
        statuses=dict(statuses),
        usage=usage,
        skipped=len(writer.completed_keys),
    )
