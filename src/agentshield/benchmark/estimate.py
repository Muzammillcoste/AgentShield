"""Pre-run usage estimates (requests, tokens, paid-equivalent cost, free-tier fit).

Method: each scenario is dry-run offline with the heuristic fake agent through the real
runtime, which yields a plausible call path and per-call prompt sizes (characters / 4).
Each call is charged an assumed output size, and the total is multiplied by a safety
factor. An upper bound assumes every episode uses all agent steps with the largest observed
prompt. Estimates are rough planning numbers; recorded usage always comes from the provider.
"""

from __future__ import annotations

from collections.abc import Sequence

from agentshield.agent.runtime import AgentRuntime, EpisodeHooks
from agentshield.auth.principals import PrincipalDirectory
from agentshield.config import BudgetLimits, DocumentedRateLimits, ModelPrice, RuntimeLimits
from agentshield.crm.fixtures import CRMFixture
from agentshield.crm.store import CRMStore
from agentshield.llm.fake_agent import HeuristicFakeAgent
from agentshield.llm.prompts import render_base_prompt
from agentshield.llm.resilience import CallController
from agentshield.schemas.common import StrictModel
from agentshield.schemas.events import ModelCallEvent
from agentshield.schemas.experiment import DefenseConfig
from agentshield.schemas.llm import GenerationConfig
from agentshield.schemas.scenario import ScenarioPublic


class RunEstimate(StrictModel):
    episodes: int
    model_calls: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    upper_bound_total_tokens: int
    paid_equivalent_usd: float | None
    minutes_at_documented_tpm: float | None
    days_at_documented_tpd: float | None
    assumptions: tuple[str, ...]


def estimate_run(
    scenarios: Sequence[ScenarioPublic],
    configs: Sequence[DefenseConfig],
    repeats: int,
    *,
    fixture: CRMFixture,
    principals: PrincipalDirectory,
    generation: GenerationConfig,
    limits: RuntimeLimits,
    output_tokens_per_call: int = 150,
    safety_factor: float = 1.3,
    price: ModelPrice | None = None,
    documented: DocumentedRateLimits | None = None,
) -> RunEstimate:
    runtime = AgentRuntime(
        HeuristicFakeAgent(),
        CallController(budget=None),
        generation,
        limits,
    )
    calls = 0
    input_tokens = 0
    largest_prompt = 0
    for scenario in scenarios:
        principal = principals.get(scenario.principal_id)
        trace = runtime.run(
            user_request=scenario.user_request,
            principal=principal,
            store=CRMStore.from_fixture(fixture),
            hooks=EpisodeHooks(system_prompt=render_base_prompt(principal, fixture.as_of_date)),
            max_turns=scenario.max_turns,
        )
        for event in trace.events:
            if isinstance(event, ModelCallEvent):
                calls += 1
                prompt = event.input_tokens or 0
                input_tokens += prompt
                largest_prompt = max(largest_prompt, prompt)

    multiplier = len(configs) * repeats
    episodes = len(scenarios) * multiplier
    est_calls = calls * multiplier
    est_input = int(input_tokens * multiplier * safety_factor)
    est_output = int(est_calls * output_tokens_per_call * safety_factor)
    total = est_input + est_output
    upper = episodes * limits.max_agent_steps * (largest_prompt + generation.max_output_tokens)
    usd = None
    if price is not None:
        usd = (est_input * price.input_usd_per_mtok + est_output * price.output_usd_per_mtok) / 1e6
    tpm = documented.tpm if documented else None
    tpd = documented.tpd if documented else None
    return RunEstimate(
        episodes=episodes,
        model_calls=est_calls,
        input_tokens=est_input,
        output_tokens=est_output,
        total_tokens=total,
        upper_bound_total_tokens=upper,
        paid_equivalent_usd=usd,
        minutes_at_documented_tpm=total / tpm if tpm else None,
        days_at_documented_tpd=total / tpd if tpd else None,
        assumptions=(
            "call path from an offline heuristic dry run (real models may take more/fewer steps)",
            "tokens ~= characters / 4 (provider tokenizers differ)",
            f"{output_tokens_per_call} output tokens per call; safety factor {safety_factor}",
            "baseline prompt only (D1 text and D6 verifier calls not yet included)",
            "documented rate limits are planning figures; response headers are authoritative",
        ),
    )


def budget_for_estimate(estimate: RunEstimate, headroom: float = 1.5) -> BudgetLimits:
    """A default hard cap derived from an estimate (used when the user gives none)."""
    return BudgetLimits(
        max_total_tokens=int(estimate.total_tokens * headroom) + 2000,
        max_requests=int(estimate.model_calls * headroom) + 4,
    )
