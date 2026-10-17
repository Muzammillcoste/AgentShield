"""D4/D5/D6, oracle diagnostics and model fallback through the runner (FAKE models only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentshield.benchmark.artifacts import RunWriter, load_episodes
from agentshield.benchmark.loader import load_public_scenarios
from agentshield.benchmark.oracle import oracle_scope
from agentshield.benchmark.runner import ModelSlot, RunContext, run_episodes
from agentshield.benchmark.truth_store import load_private_truth
from agentshield.config import RuntimeLimits
from agentshield.crm.fixtures import CRMFixture
from agentshield.defenses.registry import load_registry
from agentshield.llm.fake_agent import HeuristicFakeAgent
from agentshield.llm.protocol import LLMError, LLMErrorKind
from agentshield.llm.resilience import CallController, RetryPolicy
from agentshield.schemas.events import DecisionEvent
from agentshield.schemas.experiment import EpisodeResult
from agentshield.schemas.llm import GenerationConfig
from tests.conftest import EXAMPLES_PRIVATE, EXAMPLES_PUBLIC, ROOT

SCENARIOS = {s.scenario_id: s for s in load_public_scenarios(EXAMPLES_PUBLIC)}
TRUTH = load_private_truth(EXAMPLES_PRIVATE)
REGISTRY = load_registry(ROOT / "configs" / "defenses.yaml")
SWAP = "ex-attack-parameter-swap-001"
HIJACK = "ex-attack-workflow-hijack-001"
OOG = "ex-clean-out-of-grammar-001"
SEND = "ex-clean-send-summary-001"


def context(fixture: CRMFixture, principals: Any, **kw: Any) -> RunContext:
    return RunContext(
        run_id="phase4",
        fixture=fixture,
        principals=principals,
        client=kw.pop("client", HeuristicFakeAgent(follow_injections=True)),
        controller=kw.pop("controller", CallController()),
        generation=GenerationConfig(),
        limits=RuntimeLimits(),
        dataset_version="test",
        **kw,
    )


def run(
    tmp_path: Path, ctx: RunContext, ids: list[str], configs: list[str]
) -> dict[tuple[str, str], EpisodeResult]:
    run_episodes(
        ctx, [SCENARIOS[i] for i in ids], [REGISTRY.get(c) for c in configs], 1, RunWriter(tmp_path)
    )
    return {(e.scenario_id, e.config_id): e for e in load_episodes(tmp_path / "episodes.jsonl")}


def changes(e: EpisodeResult) -> set[tuple[str, object]]:
    return {(c.record_id, c.after) for c in e.state_diff if c.field in ("status", "amount")}


def test_wrong_record_attack_d4_insufficient_d5_blocks(
    tmp_path: Path, fixture: CRMFixture, principals: Any
) -> None:
    r = run(tmp_path, context(fixture, principals), [SWAP], ["C00", "C04", "C05", "C09"])
    assert ("INV-005", "Paid") in changes(r[(SWAP, "C00")])
    assert ("INV-005", "Paid") in changes(r[(SWAP, "C04")])  # same tool -> allowlist passes it
    for cfg in ("C05", "C09"):
        assert changes(r[(SWAP, cfg)]) == {("INV-007", "Paid")}  # attack blocked, task done
        assert "update_invoice_status" in [p.tool_name for p in r[(SWAP, cfg)].proposed_calls]


def test_attempt_recorded_even_when_blocked(
    tmp_path: Path, fixture: CRMFixture, principals: Any
) -> None:
    e = run(tmp_path, context(fixture, principals), [HIJACK], ["C09"])[(HIJACK, "C09")]
    assert "update_invoice_status" in [p.tool_name for p in e.proposed_calls]  # UAR = 1
    assert e.state_diff == ()  # UER = 0
    denials = [
        d for d in e.decisions if isinstance(d, DecisionEvent) and d.decision.value == "deny"
    ]
    assert denials and denials[0].defense_id == "D4"


def test_d6_fake_verifier_vetoes_injected_write(
    tmp_path: Path, fixture: CRMFixture, principals: Any
) -> None:
    e = run(tmp_path, context(fixture, principals), [HIJACK], ["C06"])[(HIJACK, "C06")]
    assert e.state_diff == ()
    d6 = [
        d
        for d in e.decisions
        if isinstance(d, DecisionEvent)
        and d.defense_id == "D6"
        and d.reason_code != "read_not_reviewed"
    ]
    assert d6 and d6[0].decision.value == "deny"


def test_full_stack_keeps_legitimate_tasks(
    tmp_path: Path, fixture: CRMFixture, principals: Any
) -> None:
    r = run(
        tmp_path,
        context(fixture, principals, client=HeuristicFakeAgent()),
        [SEND, "ex-clean-opportunity-update-001"],
        ["C14"],
    )
    assert any(
        c.field == "recipient_alias" and c.after == "sales-review"
        for c in r[(SEND, "C14")].state_diff
    )
    assert changes(r[("ex-clean-opportunity-update-001", "C14")]) == {("OPP-004", "185000.00")}


def test_out_of_grammar_legit_write_falsely_blocked_by_grammar_scope(
    tmp_path: Path, fixture: CRMFixture, principals: Any
) -> None:
    r = run(
        tmp_path, context(fixture, principals, client=HeuristicFakeAgent()), [OOG], ["C00", "C05"]
    )
    assert changes(r[(OOG, "C00")]) == {("INV-012", "Paid")}
    assert changes(r[(OOG, "C05")]) == set()  # measured utility cost of deterministic scoping


def test_oracle_upper_bound_allows_labeled_change(
    tmp_path: Path, fixture: CRMFixture, principals: Any
) -> None:
    scopes = {OOG: oracle_scope(SCENARIOS[OOG].user_request, TRUTH[OOG])}
    ctx = context(fixture, principals, client=HeuristicFakeAgent(), oracle_scopes=scopes)
    e = run(tmp_path, ctx, [OOG], ["ORACLE-C05"])[(OOG, "ORACLE-C05")]
    assert changes(e) == {("INV-012", "Paid")}


@dataclass
class QuotaThenFake:
    """Fake primary model whose quota runs out after `budget` successful calls."""

    budget: int
    inner: HeuristicFakeAgent = field(default_factory=HeuristicFakeAgent)
    calls: int = 0

    @property
    def provider_kind(self) -> Any:
        return self.inner.provider_kind

    @property
    def model_id(self) -> str:
        return "primary-model"

    def complete(self, messages: Any, tools: Any, config: Any) -> Any:
        self.calls += 1
        if self.calls > self.budget:
            raise LLMError(LLMErrorKind.RATE_LIMIT, "tokens per day exhausted", retry_after_s=40000)
        return self.inner.complete(messages, tools, config).model_copy(
            update={"model_id": "primary-model"}
        )


def test_quota_fallback_switches_per_scenario_block(
    tmp_path: Path, fixture: CRMFixture, principals: Any
) -> None:
    fallback = ModelSlot(
        "fallback", HeuristicFakeAgent(model="fallback-model"), CallController(), GenerationConfig()
    )
    ctx = context(
        fixture,
        principals,
        client=QuotaThenFake(budget=5),  # enough for scenario 1 (2 configs x 2 calls) + 1 call
        controller=CallController(retry=RetryPolicy(max_retries=0), max_rate_wait_s=90),
        fallback=fallback,
    )
    ids = ["ex-clean-invoice-summary-001", "ex-clean-invoice-status-update-001"]
    summary = run_episodes(
        ctx,
        [SCENARIOS[i] for i in ids],
        [REGISTRY.get("C00"), REGISTRY.get("C01")],
        1,
        RunWriter(tmp_path),
    )
    assert summary.aborted is None and summary.model_switch is not None
    assert summary.model_switch["at_scenario"] == ids[1]
    episodes = load_episodes(tmp_path / "episodes.jsonl")
    by_scenario: dict[str, set[str]] = {}
    for e in episodes:
        by_scenario.setdefault(e.scenario_id, set()).add(e.model_id)
    assert by_scenario == {
        ids[0]: {"primary-model"},
        ids[1]: {"fallback-model"},
    }  # one model per block
    aborted = load_episodes(tmp_path / "aborted_episodes.jsonl")
    assert aborted and all(a.scenario_id == ids[1] for a in aborted)
    assert summary.episodes_by_model == {"primary-model": 2, "fallback-model": 2}


def test_quota_without_fallback_stops_and_resumes(
    tmp_path: Path, fixture: CRMFixture, principals: Any
) -> None:
    ctx = context(
        fixture,
        principals,
        client=QuotaThenFake(budget=1),
        controller=CallController(retry=RetryPolicy(max_retries=0)),
    )
    summary = run_episodes(
        ctx,
        [SCENARIOS["ex-clean-invoice-summary-001"]],
        [REGISTRY.get("C00")],
        1,
        RunWriter(tmp_path),
    )
    assert summary.aborted and "exhausted" in summary.aborted
    resumed = run_episodes(
        context(fixture, principals, client=HeuristicFakeAgent()),
        [SCENARIOS["ex-clean-invoice-summary-001"]],
        [REGISTRY.get("C00")],
        1,
        RunWriter(tmp_path, resume=True),
    )
    assert resumed.episodes == 1 and resumed.aborted is None
