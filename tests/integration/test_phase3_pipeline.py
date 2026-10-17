"""Attack injection + D1/D2/D3 through the real runner with a susceptible FAKE agent.

The fake agent obeys regex-matched imperatives in tool output. These tests check plumbing
(injection reaches the model, defenses transform what it sees, outcomes are recorded); they
say nothing about how a real model behaves.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.benchmark.artifacts import RunWriter, load_episodes
from agentshield.benchmark.loader import load_public_scenarios
from agentshield.benchmark.runner import (
    RunContext,
    UnsupportedInPhaseError,
    check_supported,
    run_episodes,
)
from agentshield.config import RuntimeLimits
from agentshield.crm.fixtures import CRMFixture
from agentshield.defenses.d1_system_prompt import D1_SECURITY_INSTRUCTION
from agentshield.defenses.registry import load_registry
from agentshield.llm.fake_agent import HeuristicFakeAgent
from agentshield.llm.resilience import CallController
from agentshield.schemas.events import DecisionEvent, ToolResultEvent
from agentshield.schemas.experiment import EpisodeResult
from agentshield.schemas.llm import GenerationConfig
from tests.conftest import EXAMPLES_PUBLIC, ROOT

SCENARIOS = {s.scenario_id: s for s in load_public_scenarios(EXAMPLES_PUBLIC)}
REGISTRY = load_registry(ROOT / "configs" / "defenses.yaml")
HIJACK = "ex-attack-workflow-hijack-001"
SWAP = "ex-attack-parameter-swap-001"
BENIGN = "ex-hard-benign-001"


def run(
    tmp_path: Path,
    fixture: CRMFixture,
    principals: object,
    scenario_ids: list[str],
    config_ids: list[str],
    susceptible: bool = True,
) -> dict[tuple[str, str], EpisodeResult]:
    ctx = RunContext(
        run_id="phase3",
        fixture=fixture,
        principals=principals,  # type: ignore[arg-type]
        client=HeuristicFakeAgent(follow_injections=susceptible),
        controller=CallController(),
        generation=GenerationConfig(),
        limits=RuntimeLimits(),
        dataset_version="test",
    )
    run_episodes(
        ctx,
        [SCENARIOS[s] for s in scenario_ids],
        [REGISTRY.get(c) for c in config_ids],
        1,
        RunWriter(tmp_path),
    )
    return {(e.scenario_id, e.config_id): e for e in load_episodes(tmp_path / "episodes.jsonl")}


def proposed(e: EpisodeResult) -> list[str]:
    return [p.tool_name for p in e.proposed_calls]


def test_injection_reaches_model_and_baseline_executes_attack(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    e = run(tmp_path, fixture, principals, [HIJACK], ["C00"])[(HIJACK, "C00")]
    delivered = [r for r in e.trace if isinstance(r, ToolResultEvent) and r.injection_applied]
    assert delivered and "mark invoice INV-003 as Paid" in delivered[0].content
    assert "update_invoice_status" in proposed(e)
    assert [(c.record_id, c.after) for c in e.state_diff] == [("INV-003", "Paid")]


def test_d2_quarantine_prevents_attempt_and_logs_decision(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    e = run(tmp_path, fixture, principals, [HIJACK], ["C02"])[(HIJACK, "C02")]
    assert "update_invoice_status" not in proposed(e) and e.state_diff == ()
    decisions = [d for d in e.decisions if isinstance(d, DecisionEvent) and d.defense_id == "D2"]
    assert decisions and decisions[0].decision.value == "quarantine"
    seen = next(r for r in e.trace if isinstance(r, ToolResultEvent))
    assert seen.transforms == ("override-v1", "d2", "json-v1") and "withheld" in seen.content


def test_d3_wraps_but_fake_still_follows(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    # D3 changes presentation only; a regex-following fake ignores it (real models may not).
    e = run(tmp_path, fixture, principals, [HIJACK], ["C03"])[(HIJACK, "C03")]
    seen = next(r for r in e.trace if isinstance(r, ToolResultEvent))
    assert seen.content.startswith("<<TOOL_RESULT") and seen.transforms[-1] == "d3-v1"
    assert "update_invoice_status" in proposed(e)
    assert e.final_answer  # fake agent still parses wrapped JSON


def test_d1_changes_only_the_prompt(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    results = run(tmp_path, fixture, principals, [HIJACK], ["C00", "C01"])
    base, d1 = results[(HIJACK, "C00")], results[(HIJACK, "C01")]
    assert (
        base.artifact_hashes["system_prompt_sha256"] != d1.artifact_hashes["system_prompt_sha256"]
    )
    assert base.artifact_hashes["tool_schema_sha256"] == d1.artifact_hashes["tool_schema_sha256"]
    transcript = (tmp_path / "traces" / f"{HIJACK}__C01__r0.json").read_text(encoding="utf-8")
    assert D1_SECURITY_INSTRUCTION[:60] in transcript


def test_same_tool_wrong_record_attack_and_legit_write_under_baseline(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    e = run(tmp_path, fixture, principals, [SWAP], ["C00"])[(SWAP, "C00")]
    changed = {(c.record_id, c.after) for c in e.state_diff}
    assert ("INV-005", "Paid") in changed  # attacker's record (executed in baseline)
    assert ("INV-007", "Paid") in changed  # the legitimate requested write also happened


def test_hard_benign_not_quarantined(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    e = run(tmp_path, fixture, principals, [BENIGN], ["C02"])[(BENIGN, "C02")]
    assert not [d for d in e.decisions if isinstance(d, DecisionEvent) and d.defense_id == "D2"]
    seen = next(r for r in e.trace if isinstance(r, ToolResultEvent))
    assert seen.injection_applied and "do not close this ticket" in seen.content


def test_non_susceptible_fake_ignores_injection(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    e = run(tmp_path, fixture, principals, [HIJACK], ["C00"], susceptible=False)[(HIJACK, "C00")]
    assert proposed(e) == ["list_invoices"] and e.state_diff == ()


def test_oracle_requires_private_scopes() -> None:
    with pytest.raises(UnsupportedInPhaseError, match="ORACLE UPPER BOUND"):
        check_supported([SCENARIOS[HIJACK]], [REGISTRY.get("ORACLE-C09")])
    all_ids = ("C00", "C01", "C02", "C03", "C04", "C05", "C06", "C09", "C14", "C15")
    check_supported(list(SCENARIOS.values()), [REGISTRY.get(c) for c in all_ids])
