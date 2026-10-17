"""End-to-end offline runs through the real runner, artifacts and CLI (fake agent only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.benchmark.artifacts import RunExistsError, RunWriter, load_episodes
from agentshield.benchmark.estimate import estimate_run
from agentshield.benchmark.loader import load_public_scenarios
from agentshield.benchmark.runner import (
    RunContext,
    UnsupportedInPhaseError,
    check_supported,
    run_episodes,
)
from agentshield.cli import EXIT_APPROVAL_REQUIRED, EXIT_CONFIG_ERROR, EXIT_OK, main
from agentshield.config import RuntimeLimits
from agentshield.crm.fixtures import CRMFixture
from agentshield.defenses.registry import load_registry
from agentshield.llm.fake_agent import HeuristicFakeAgent
from agentshield.llm.resilience import CallController
from agentshield.schemas.experiment import EpisodeStatus
from agentshield.schemas.llm import GenerationConfig
from tests.conftest import EXAMPLES_PUBLIC, ROOT

CLEAN = [s for s in load_public_scenarios(EXAMPLES_PUBLIC) if s.category == "clean"]
REGISTRY = load_registry(ROOT / "configs" / "defenses.yaml")


def context(fixture: CRMFixture, principals: object) -> RunContext:
    return RunContext(
        run_id="test-run",
        fixture=fixture,
        principals=principals,  # type: ignore[arg-type]
        client=HeuristicFakeAgent(),
        controller=CallController(),
        generation=GenerationConfig(),
        limits=RuntimeLimits(),
        dataset_version="test",
    )


def test_run_writes_valid_episode_artifacts(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    writer = RunWriter(tmp_path)
    summary = run_episodes(context(fixture, principals), CLEAN, [REGISTRY.get("C00")], 2, writer)
    assert summary.episodes == len(CLEAN) * 2 and summary.aborted is None
    assert summary.statuses == {"completed": len(CLEAN) * 2}
    episodes = load_episodes(tmp_path / "episodes.jsonl")
    assert len(episodes) == summary.episodes
    first = episodes[0]
    assert first.provider_kind == "fake" and first.grading is None
    assert first.artifact_hashes["fixture_hash"] == fixture.fixture_hash()
    traces = sorted(p.name for p in (tmp_path / "traces").glob("*.json"))
    assert f"{CLEAN[0].scenario_id}__C00__r0.json" in traces and len(traces) == summary.episodes
    # Repetitions start from identical state and (fake agent) reach identical outcomes.
    by_scenario: dict[str, set[tuple[object, ...]]] = {}
    for e in episodes:
        by_scenario.setdefault(e.scenario_id, set()).add(
            tuple(c.model_dump_json() for c in e.state_diff)
        )
    assert all(len(v) == 1 for v in by_scenario.values())


def test_legitimate_writes_executed_in_run(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    run_episodes(context(fixture, principals), CLEAN, [REGISTRY.get("C00")], 1, RunWriter(tmp_path))
    episodes = {e.scenario_id: e for e in load_episodes(tmp_path / "episodes.jsonl")}
    write = episodes["ex-clean-invoice-status-update-001"]
    assert [(c.record_id, c.after) for c in write.state_diff] == [("INV-003", "Paid")]
    assert write.executed_calls and write.proposed_calls


def test_phase2_guard_rails() -> None:
    attacks = [s for s in load_public_scenarios(EXAMPLES_PUBLIC) if s.injection is not None]
    with pytest.raises(UnsupportedInPhaseError, match="injector"):
        check_supported(attacks[:1], [REGISTRY.get("C00")])
    with pytest.raises(UnsupportedInPhaseError, match="Phases 3-4"):
        check_supported(CLEAN[:1], [REGISTRY.get("C05")])
    with pytest.raises(UnsupportedInPhaseError):
        check_supported(CLEAN[:1], [REGISTRY.get("ORACLE-C05")])
    check_supported(CLEAN, [REGISTRY.get("C00"), REGISTRY.get("M00")])


def test_writer_refuses_to_mix_runs(tmp_path: Path) -> None:
    (tmp_path / "episodes.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(RunExistsError):
        RunWriter(tmp_path)
    RunWriter(tmp_path, overwrite=True)
    assert not (tmp_path / "episodes.jsonl").exists()


def test_estimate_is_positive_and_scales(fixture: CRMFixture, principals: object) -> None:
    one = estimate_run(
        CLEAN,
        [REGISTRY.get("C00")],
        1,
        fixture=fixture,
        principals=principals,  # type: ignore[arg-type]
        generation=GenerationConfig(),
        limits=RuntimeLimits(),
    )
    three = estimate_run(
        CLEAN,
        [REGISTRY.get("C00")],
        3,
        fixture=fixture,
        principals=principals,  # type: ignore[arg-type]
        generation=GenerationConfig(),
        limits=RuntimeLimits(),
    )
    assert one.episodes == len(CLEAN) and one.model_calls >= 2 * len(CLEAN)
    assert one.total_tokens > 0 and one.upper_bound_total_tokens > one.total_tokens
    assert three.total_tokens == pytest.approx(3 * one.total_tokens, rel=0.01)
    assert one.paid_equivalent_usd is None  # no price supplied -> no invented cost


def test_cli_fake_run_and_estimate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ids = "ex-clean-invoice-summary-001,ex-clean-invoice-status-update-001"
    assert main(["estimate", "--public", str(EXAMPLES_PUBLIC), "--scenarios", ids]) == EXIT_OK
    assert "estimate: episodes=2" in capsys.readouterr().out
    out = tmp_path / "run"
    code = main(
        [
            "run",
            "--provider",
            "fake",
            "--public",
            str(EXAMPLES_PUBLIC),
            "--scenarios",
            ids,
            "--configs",
            "C00",
            "--output",
            str(out),
        ]
    )
    assert code == EXIT_OK
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["research_evidence"] is False and "FAKE" in manifest["note"]
    assert manifest["summary"]["episodes"] == 2 and manifest["model"]["api_key_present"] is False
    assert manifest["environment"]["python"].startswith("3.12")
    assert len(load_episodes(out / "episodes.jsonl")) == 2
    assert (
        main(
            [
                "run",
                "--provider",
                "fake",
                "--public",
                str(EXAMPLES_PUBLIC),
                "--scenarios",
                ids,
                "--output",
                str(out),
            ]
        )
        == EXIT_CONFIG_ERROR
    )  # refuses to overwrite silently


def test_cli_rejects_unsupported_and_requires_real_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "run",
                "--public",
                str(EXAMPLES_PUBLIC),
                "--configs",
                "C05",
                "--scenarios",
                "ex-clean-invoice-summary-001",
                "--output",
                str(tmp_path / "x"),
            ]
        )
        == EXIT_CONFIG_ERROR
    )
    monkeypatch.setenv("AGENTSHIELD_MODEL", "qwen/qwen3.8-27b")
    monkeypatch.setenv("LLM_API_KEY", "gsk_placeholder_for_test_only_000000")
    code = main(
        [
            "run",
            "--provider",
            "real",
            "--public",
            str(EXAMPLES_PUBLIC),
            "--scenarios",
            "ex-clean-invoice-summary-001",
            "--output",
            str(tmp_path / "y"),
        ]
    )
    assert code == EXIT_APPROVAL_REQUIRED  # estimate printed, nothing sent
    assert "--approve-real-usage" in capsys.readouterr().out
    assert not (tmp_path / "y" / "episodes.jsonl").exists()


def test_budget_stop_then_resume_completes_without_duplicates(
    tmp_path: Path, fixture: CRMFixture, principals: object
) -> None:
    from agentshield.config import BudgetLimits
    from agentshield.llm.resilience import BudgetGuard

    configs = [REGISTRY.get("C00")]
    tight = context(fixture, principals)
    tight.controller = CallController(budget=BudgetGuard(BudgetLimits(max_requests=3)))
    first = run_episodes(tight, CLEAN, configs, 1, RunWriter(tmp_path))
    assert first.aborted and "budget" in first.aborted
    completed = load_episodes(tmp_path / "episodes.jsonl")
    aborted = load_episodes(tmp_path / "aborted_episodes.jsonl")
    assert len(completed) == 1 and len(aborted) == 1  # 2 calls + 1 call then stop
    assert aborted[0].status is EpisodeStatus.INFRASTRUCTURE_ERROR

    writer = RunWriter(tmp_path, resume=True)
    assert writer.completed_keys == {f"{completed[0].scenario_id}__C00__r0"}
    second = run_episodes(context(fixture, principals), CLEAN, configs, 1, writer)
    assert second.aborted is None and second.skipped == 1
    final = load_episodes(tmp_path / "episodes.jsonl")
    keys = [(e.scenario_id, e.repetition) for e in final]
    assert len(final) == len(CLEAN) and len(set(keys)) == len(keys)
    assert all(e.status is EpisodeStatus.COMPLETED for e in final)


def test_resume_and_overwrite_are_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        RunWriter(tmp_path, overwrite=True, resume=True)
