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


def test_cli_requires_real_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
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


def test_cli_run_and_analyze_dev_subset(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "run"
    args = [
        "run",
        "--provider",
        "fake",
        "--fake-susceptible",
        "--split",
        "dev",
        "--scenarios",
        "cln-r1-cus001,cln-w1-inv008,atk-001,atk-025,atk-033,hb-d01",
        "--configs",
        "C00,C09",
        "--output",
        str(out),
    ]
    assert main(args) == EXIT_OK
    assert main(["analyze", "--input", str(out)]) == EXIT_OK
    printed = capsys.readouterr().out
    assert "not research evidence" in printed
    analysis = out / "analysis"
    for name in (
        "grades.csv",
        "summary.csv",
        "summary.json",
        "per_attack_family.csv",
        "paired_comparison.csv",
        "detector.json",
        "report.md",
        "security_utility.png",
    ):
        assert (analysis / name).exists(), name
    assert "NOT RESEARCH EVIDENCE" in (analysis / "report.md").read_text(encoding="utf-8")


def test_cli_select_freezes_finalists_from_dev_only(tmp_path: Path) -> None:
    out = tmp_path / "run"
    ids = "cln-r1-cus001,cln-w1-inv008,cln-s1-cus001,atk-001,atk-025,hb-d01"
    assert (
        main(
            [
                "run",
                "--provider",
                "fake",
                "--fake-susceptible",
                "--split",
                "dev",
                "--scenarios",
                ids,
                "--configs",
                "C00,C03,C09,C14",
                "--output",
                str(out),
            ]
        )
        == EXIT_OK
    )
    assert main(["analyze", "--input", str(out)]) == EXIT_OK
    frozen = tmp_path / "final.yaml"
    assert main(["select", "--analysis", str(out / "analysis"), "--output", str(frozen)]) == EXIT_OK
    import yaml

    data = yaml.safe_load(frozen.read_text(encoding="utf-8"))
    assert data["finalists"][0] == "C00" and len(data["finalists"]) <= 4
    assert set(data["finalist_hashes"]) == set(data["finalists"])
    grades = out / "analysis" / "grades.csv"
    grades.write_text(
        grades.read_text(encoding="utf-8").replace(",dev,", ",heldout,"), encoding="utf-8"
    )
    assert (
        main(["select", "--analysis", str(out / "analysis"), "--output", str(frozen)])
        == EXIT_CONFIG_ERROR
    )


def test_heldout_requires_frozen_selection(tmp_path: Path) -> None:
    base = ["run", "--provider", "fake", "--split", "heldout", "--limit", "2", "--output"]
    assert main([*base, str(tmp_path / "a")]) == EXIT_CONFIG_ERROR
    frozen = ROOT / "configs" / "final_selection.yaml"
    assert main([*base, str(tmp_path / "b"), "--frozen-selection", str(frozen)]) == EXIT_OK
    episodes = load_episodes(tmp_path / "b" / "episodes.jsonl")
    assert {e.config_id for e in episodes} == {"C00", "C11", "C14"}
