"""Golden regression test: a fixed offline (FAKE) run must reproduce stored metrics exactly.

Regenerate deliberately with:  AGENTSHIELD_UPDATE_GOLDEN=1 uv run pytest tests/golden
The golden file contains fake-model numbers only; it is a software regression oracle, not a
research result.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agentshield.analysis.reports import grade_run
from agentshield.auth.principals import PrincipalDirectory
from agentshield.benchmark.artifacts import RunWriter
from agentshield.benchmark.loader import load_public_scenarios
from agentshield.benchmark.metrics import group, summarize
from agentshield.benchmark.runner import RunContext, run_episodes
from agentshield.benchmark.truth_store import load_private_truth
from agentshield.config import RuntimeLimits
from agentshield.crm.fixtures import CRMFixture
from agentshield.defenses.registry import load_registry
from agentshield.llm.fake_agent import HeuristicFakeAgent
from agentshield.llm.resilience import CallController
from agentshield.schemas.llm import GenerationConfig
from tests.conftest import ROOT

GOLDEN = Path(__file__).with_name("fake_dev_golden.json")
SCENARIOS = [
    "cln-r1-cus001",
    "cln-w1-inv008",
    "cln-s1-cus001",
    "cln-o-inv012",
    "atk-001",
    "atk-009",
    "atk-017",
    "atk-025",
    "atk-033",
    "hb-d01",
]
CONFIGS = ["C00", "C04", "C09", "C14"]
KEYS = (
    "UER",
    "UAR",
    "AGSR",
    "ALTS",
    "CTSR",
    "HBTSR",
    "FBR",
    "delivery",
    "contamination",
    "failure_gap",
)


def _metrics(tmp_path: Path, fixture: CRMFixture) -> dict[str, Any]:
    public = {
        s.scenario_id: s for s in load_public_scenarios(ROOT / "data" / "public" / "dev.jsonl")
    }
    truths = load_private_truth(ROOT / "data" / "private" / "dev_truth.jsonl")
    registry = load_registry(ROOT / "configs" / "defenses.yaml")
    ctx = RunContext(
        run_id="golden",
        fixture=fixture,
        principals=PrincipalDirectory(fixture.principals),
        client=HeuristicFakeAgent(follow_injections=True),
        controller=CallController(),
        generation=GenerationConfig(),
        limits=RuntimeLimits(),
        dataset_version="golden",
    )
    run_episodes(
        ctx,
        [public[s] for s in SCENARIOS],
        [registry.get(c) for c in CONFIGS],
        1,
        RunWriter(tmp_path),
    )
    grades = grade_run(tmp_path, public, truths, fixture)
    out: dict[str, Any] = {}
    for (config,), items in sorted(group(grades, "config_id").items()):
        summary = summarize(items)
        out[config] = {k: summary.get(k) for k in KEYS} | {
            f"{k}_k": summary.get(f"{k}_k") for k in KEYS if f"{k}_k" in summary
        }
        out[config]["outcomes"] = sorted((g.scenario_id, g.outcome) for g in items)
    return out


def test_fake_pipeline_reproduces_golden_metrics(tmp_path: Path, fixture: CRMFixture) -> None:
    actual = json.loads(json.dumps(_metrics(tmp_path, fixture)))
    if os.environ.get("AGENTSHIELD_UPDATE_GOLDEN") == "1" or not GOLDEN.exists():
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert actual == expected
