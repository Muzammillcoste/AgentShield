from __future__ import annotations

from typing import Any

import pytest

from agentshield.benchmark.selection import select_finalists
from agentshield.defenses.registry import load_registry
from tests.conftest import ROOT

REG = load_registry(ROOT / "configs" / "defenses.yaml")
CONFIGS = {c.id: c for c in REG.configs()}


def row(cid: str, uer: float, ctsr: float, alts: float = 0.5, fbr: float = 0.0) -> dict[str, Any]:
    return {
        "config_id": cid,
        "UER": uer,
        "CTSR": ctsr,
        "ALTS": alts,
        "FBR": fbr,
        "tokens_mean": 1000,
    }


def test_rule_picks_baseline_best_prompt_level_and_full_stack() -> None:
    summary = [
        row("C00", 0.5, 0.9),
        row("C01", 0.3, 0.9),
        row("C03", 0.2, 0.88),
        row("C09", 0.0, 0.8),
        row("C14", 0.0, 0.78),
        row("C05", 0.0, 0.5),  # C05 unusable (CTSR below floor)
        row("ORACLE-C09", 0.0, 1.0),
    ]
    out = select_finalists(summary, CONFIGS)
    assert out["finalists"] == ["C00", "C09", "C03", "C14"]
    assert "C05" in out["rejected"] and "ORACLE-C09" not in out["ranking"]


def test_rule_replaces_duplicate_pick() -> None:
    summary = [
        row("C00", 0.5, 0.9),
        row("C14", 0.0, 0.9, alts=0.9),
        row("C01", 0.4, 0.9),
        row("C12", 0.1, 0.85),
    ]
    out = select_finalists(summary, CONFIGS)
    assert out["finalists"] == ["C00", "C14", "C01", "C12"]


def test_high_false_block_rejected_and_baseline_required() -> None:
    out = select_finalists([row("C00", 0.5, 0.9), row("C09", 0.0, 0.9, fbr=0.5)], CONFIGS)
    assert "C09" in out["rejected"]
    with pytest.raises(ValueError):
        select_finalists([row("C09", 0.0, 0.9)], CONFIGS)
