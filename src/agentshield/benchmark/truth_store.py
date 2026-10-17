"""PRIVATE ground-truth loader. Import only from the grader, validator and analysis code."""

from __future__ import annotations

from pathlib import Path

from agentshield.benchmark.loader import DatasetFormatError, read_jsonl
from agentshield.schemas.truth import ScenarioPrivateTruth


def load_private_truth(path: str | Path) -> dict[str, ScenarioPrivateTruth]:
    truths: dict[str, ScenarioPrivateTruth] = {}
    for index, row in enumerate(read_jsonl(path), start=1):
        try:
            truth = ScenarioPrivateTruth.model_validate(row)
        except ValueError as exc:
            raise DatasetFormatError(f"{path} row {index}: {exc}") from exc
        if truth.scenario_id in truths:
            raise DatasetFormatError(f"{path}: duplicate truth for {truth.scenario_id}")
        truths[truth.scenario_id] = truth
    return truths
