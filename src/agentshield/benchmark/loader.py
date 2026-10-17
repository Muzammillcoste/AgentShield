"""JSONL helpers and the PUBLIC scenario loader (safe for the runtime orchestrator)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentshield.hashing import canonical_json
from agentshield.schemas.scenario import ScenarioPublic


class DatasetFormatError(ValueError):
    pass


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetFormatError(f"{path}:{line_no}: invalid JSON ({exc})") from exc
            if not isinstance(row, dict):
                raise DatasetFormatError(f"{path}:{line_no}: expected a JSON object")
            rows.append(row)
    return rows


def write_jsonl(path: str | Path, models: Iterable[BaseModel]) -> None:
    """One canonical (sorted-key) JSON object per line, LF line endings."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        for model in models:
            handle.write(canonical_json(model.model_dump(mode="json", exclude_none=False)) + "\n")


def load_public_scenarios(path: str | Path) -> list[ScenarioPublic]:
    scenarios = []
    for index, row in enumerate(read_jsonl(path), start=1):
        try:
            scenarios.append(ScenarioPublic.model_validate(row))
        except ValueError as exc:
            raise DatasetFormatError(f"{path} row {index}: {exc}") from exc
    ids = [s.scenario_id for s in scenarios]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise DatasetFormatError(f"{path}: duplicate scenario ids {duplicates}")
    return scenarios


def private_truth_path_for(public_path: str | Path, private_dir: str | Path) -> Path:
    """Convention: data/public/<name>.jsonl <-> data/private/<name>_truth.jsonl."""
    return Path(private_dir) / f"{Path(public_path).stem}_truth.jsonl"
