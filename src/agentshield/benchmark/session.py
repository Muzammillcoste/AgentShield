"""Helpers shared by the run/estimate/check-provider CLI commands."""

from __future__ import annotations

from pathlib import Path

from agentshield.benchmark.loader import load_public_scenarios
from agentshield.benchmark.manifest import content_hash
from agentshield.config import ModelConfig, ModelPrice, load_model_config, load_pricing
from agentshield.llm.settings import ResolvedModelSettings, load_environment, resolve_model_settings
from agentshield.schemas.scenario import ScenarioPublic

DEFAULT_MODEL_CONFIGS = {"fake": "configs/model.fake.yaml", "real": "configs/model.groq.yaml"}
DEFAULT_PRICING = {"real": "configs/pricing.groq.yaml"}


class SelectionError(ValueError):
    pass


def select_scenarios(
    public_path: Path, scenario_ids: str | None = None, limit: int | None = None
) -> list[ScenarioPublic]:
    scenarios = load_public_scenarios(public_path)
    if scenario_ids:
        wanted = [s.strip() for s in scenario_ids.split(",") if s.strip()]
        by_id = {s.scenario_id: s for s in scenarios}
        missing = [w for w in wanted if w not in by_id]
        if missing:
            raise SelectionError(f"unknown scenario ids in {public_path.name}: {missing}")
        scenarios = [by_id[w] for w in wanted]
    if limit is not None:
        scenarios = scenarios[:limit]
    if not scenarios:
        raise SelectionError("no scenarios selected")
    return scenarios


def dataset_version(manifest_path: Path, public_path: Path) -> str:
    """Content hash identifying the dataset state (data manifest, else the public file)."""
    source = manifest_path if manifest_path.exists() else public_path
    return f"{source.name}:{content_hash(source)[:16]}"


def load_model(root: Path, model_config_path: Path) -> tuple[ModelConfig, ResolvedModelSettings]:
    config = load_model_config(model_config_path)
    return config, resolve_model_settings(config, load_environment(root))


def load_price(pricing_path: Path | None, model_id: str) -> tuple[ModelPrice | None, str | None]:
    """(price, pricing version) for `model_id`, or (None, None) when unavailable."""
    if pricing_path is None or not pricing_path.exists():
        return None, None
    table = load_pricing(pricing_path)
    return table.models.get(model_id), table.version
