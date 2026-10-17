"""Typed configuration loading (YAML files under `configs/`)."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import Field

from agentshield.schemas.common import StrictModel
from agentshield.schemas.llm import GenerationConfig


class ConfigError(ValueError):
    pass


class DatasetPaths(StrictModel):
    fixture: str
    public_dir: str
    private_dir: str
    manifest: str


class RuntimeLimits(StrictModel):
    max_agent_steps: Annotated[int, Field(ge=1, le=64)] = 8
    max_tool_calls: Annotated[int, Field(ge=1, le=128)] = 16
    episode_timeout_s: Annotated[float, Field(gt=0)] = 300.0
    max_retries: Annotated[int, Field(ge=0, le=10)] = 3
    backoff_initial_s: Annotated[float, Field(gt=0)] = 1.0
    backoff_max_s: Annotated[float, Field(gt=0)] = 30.0


class BudgetLimits(StrictModel):
    """Hard spending caps. Any `None` cap is unlimited for that dimension."""

    max_usd: Annotated[float, Field(ge=0)] | None = None
    max_total_tokens: Annotated[int, Field(ge=0)] | None = None
    max_requests: Annotated[int, Field(ge=0)] | None = None


class BaseConfig(StrictModel):
    schema_version: str
    dataset: DatasetPaths
    runtime: RuntimeLimits = RuntimeLimits()
    budget: BudgetLimits = BudgetLimits()
    defenses_registry: str = "configs/defenses.yaml"
    results_dir: str = "results"


class DocumentedRateLimits(StrictModel):
    """Provider-published limits, used only for planning messages (headers are authoritative)."""

    rpm: int | None = None
    rpd: int | None = None
    tpm: int | None = None
    tpd: int | None = None
    source: str = ""
    retrieved_on: date | None = None


class ModelConfig(StrictModel):
    provider: Literal["fake", "openai_compatible"]
    # The model is identified by model_id or by the first set variable among model_env and
    # model_env_aliases; it is never assumed.
    model_id: str | None = None
    model_env: str | None = None
    model_env_aliases: tuple[str, ...] = ()
    api_key_env: str | None = None
    base_url: str | None = None
    base_url_env: str | None = None
    max_tokens_param: Literal["max_tokens", "max_completion_tokens"] = "max_completion_tokens"
    generation: GenerationConfig = GenerationConfig()
    extra_body: dict[str, Any] = Field(default_factory=dict)
    # Longest client-side wait for a rate-limit window before failing (e.g. daily quota).
    max_rate_limit_wait_s: Annotated[float, Field(gt=0)] = 90.0
    documented_limits: DocumentedRateLimits | None = None


class ModelPrice(StrictModel):
    input_usd_per_mtok: Annotated[float, Field(ge=0)]
    output_usd_per_mtok: Annotated[float, Field(ge=0)]


class PricingTable(StrictModel):
    """User-supplied prices with provenance. AgentShield never invents prices."""

    version: str
    source: str
    retrieved_on: date | None = None
    currency: Literal["USD"] = "USD"
    models: dict[str, ModelPrice] = Field(default_factory=dict)


def find_repo_root(start: Path | None = None) -> Path:
    """Nearest ancestor containing pyproject.toml (falls back to the current directory)."""
    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "configs").is_dir():
            return candidate
    return here


def load_yaml(path: str | Path) -> dict[str, Any]:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at the top level")
    return data


def load_base_config(path: str | Path) -> BaseConfig:
    return BaseConfig.model_validate(load_yaml(path))


def load_model_config(path: str | Path) -> ModelConfig:
    return ModelConfig.model_validate(load_yaml(path))


def load_pricing(path: str | Path) -> PricingTable:
    return PricingTable.model_validate(load_yaml(path))
