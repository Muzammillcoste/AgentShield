"""Resolve a `ModelConfig` plus environment variables into concrete provider settings.

Credentials come only from the environment (optionally loaded from a local `.env`). The API
key is held as a `SecretStr`, so it never appears in reprs, logs, traces or manifests. A real
provider with missing settings raises `ProviderConfigurationError`; it never falls back to the
fake model.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from dotenv import dotenv_values
from pydantic import Field, SecretStr

from agentshield.config import ModelConfig
from agentshield.schemas.common import StrictModel
from agentshield.schemas.llm import GenerationConfig


class ProviderConfigurationError(ValueError):
    """Real-provider settings are missing or invalid. Messages name variables, never values."""


class ResolvedModelSettings(StrictModel):
    provider: Literal["fake", "openai_compatible"]
    model_id: str
    model_source: str  # where the model id came from, e.g. "env:MODEL_NAME"
    base_url: str | None = None
    api_key: SecretStr | None = None
    api_key_env: str | None = None
    max_tokens_param: Literal["max_tokens", "max_completion_tokens"] = "max_completion_tokens"
    generation: GenerationConfig = GenerationConfig()
    extra_body: dict[str, Any] = Field(default_factory=dict)
    max_rate_limit_wait_s: float = 90.0

    def public_view(self) -> dict[str, Any]:
        """Settings safe to write into manifests (no secret material)."""
        data = self.model_dump(mode="json", exclude={"api_key"})
        data["api_key_present"] = self.api_key is not None
        return data


def load_environment(root: Path, *, env_file: str = ".env") -> dict[str, str]:
    """Process environment overlaid on top of the optional local `.env` (env wins)."""
    merged: dict[str, str] = {}
    path = root / env_file
    if path.is_file():
        merged.update({k: v for k, v in dotenv_values(path).items() if v is not None})
    merged.update(os.environ)
    return merged


def _first_set(env: Mapping[str, str], names: tuple[str, ...]) -> tuple[str, str] | None:
    for name in names:
        value = env.get(name, "").strip()
        if value:
            return name, value
    return None


def resolve_model_settings(config: ModelConfig, env: Mapping[str, str]) -> ResolvedModelSettings:
    if config.provider == "fake":
        return ResolvedModelSettings(
            provider="fake",
            model_id=config.model_id or "fake-scripted-v1",
            model_source="config",
            generation=config.generation,
        )

    if config.model_id:
        model_id, source = config.model_id, "config"
    else:
        names = tuple(n for n in (config.model_env, *config.model_env_aliases) if n)
        found = _first_set(env, names)
        if found is None:
            raise ProviderConfigurationError(
                "No model configured: set model_id in the model config or one of the "
                f"environment variables {list(names)} (e.g. in your local .env)."
            )
        model_id, source = found[1], f"env:{found[0]}"

    base_url = config.base_url
    if not base_url and config.base_url_env:
        base_url = env.get(config.base_url_env, "").strip() or None
    if not base_url:
        raise ProviderConfigurationError(
            "No base URL configured: set base_url in the model config or the "
            f"{config.base_url_env or 'base_url_env'} environment variable."
        )

    if not config.api_key_env:
        raise ProviderConfigurationError("api_key_env must name the API key variable.")
    key = env.get(config.api_key_env, "").strip()
    if not key:
        raise ProviderConfigurationError(
            f"Environment variable {config.api_key_env} is not set. Put the key in your local "
            ".env file (never in configs, code or chat)."
        )

    return ResolvedModelSettings(
        provider="openai_compatible",
        model_id=model_id,
        model_source=source,
        base_url=base_url,
        api_key=SecretStr(key),
        api_key_env=config.api_key_env,
        max_tokens_param=config.max_tokens_param,
        generation=config.generation,
        extra_body=dict(config.extra_body),
        max_rate_limit_wait_s=config.max_rate_limit_wait_s,
    )
