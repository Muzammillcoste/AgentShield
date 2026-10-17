from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.config import ModelConfig, load_model_config
from agentshield.llm.provider import build_client
from agentshield.llm.settings import (
    ProviderConfigurationError,
    load_environment,
    resolve_model_settings,
)
from agentshield.schemas.llm import ProviderKind
from tests.conftest import ROOT

GROQ = load_model_config(ROOT / "configs" / "model.groq.yaml")
KEY = "gsk_unit_test_key_abcdefghijklmnop"


def test_model_name_alias_and_key_resolution() -> None:
    settings = resolve_model_settings(GROQ, {"MODEL_NAME": "qwen/qwen3.8-27b", "LLM_API_KEY": KEY})
    assert settings.model_id == "qwen/qwen3.8-27b" and settings.model_source == "env:MODEL_NAME"
    assert settings.api_key is not None and settings.api_key.get_secret_value() == KEY
    assert settings.base_url == "https://api.groq.com/openai/v1"
    assert KEY not in repr(settings)


def test_primary_env_wins_over_alias() -> None:
    env = {"AGENTSHIELD_MODEL": "model-a", "MODEL_NAME": "model-b", "LLM_API_KEY": KEY}
    assert resolve_model_settings(GROQ, env).model_id == "model-a"


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"LLM_API_KEY": KEY}, "No model configured"),
        ({"MODEL_NAME": "m"}, "LLM_API_KEY is not set"),
        ({"MODEL_NAME": "m", "LLM_API_KEY": "   "}, "LLM_API_KEY is not set"),
    ],
)
def test_missing_settings_fail_loudly(env: dict[str, str], message: str) -> None:
    with pytest.raises(ProviderConfigurationError, match=message) as info:
        resolve_model_settings(GROQ, env)
    assert KEY not in str(info.value)


def test_missing_base_url() -> None:
    config = ModelConfig(
        provider="openai_compatible", model_id="m", api_key_env="K", base_url_env="URL"
    )
    with pytest.raises(ProviderConfigurationError, match="base URL"):
        resolve_model_settings(config, {"K": KEY})


def test_fake_provider_needs_no_credentials() -> None:
    settings = resolve_model_settings(
        ModelConfig(provider="fake", model_id="fake-heuristic-v1"), {}
    )
    assert settings.api_key is None
    assert build_client(settings).provider_kind is ProviderKind.FAKE


def test_real_provider_never_builds_fake_client() -> None:
    settings = resolve_model_settings(GROQ, {"MODEL_NAME": "m", "LLM_API_KEY": KEY})
    assert build_client(settings).provider_kind is ProviderKind.REAL  # no network at construction


def test_load_environment_reads_dotenv_and_process_env_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text("MODEL_NAME=from-file\nLLM_API_KEY=file-key\n", encoding="utf-8")
    monkeypatch.setenv("MODEL_NAME", "from-process")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    env = load_environment(tmp_path)
    assert env["MODEL_NAME"] == "from-process" and env["LLM_API_KEY"] == "file-key"
