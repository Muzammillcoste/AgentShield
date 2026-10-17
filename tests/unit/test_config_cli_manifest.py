from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.benchmark.manifest import build_data_manifest, content_hash, verify_manifest
from agentshield.cli import EXIT_CONFIG_ERROR, EXIT_OK, main
from agentshield.config import (
    ConfigError,
    load_base_config,
    load_model_config,
    load_pricing,
    load_yaml,
)
from agentshield.crm.fixtures import CRMFixture
from tests.conftest import ROOT

CONFIGS = ROOT / "configs"


def test_base_config_loads_with_spec_limits() -> None:
    config = load_base_config(CONFIGS / "base.yaml")
    assert config.runtime.max_agent_steps == 8 and config.runtime.max_tool_calls == 16
    assert (ROOT / config.dataset.fixture).is_file()


def test_model_configs() -> None:
    fake = load_model_config(CONFIGS / "model.fake.yaml")
    assert fake.provider == "fake" and fake.model_id == "fake-scripted-v1"
    real = load_model_config(CONFIGS / "model.real.example.yaml")
    assert real.provider == "openai_compatible"
    assert real.model_id is None and real.model_env == "AGENTSHIELD_MODEL"  # never assumed


def test_pricing_template_invents_no_prices() -> None:
    pricing = load_pricing(CONFIGS / "pricing.example.yaml")
    assert pricing.models == {}


def test_experiments_yaml_marks_paid_plans() -> None:
    plans = load_yaml(CONFIGS / "experiments.yaml")["plans"]
    for name, plan in plans.items():
        if plan["provider"] == "real":
            assert plan.get("requires_approval") is True, name


def test_config_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_yaml(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_yaml(bad)


def test_cli_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list-configs", "--json"]) == EXIT_OK
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 16 + 6 + 4 + 2
    assert main(["list-configs", "--all-bitmasks"]) == EXIT_OK
    assert len(capsys.readouterr().out.strip().splitlines()) == 64
    assert main(["show-config", "C09"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["bitmask"] == 24
    assert main(["show-config", "C99"]) == EXIT_CONFIG_ERROR
    capsys.readouterr()
    assert main(["resolve-scope", "Mark invoice INV-003 as Paid."]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["resolution"] == "resolved"
    assert main(["fixture-info"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["customers"] == 20
    assert main(["validate-data"]) == EXIT_OK
    assert "VALID" in capsys.readouterr().out


def test_cli_version_and_usage_errors(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    with pytest.raises(SystemExit) as info:
        main(["no-such-command"])
    assert info.value.code == 2


def test_manifest_detects_changes_and_normalizes_newlines(
    tmp_path: Path, fixture: CRMFixture
) -> None:
    (tmp_path / "public").mkdir()
    data_file = tmp_path / "public" / "x.jsonl"
    data_file.write_bytes(b'{"a":1}\n')
    manifest = build_data_manifest(tmp_path, fixture)
    assert verify_manifest(manifest, tmp_path) == []
    data_file.write_bytes(b'{"a":1}\r\n')  # Windows checkout: same content hash
    assert content_hash(data_file) == manifest.files["public/x.jsonl"]
    data_file.write_bytes(b'{"a":2}\n')
    assert verify_manifest(manifest, tmp_path) == ["hash mismatch: public/x.jsonl"]
    (tmp_path / "public" / "y.jsonl").write_text("{}\n", encoding="utf-8")
    assert "file not in manifest: public/y.jsonl" in verify_manifest(manifest, tmp_path)
