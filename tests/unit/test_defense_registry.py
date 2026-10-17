from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from agentshield.defenses.registry import (
    DefenseRegistry,
    UnknownConfigError,
    config_from_bitmask,
    defenses_from_mask,
    load_registry,
)
from agentshield.schemas.experiment import (
    ConfigFamily,
    D2Mode,
    D5Granularity,
    DefenseConfig,
    DefenseId,
    ScopeSource,
)
from tests.conftest import ROOT

# Specification §9, verbatim.
SPEC_PRIMARY = {
    "C00": "",
    "C01": "D1",
    "C02": "D2",
    "C03": "D3",
    "C04": "D4",
    "C05": "D5",
    "C06": "D6",
    "C07": "D1+D3",
    "C08": "D2+D3",
    "C09": "D4+D5",
    "C10": "D3+D6",
    "C11": "D1+D2+D3",
    "C12": "D1+D4+D5",
    "C13": "D2+D4+D5",
    "C14": "D1+D2+D3+D4+D5+D6",
    "C15": "D1+D3+D4+D5+D6",
}


@pytest.fixture(scope="module")
def registry() -> DefenseRegistry:
    return load_registry(ROOT / "configs" / "defenses.yaml")


def test_primary_configs_match_specification(registry: DefenseRegistry) -> None:
    primary = registry.configs(ConfigFamily.PRIMARY)
    assert {c.id: "+".join(c.enabled) for c in primary} == SPEC_PRIMARY
    hashes = [c.config_hash() for c in primary]
    assert len(set(hashes)) == 16


def test_primary_defaults(registry: DefenseRegistry) -> None:
    c14 = registry.get("C14")
    assert c14.d2_mode is D2Mode.QUARANTINE
    assert c14.d5_granularity is D5Granularity.RECORD_FIELD_VALUE
    assert c14.d6_settings is not None and c14.d6_settings.shadow_after_deny is False
    c00 = registry.get("C00")
    assert c00.enabled == () and c00.d2_mode is D2Mode.OFF and c00.d5_granularity is None


def test_all_64_combinations_representable_and_distinct(registry: DefenseRegistry) -> None:
    configs = registry.all_bitmask_configs()
    assert len(configs) == 64
    assert len({c.config_hash() for c in configs}) == 64
    assert [c.bitmask for c in configs] == list(range(64))
    assert registry.get("M63").enabled == tuple(DefenseId)
    assert registry.get("M00").enabled == ()
    with pytest.raises(UnknownConfigError):
        registry.get("M64")
    with pytest.raises(ValueError):
        defenses_from_mask(64)


def test_bitmask_and_named_configs_share_semantic_hash(registry: DefenseRegistry) -> None:
    assert registry.get("M63").config_hash() == registry.get("C14").config_hash()
    assert registry.get("M24").config_hash() == registry.get("C09").config_hash()  # D4+D5
    assert registry.get("C14-noD2").config_hash() == registry.get("C15").config_hash()


def test_leave_one_out(registry: DefenseRegistry) -> None:
    loo = registry.configs(ConfigFamily.LEAVE_ONE_OUT)
    assert len(loo) == 6
    for config in loo:
        removed = DefenseId(config.id.removeprefix("C14-no"))
        assert set(config.enabled) == set(DefenseId) - {removed}


def test_d5_granularity_levels_are_distinct(registry: DefenseRegistry) -> None:
    levels = registry.configs(ConfigFamily.D5_GRANULARITY)
    assert [c.d5_granularity for c in levels] == list(D5Granularity)
    assert len({c.config_hash() for c in levels}) == 4
    assert all(c.enabled == (DefenseId.D5,) for c in levels)


def test_oracle_configs_are_labeled_and_flagged(registry: DefenseRegistry) -> None:
    oracle = registry.configs(ConfigFamily.ORACLE_DIAGNOSTIC)
    assert {c.id for c in oracle} == {"ORACLE-C05", "ORACLE-C09"}
    for config in oracle:
        assert config.is_oracle and config.label.startswith("ORACLE UPPER BOUND")
        assert config.config_hash() != registry.get(config.id.removeprefix("ORACLE-")).config_hash()
    assert not any(c.is_oracle for c in registry.configs(ConfigFamily.PRIMARY))


def test_resolve_list(registry: DefenseRegistry) -> None:
    assert [c.id for c in registry.resolve("C00, C05,M24")] == ["C00", "C05", "M24"]
    with pytest.raises(UnknownConfigError):
        registry.resolve("C99")


def test_hash_ignores_id_and_description() -> None:
    a = DefenseConfig(id="A", d1=True, description="x")
    b = DefenseConfig(id="B", d1=True, description="y")
    assert a.config_hash() == b.config_hash()
    assert a.config_hash() != DefenseConfig(id="A", d1=True, d2=True).config_hash()


@pytest.mark.parametrize(
    "data",
    [
        {"id": "X", "d2": True, "d2_mode": "off"},
        {"id": "X", "d2": False, "d2_mode": "flag"},
        {"id": "X", "d5": False, "d5_granularity": "record"},
        {"id": "X", "d5": True, "d5_granularity": "everything"},
        {"id": "X", "d6": False, "d6_settings": {}},
        {"id": "X", "d5": True, "scope_source": "oracle"},  # oracle outside diagnostic family
        {"id": "X", "family": "oracle_diagnostic", "d5": True},  # diagnostic without oracle
        {"id": "X", "family": "oracle_diagnostic", "d1": True, "scope_source": "oracle"},
        {"id": "bad id!"},
    ],
)
def test_invalid_defense_configs_rejected(data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DefenseConfig.model_validate(data)


def test_explicit_settings_and_bitmask_builder() -> None:
    c = DefenseConfig.model_validate(
        {"id": "X", "d2": True, "d2_mode": "flag", "d5": True, "d5_granularity": "rbac_only"}
    )
    assert c.d2_mode is D2Mode.FLAG and c.d5_granularity is D5Granularity.RBAC_ONLY
    assert c.semantic_payload()["d5_granularity"] == "rbac_only"
    assert config_from_bitmask(0b010001).enabled == (DefenseId.D1, DefenseId.D5)
    assert config_from_bitmask(5).scope_source is ScopeSource.GRAMMAR
