"""Registry of defense configurations.

- 16 primary screening configs (C00-C15) are declared in `configs/defenses.yaml`.
- All 64 D1-D6 combinations are representable as bitmask configs `M00`..`M63`.
- Six leave-one-out ablations from C14 (`C14-noD1` ...).
- D5 granularity variants on C05 (`C05-rbac_only` ... `C05-record_field_value`).
- ORACLE UPPER BOUND diagnostics (`ORACLE-C05`, `ORACLE-C09`) are labeled and must be
  excluded from deployable-defense rankings.

The 16 primary configs are an exploratory screening set, not a balanced factorial design.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from agentshield.config import load_yaml
from agentshield.schemas.common import StrictModel
from agentshield.schemas.experiment import (
    ALL_DEFENSES_MASK,
    DEFENSE_BITS,
    ConfigFamily,
    D2Mode,
    D5Granularity,
    DefenseConfig,
    DefenseId,
    ScopeSource,
    VerifierSettings,
)


class UnknownConfigError(KeyError):
    pass


class RegistryDefaults(StrictModel):
    d2_mode: D2Mode = D2Mode.QUARANTINE
    d5_granularity: str = "record_field_value"
    d6_settings: VerifierSettings = VerifierSettings()


class _PrimaryEntry(StrictModel):
    id: str
    defenses: tuple[DefenseId, ...]
    description: str = ""


class _RegistryFile(StrictModel):
    schema_version: str
    defaults: RegistryDefaults = RegistryDefaults()
    primary: tuple[_PrimaryEntry, ...]


def build_config(
    config_id: str,
    defenses: Iterable[DefenseId],
    *,
    family: ConfigFamily,
    defaults: RegistryDefaults,
    description: str = "",
    d5_granularity: str | None = None,
    scope_source: ScopeSource = ScopeSource.GRAMMAR,
) -> DefenseConfig:
    enabled = set(defenses)
    data: dict[str, Any] = {
        "id": config_id,
        "family": family,
        "description": description,
        "scope_source": scope_source,
    }
    for defense in DefenseId:
        data[defense.value.lower()] = defense in enabled
    if DefenseId.D2 in enabled:
        data["d2_mode"] = defaults.d2_mode
    if DefenseId.D5 in enabled:
        data["d5_granularity"] = d5_granularity or defaults.d5_granularity
    if DefenseId.D6 in enabled:
        data["d6_settings"] = defaults.d6_settings
    return DefenseConfig.model_validate(data)


def defenses_from_mask(mask: int) -> tuple[DefenseId, ...]:
    if not 0 <= mask <= ALL_DEFENSES_MASK:
        raise ValueError(f"bitmask must be in [0, {ALL_DEFENSES_MASK}], got {mask}")
    return tuple(d for d in DefenseId if mask & DEFENSE_BITS[d])


def config_from_bitmask(mask: int, defaults: RegistryDefaults | None = None) -> DefenseConfig:
    names = "+".join(defenses_from_mask(mask)) or "none"
    return build_config(
        f"M{mask:02d}",
        defenses_from_mask(mask),
        family=ConfigFamily.BITMASK,
        defaults=defaults or RegistryDefaults(),
        description=f"bitmask {mask:06b} ({names})",
    )


_BITMASK_ID = re.compile(r"^M(\d{2})$")


class DefenseRegistry:
    def __init__(self, configs: Sequence[DefenseConfig], defaults: RegistryDefaults) -> None:
        self._defaults = defaults
        self._configs: dict[str, DefenseConfig] = {}
        for config in configs:
            if config.id in self._configs:
                raise ValueError(f"duplicate config id {config.id!r}")
            self._configs[config.id] = config

    @property
    def defaults(self) -> RegistryDefaults:
        return self._defaults

    def get(self, config_id: str) -> DefenseConfig:
        if config_id in self._configs:
            return self._configs[config_id]
        match = _BITMASK_ID.match(config_id)
        if match and int(match[1]) <= ALL_DEFENSES_MASK:
            return config_from_bitmask(int(match[1]), self._defaults)
        raise UnknownConfigError(config_id)

    def resolve(self, spec: str) -> list[DefenseConfig]:
        """Resolve a comma-separated list of config ids (bitmask ids allowed)."""
        ids = [part.strip() for part in spec.split(",") if part.strip()]
        if not ids:
            raise UnknownConfigError(spec)
        return [self.get(config_id) for config_id in ids]

    def configs(self, family: ConfigFamily | None = None) -> list[DefenseConfig]:
        return [c for c in self._configs.values() if family is None or c.family is family]

    def all_bitmask_configs(self) -> list[DefenseConfig]:
        return [config_from_bitmask(mask, self._defaults) for mask in range(ALL_DEFENSES_MASK + 1)]


def load_registry(path: str | Path) -> DefenseRegistry:
    raw = _RegistryFile.model_validate(load_yaml(path))
    defaults = raw.defaults
    configs = [
        build_config(
            entry.id,
            entry.defenses,
            family=ConfigFamily.PRIMARY,
            defaults=defaults,
            description=entry.description,
        )
        for entry in raw.primary
    ]
    by_id = {c.id: c for c in configs}

    full = by_id.get("C14")
    if full is not None:
        for removed in DefenseId:
            configs.append(
                build_config(
                    f"C14-no{removed.value}",
                    (d for d in full.enabled if d is not removed),
                    family=ConfigFamily.LEAVE_ONE_OUT,
                    defaults=defaults,
                    description=f"Leave-one-out: full stack C14 without {removed.value}",
                )
            )

    for level in D5Granularity:
        configs.append(
            build_config(
                f"C05-{level.label}",
                (DefenseId.D5,),
                family=ConfigFamily.D5_GRANULARITY,
                defaults=defaults,
                d5_granularity=level.label,
                description=f"D5 only, granularity {level.label}",
            )
        )

    for base in ("C05", "C09"):
        if base in by_id:
            configs.append(
                build_config(
                    f"ORACLE-{base}",
                    by_id[base].enabled,
                    family=ConfigFamily.ORACLE_DIAGNOSTIC,
                    defaults=defaults,
                    scope_source=ScopeSource.ORACLE,
                    description=(
                        f"ORACLE UPPER BOUND of {base}: scope built from private labels. "
                        "Diagnostic only; never a deployable result."
                    ),
                )
            )
    return DefenseRegistry(configs, defaults)
