"""Defense configuration and episode result contracts."""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from agentshield.hashing import stable_hash
from agentshield.schemas.common import SCHEMA_VERSION, StrictModel
from agentshield.schemas.events import StateChange, ToolCallProposal, TraceEvent
from agentshield.schemas.llm import Usage


class DefenseId(StrEnum):
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"
    D5 = "D5"
    D6 = "D6"


DEFENSE_BITS: dict[DefenseId, int] = {d: 1 << i for i, d in enumerate(DefenseId)}
ALL_DEFENSES_MASK = (1 << len(DefenseId)) - 1


class D2Mode(StrEnum):
    OFF = "off"
    FLAG = "flag"
    QUARANTINE = "quarantine"


class D5Granularity(IntEnum):
    """Cumulative policy levels; each level enforces everything below it."""

    RBAC_ONLY = 1  # (a) general role ability + tenant confinement
    TASK_AND_TOOL = 2  # + (b) request-specific tool/action permission
    RECORD = 3  # + (c) record scope
    RECORD_FIELD_VALUE = 4  # + field and exact value scope

    @property
    def label(self) -> str:
        return self.name.lower()


class ScopeSource(StrEnum):
    GRAMMAR = "grammar"  # deployable: trusted deterministic request grammar
    ORACLE = "oracle"  # ORACLE UPPER BOUND: built from private labels, diagnostic only


class ConfigFamily(StrEnum):
    PRIMARY = "primary"
    LEAVE_ONE_OUT = "leave_one_out"
    D5_GRANULARITY = "d5_granularity"
    BITMASK = "bitmask"
    ORACLE_DIAGNOSTIC = "oracle_diagnostic"


class VerifierSettings(StrictModel):
    """D6 configuration. ABSTAIN always rejects high-impact actions (not configurable)."""

    provider: Literal["same_as_agent", "fake", "real"] = "same_as_agent"
    model: str | None = None
    temperature: Annotated[float, Field(ge=0, le=2)] | None = 0.0
    max_output_tokens: Annotated[int, Field(ge=16, le=4096)] = 256
    timeout_s: Annotated[float, Field(gt=0, le=300)] = 30.0
    # Consult D6 even after D5 denied, for disagreement logging only (costs tokens).
    shadow_after_deny: bool = False


class DefenseConfig(StrictModel):
    id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:+-]{1,64}$")]
    family: ConfigFamily = ConfigFamily.PRIMARY
    description: str = ""
    d1: bool = False
    d2: bool = False
    d3: bool = False
    d4: bool = False
    d5: bool = False
    d6: bool = False
    d2_mode: D2Mode = D2Mode.OFF
    d5_granularity: D5Granularity | None = None
    d6_settings: VerifierSettings | None = None
    scope_source: ScopeSource = ScopeSource.GRAMMAR

    @field_validator("d5_granularity", mode="before")
    @classmethod
    def _parse_granularity(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.isdigit():
            try:
                return D5Granularity[value.upper()]
            except KeyError:
                raise ValueError(f"unknown D5 granularity {value!r}") from None
        return value

    @model_validator(mode="before")
    @classmethod
    def _fill_defaults(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        # Fill only *missing* settings; explicit contradictions (d2=True, mode=off) still fail.
        if data.get("d2") and data.get("d2_mode") is None:
            data["d2_mode"] = D2Mode.QUARANTINE
        if data.get("d5") and data.get("d5_granularity") is None:
            data["d5_granularity"] = D5Granularity.RECORD_FIELD_VALUE
        if data.get("d6") and data.get("d6_settings") is None:
            data["d6_settings"] = VerifierSettings()
        return data

    @model_validator(mode="after")
    def _check_consistency(self) -> DefenseConfig:
        if self.d2 != (self.d2_mode is not D2Mode.OFF):
            raise ValueError("d2_mode must be 'off' exactly when D2 is disabled")
        if self.d5 != (self.d5_granularity is not None):
            raise ValueError("d5_granularity must be set exactly when D5 is enabled")
        if self.d6 != (self.d6_settings is not None):
            raise ValueError("d6_settings must be set exactly when D6 is enabled")
        if self.scope_source is ScopeSource.ORACLE:
            if self.family is not ConfigFamily.ORACLE_DIAGNOSTIC:
                raise ValueError("oracle scope is only allowed in the oracle_diagnostic family")
            if not (self.d4 or self.d5 or self.d6):
                raise ValueError("oracle scope is meaningless without D4, D5 or D6")
        elif self.family is ConfigFamily.ORACLE_DIAGNOSTIC:
            raise ValueError("oracle_diagnostic configs must use oracle scope")
        return self

    @property
    def enabled(self) -> tuple[DefenseId, ...]:
        flags = (self.d1, self.d2, self.d3, self.d4, self.d5, self.d6)
        return tuple(d for d, on in zip(DefenseId, flags, strict=True) if on)

    @property
    def bitmask(self) -> int:
        return sum(DEFENSE_BITS[d] for d in self.enabled)

    @property
    def is_oracle(self) -> bool:
        """ORACLE UPPER BOUND configs are excluded from deployable-defense rankings."""
        return self.scope_source is ScopeSource.ORACLE

    @property
    def label(self) -> str:
        names = "+".join(self.enabled) or "none"
        return f"ORACLE UPPER BOUND ({names})" if self.is_oracle else names

    def semantic_payload(self) -> dict[str, Any]:
        """Everything that changes behavior; excludes id/description/family."""
        payload = self.model_dump(mode="json", exclude={"id", "description", "family"})
        if self.d5_granularity is not None:
            payload["d5_granularity"] = self.d5_granularity.label
        return payload

    def config_hash(self) -> str:
        return stable_hash(self.semantic_payload())


class EpisodeStatus(StrEnum):
    COMPLETED = "completed"
    AGENT_REFUSED = "agent_refused"
    TIMEOUT = "timeout"
    API_ERROR = "api_error"
    PARSE_ERROR = "parse_error"
    MAX_STEPS = "max_steps"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    UNSCORABLE = "unscorable"


class EpisodeResult(StrictModel):
    """One agent episode. `grading` is filled only by the private scorer, after execution."""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: str
    scenario_id: str
    config_id: str
    config_hash: str
    model_id: str
    provider_kind: str
    repetition: Annotated[int, Field(ge=0)]
    seed: int | None = None
    dataset_version: str
    start_time: datetime
    end_time: datetime
    final_answer: str | None = None
    proposed_calls: tuple[ToolCallProposal, ...] = ()
    decisions: tuple[TraceEvent, ...] = ()
    executed_calls: tuple[TraceEvent, ...] = ()
    state_diff: tuple[StateChange, ...] = ()
    trace: tuple[TraceEvent, ...] = ()
    grading: dict[str, Any] | None = None
    usage: Usage = Field(default_factory=lambda: Usage(requests=0))
    status: EpisodeStatus
    errors: tuple[str, ...] = ()
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
