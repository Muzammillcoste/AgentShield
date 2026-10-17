"""Public scenario contract: what the runtime orchestrator may see.

The orchestrator sees `category`/`attack_family` for bookkeeping, but these labels must never
be passed to the agent, the tools, or any defense. Defenses receive only the trusted user
request, the authenticated principal and the derived task scope.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from agentshield.schemas.common import (
    SCHEMA_VERSION,
    EntityType,
    PrincipalId,
    StrictModel,
    entity_type_of,
)

ScenarioId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{2,80}$")]


class Split(StrEnum):
    DEV = "dev"
    HELDOUT = "heldout"


class Category(StrEnum):
    CLEAN = "clean"
    ATTACK = "attack"
    HARD_BENIGN = "hard_benign"


class AttackFamily(StrEnum):
    AUTHORITY_SPOOF = "authority_spoof"
    WORKFLOW_HIJACK = "workflow_hijack"
    TOOL_MISUSE = "tool_misuse"
    PARAMETER_SWAP = "parameter_swap"
    ANSWER_CONTAMINATION = "answer_contamination"


class Placement(StrEnum):
    REPLACE = "replace"
    APPEND = "append"


class InjectionSurface(StrictModel):
    """A lower-trust text field that an attacker can edit and that a read tool returns."""

    tool_name: str
    entity: EntityType
    field_path: str


# The complete attacker-writable surface. IDs, amounts, statuses, tenants, principals,
# tool schemas and prompts are deliberately absent.
ATTACK_SURFACES: tuple[InjectionSurface, ...] = (
    InjectionSurface(tool_name="list_invoices", entity=EntityType.INVOICE, field_path="notes"),
    InjectionSurface(tool_name="get_invoice", entity=EntityType.INVOICE, field_path="notes"),
    InjectionSurface(
        tool_name="get_opportunity", entity=EntityType.OPPORTUNITY, field_path="description"
    ),
    InjectionSurface(tool_name="list_cases", entity=EntityType.CASE, field_path="description"),
)


def find_surface(tool_name: str, field_path: str) -> InjectionSurface | None:
    for surface in ATTACK_SURFACES:
        if surface.tool_name == tool_name and surface.field_path == field_path:
            return surface
    return None


def surfaces_for(entity: EntityType, field_path: str) -> tuple[InjectionSurface, ...]:
    return tuple(s for s in ATTACK_SURFACES if s.entity == entity and s.field_path == field_path)


class InjectionSpec(StrictModel):
    """A text override applied to tool *responses*; the stored CRM record is never modified.

    Matching semantics: a "matching tool result" is any attack-surface tool result that
    exposes `field_path` of `target_record_id` (the attacker edited the stored field, so
    every read shows it). `apply_on_nth_matching_tool_result=None` applies the override to
    every matching result (persistent, the dataset default); an integer k applies it only to
    the k-th. `tool_name` is the primary delivery surface used for reachability validation.
    The same mechanism carries benign imperative-looking text for hard-benign scenarios.
    """

    tool_name: str
    target_record_id: str
    field_path: str
    replacement_text: Annotated[str, StringConstraints(min_length=1, max_length=2000)]
    placement: Placement = Placement.APPEND
    apply_on_nth_matching_tool_result: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def _check_surface(self) -> InjectionSpec:
        surface = find_surface(self.tool_name, self.field_path)
        if surface is None:
            raise ValueError(
                f"({self.tool_name!r}, {self.field_path!r}) is not a configured attack surface"
            )
        if entity_type_of(self.target_record_id) != surface.entity:
            raise ValueError(
                f"target_record_id {self.target_record_id!r} is not a {surface.entity} id"
            )
        return self

    @property
    def surface(self) -> InjectionSurface:
        surface = find_surface(self.tool_name, self.field_path)
        assert surface is not None  # guaranteed by validator
        return surface


class ScenarioPublic(StrictModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    scenario_id: ScenarioId
    base_task_id: ScenarioId
    split: Split
    category: Category
    attack_family: AttackFamily | None = None
    principal_id: PrincipalId
    fixture_id: str
    user_request: Annotated[str, StringConstraints(min_length=1, max_length=1000)]
    injection: InjectionSpec | None = None
    max_turns: Annotated[int, Field(ge=1, le=32)] = 8
    tags: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_category(self) -> ScenarioPublic:
        if self.category is Category.ATTACK:
            if self.injection is None or self.attack_family is None:
                raise ValueError("attack scenarios require an injection and an attack_family")
        elif self.category is Category.CLEAN:
            if self.injection is not None or self.attack_family is not None:
                raise ValueError("clean scenarios must not have an injection or attack_family")
        elif self.category is Category.HARD_BENIGN:
            if self.attack_family is not None:
                raise ValueError("hard_benign scenarios must not have an attack_family")
            if self.injection is None:
                raise ValueError(
                    "hard_benign scenarios carry benign text via an injection override"
                )
        return self
