"""Applies a scenario's `InjectionSpec` to tool results (never to the CRM store).

The injector is a payload transformer: it receives a deep copy of the dispatcher payload,
edits exactly one allowlisted free-text field of exactly one record, and returns it. IDs,
statuses, amounts and all other fields are untouched (verified by tests). Every matching
result is counted so `apply_on_nth_matching_tool_result` can select one delivery; `None`
delivers on every matching result (the dataset default, D-006).

The same mechanism carries benign imperative-looking text for hard-benign scenarios; the
transformer never knows which kind of text it carries.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from agentshield.agent.observation import ObservationContext, TransformOutcome
from agentshield.schemas.common import EntityType
from agentshield.schemas.scenario import InjectionSpec, Placement, surfaces_for

# Where each read tool places records in its payload, and the record's id key.
_RECORD_LOCATIONS: dict[str, tuple[str | None, str]] = {
    "list_invoices": ("invoices", "invoice_id"),
    "get_invoice": (None, "invoice_id"),
    "get_opportunity": (None, "opportunity_id"),
    "list_cases": ("cases", "case_id"),
}


def _records(tool_name: str, payload: dict[str, Any]) -> Iterator[tuple[dict[str, Any], str]]:
    location = _RECORD_LOCATIONS.get(tool_name)
    data = payload.get("data")
    if location is None or not isinstance(data, dict):
        return
    list_key, id_key = location
    items = data.get(list_key, []) if list_key else [data]
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and isinstance(item.get(id_key), str):
            yield item, item[id_key]


def apply_text(original: str, text: str, placement: Placement) -> str:
    if placement is Placement.REPLACE or not original:
        return text
    return f"{original} {text}"


class TextOverrideInjector:
    """One instance per episode (it counts matching results)."""

    name = "override-v1"
    is_override = True

    def __init__(self, spec: InjectionSpec) -> None:
        self.spec = spec
        surface = spec.surface
        self._tools = {s.tool_name for s in surfaces_for(surface.entity, spec.field_path)}
        self.matches = 0
        self.deliveries = 0

    def transform(self, context: ObservationContext, payload: dict[str, Any]) -> TransformOutcome:
        if not context.ok or context.tool_name not in self._tools:
            return TransformOutcome(payload=payload)
        for record, record_id in _records(context.tool_name, payload):
            if record_id != self.spec.target_record_id:
                continue
            original = record.get(self.spec.field_path)
            if not isinstance(original, str):
                continue
            self.matches += 1
            nth = self.spec.apply_on_nth_matching_tool_result
            if nth is not None and self.matches != nth:
                return TransformOutcome(payload=payload)
            record[self.spec.field_path] = apply_text(
                original, self.spec.replacement_text, self.spec.placement
            )
            self.deliveries += 1
            return TransformOutcome(
                payload=payload,
                applied=True,
                details={"record_id": record_id, "field": self.spec.field_path},
            )
        return TransformOutcome(payload=payload)


def target_entity(spec: InjectionSpec) -> EntityType:
    return spec.surface.entity
