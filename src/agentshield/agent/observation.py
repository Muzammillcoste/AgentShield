"""Observation pipeline: how a dispatcher payload becomes the text the model reads.

Order (fixed by the runtime): payload transformers (Phase 3: attack injection, then D2
inspection) operate on a deep copy of the structured payload; then exactly one serializer
(default compact JSON; D3 provenance wrapper in Phase 3) produces the message text.
Transformers never touch the CRM store, so injected text is never a state change.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Protocol

from pydantic import Field

from agentshield.schemas.common import StrictModel


class ObservationContext(StrictModel):
    call_id: str
    tool_name: str
    args: dict[str, Any]
    ok: bool
    exposed_records: tuple[str, ...] = ()


class TransformOutcome(StrictModel):
    payload: dict[str, Any]
    applied: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class PayloadTransformer(Protocol):
    name: str

    def transform(
        self, context: ObservationContext, payload: dict[str, Any]
    ) -> TransformOutcome: ...


class ObservationSerializer(Protocol):
    name: str

    def serialize(self, context: ObservationContext, payload: dict[str, Any]) -> str: ...


class JsonObservationSerializer:
    """Baseline serialization: compact JSON, insertion-ordered keys, UTF-8 preserved."""

    name = "json-v1"

    def serialize(self, context: ObservationContext, payload: dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def isolated_copy(payload: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(payload)
