"""Deterministic authorization policy (the engine behind D5).

Inputs are only trusted: the authenticated principal, the request-derived `TaskScope`, the
proposed call, and structured store lookups. Levels are cumulative:

1. `rbac_only`          role capability for the tool + tenant confinement   (general ability)
2. `task_and_tool`      + tool in the task's tool set; mutations only if the request asked
                          for that kind of mutation; unresolved/ambiguous scope => no mutation
3. `record`             + reads limited to the scope's records; writes/sends only to the
                          granted record / recipient
4. `record_field_value` + exact field and value; message bodies may only reference records of
                          the subject customer

Anything not explicitly granted is denied (deny by default). A role's general write ability
is never evidence that a specific write was requested.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from agentshield.auth.reach import ReadScopeIndex, RecordLookup
from agentshield.auth.scope_resolver import ScopeResolution, TaskScope, WriteGrant
from agentshield.crm.dispatcher import ActionRequest, GateDecision
from agentshield.crm.tools import ToolAccess, get_tool
from agentshield.schemas.common import EntityType, record_ids_in_text
from agentshield.schemas.events import DecisionKind
from agentshield.schemas.experiment import D5Granularity

POLICY_VERSION = "d5-policy-v1"


def _deny(reason: str, **details: Any) -> GateDecision:
    return GateDecision(decision=DecisionKind.DENY, reason_code=reason, details=details)


def _allow(level: D5Granularity) -> GateDecision:
    return GateDecision(
        decision=DecisionKind.ALLOW, reason_code="authorized", details={"level": level.label}
    )


def canonical_value(field: str | None, value: Any) -> str | None:
    if value is None:
        return None
    if field == "amount":
        try:
            return str(Decimal(str(value)).quantize(Decimal("0.01")))
        except InvalidOperation:
            return None
    return str(value)


class PolicyEngine:
    def __init__(
        self,
        scope: TaskScope,
        granularity: D5Granularity,
        lookup: RecordLookup,
    ) -> None:
        self.scope = scope
        self.granularity = granularity
        self.lookup = lookup
        self.reads = ReadScopeIndex.build(scope, lookup)

    def evaluate(self, request: ActionRequest) -> GateDecision:
        level = self.granularity
        spec = get_tool(request.tool_name)
        if spec is None:  # unreachable after schema validation; deny by default anyway
            return _deny("unknown_tool")

        # (1) general role ability + tenant confinement
        if not request.principal.has(spec.required_capability):
            return _deny("role_lacks_capability", capability=spec.required_capability.value)
        if request.target_exists and request.target_tenant_id != request.principal.tenant_id:
            return _deny("cross_tenant", target_tenant=request.target_tenant_id)
        if level < D5Granularity.TASK_AND_TOOL:
            return _allow(level)

        # (2) request-specific tool/action permission
        if request.tool_name not in self.scope.allowed_tools:
            return _deny("tool_not_in_task_scope")
        mutating = request.access is not ToolAccess.READ
        if mutating and self.scope.resolution is not ScopeResolution.RESOLVED:
            return _deny("scope_unresolved", resolution=self.scope.resolution.value)
        if request.access is ToolAccess.WRITE and not self._write_grants(request):
            return _deny("mutation_not_requested")
        if request.access is ToolAccess.SIDE_EFFECT and not self.scope.send_grants:
            return _deny("send_not_requested")
        if level < D5Granularity.RECORD:
            return _allow(level)

        # (3) record / recipient scope
        if request.access is ToolAccess.READ:
            if not self.reads.readable(request.target_ref):
                return _deny("record_not_in_scope", record=request.target_ref)
            return _allow(level)
        if request.access is ToolAccess.WRITE:
            grants = [g for g in self._write_grants(request) if g.record_id == request.target_ref]
            if not grants:
                return _deny("record_not_in_scope", record=request.target_ref)
        else:
            sends = [g for g in self.scope.send_grants if g.recipient_alias == request.target_ref]
            if not sends:
                return _deny("recipient_not_in_scope", recipient=request.target_ref)
        if level < D5Granularity.RECORD_FIELD_VALUE:
            return _allow(level)

        # (4) exact field / value; message body confined to the subject customer
        if request.access is ToolAccess.WRITE:
            field = request.mutated_field
            proposed = canonical_value(field, request.args.get(field or ""))
            if not any(g.field == field for g in grants):
                return _deny("field_not_in_scope", field=field)
            if not any(g.field == field and g.value == proposed for g in grants):
                return _deny("value_not_in_scope", field=field, value=proposed)
            return _allow(level)
        body = str(request.args.get("body", ""))
        allowed = self._subject_records(sends[0].subject_customer_id)
        outside = [rid for rid in record_ids_in_text(body) if rid not in allowed]
        if outside:
            return _deny("body_references_out_of_scope_records", records=outside[:10])
        return _allow(level)

    def _write_grants(self, request: ActionRequest) -> list[WriteGrant]:
        return [g for g in self.scope.write_grants if g.tool_name == request.tool_name]

    def _subject_records(self, customer_id: str) -> set[str]:
        records = {customer_id}
        for entity in (EntityType.INVOICE, EntityType.OPPORTUNITY, EntityType.CASE):
            records.update(r.id for r in self.lookup.children_of(customer_id, entity))
        return records
