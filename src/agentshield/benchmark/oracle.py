"""ORACLE UPPER BOUND task scopes, built from PRIVATE ground truth.

Diagnostic only: these scopes grant exactly the labeled allowed changes, which no deployable
system could know. Results using them must be labeled ORACLE UPPER BOUND and excluded from
deployable-defense rankings. Never used unless a config has `scope_source=oracle`.
"""

from __future__ import annotations

from agentshield.auth.scope_resolver import (
    ReadGrant,
    ReadRelation,
    ScopeResolution,
    SendGrant,
    TaskScope,
    WriteGrant,
    resolve_task_scope,
)
from agentshield.schemas.common import EntityType, record_ids_in_text
from agentshield.schemas.truth import ScenarioPrivateTruth

_WRITE_TOOLS = {
    EntityType.INVOICE: "update_invoice_status",
    EntityType.OPPORTUNITY: "update_opportunity_amount",
}


def oracle_scope(user_request: str, truth: ScenarioPrivateTruth) -> TaskScope:
    base = resolve_task_scope(user_request)
    customers = [r for r in record_ids_in_text(user_request) if r.startswith("CUS-")]
    writes: list[WriteGrant] = []
    sends: list[SendGrant] = []
    reads = list(base.read_grants)
    for pattern in truth.allowed_state_changes:
        if pattern.entity is EntityType.MESSAGE and pattern.field == "recipient_alias":
            if pattern.value is not None:
                sends.append(
                    SendGrant(
                        recipient_alias=str(pattern.value),
                        subject_customer_id=customers[0] if customers else "",
                    )
                )
        elif pattern.entity in _WRITE_TOOLS and pattern.record_id and pattern.field:
            if pattern.value is None:
                continue
            writes.append(
                WriteGrant(
                    tool_name=_WRITE_TOOLS[pattern.entity],
                    entity=pattern.entity,
                    record_id=pattern.record_id,
                    field=pattern.field,
                    value=str(pattern.value),
                )
            )
            reads.append(ReadGrant(record_id=pattern.record_id, relation=ReadRelation.PARENT))
    tools = set(base.allowed_tools) | {w.tool_name for w in writes}
    if sends:
        tools.add("send_internal_message")
    if writes:
        tools |= {"get_invoice", "get_opportunity", "get_customer", "list_invoices"}
    return TaskScope(
        request_sha256=base.request_sha256,
        resolution=ScopeResolution.RESOLVED,
        matched_rules=("ORACLE_UPPER_BOUND",),
        intents=base.intents,
        allowed_tools=tuple(sorted(tools)),
        read_grants=tuple(dict.fromkeys(reads)),
        write_grants=tuple(writes),
        send_grants=tuple(sends),
    )
