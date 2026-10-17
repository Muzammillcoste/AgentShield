"""Which records a task scope makes readable, via trusted structured foreign keys only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from agentshield.auth.scope_resolver import ReadRelation, TaskScope
from agentshield.schemas.common import EntityType, entity_type_of

_CHILD_ENTITIES = (EntityType.INVOICE, EntityType.OPPORTUNITY, EntityType.CASE)


class RecordLookup(Protocol):
    def get(self, record_id: str) -> Any: ...

    def customer_of(self, record_id: str) -> str | None: ...

    def children_of(self, customer_id: str, entity: EntityType) -> list[Any]: ...


@dataclass(frozen=True)
class ReadScopeIndex:
    customers: frozenset[str]
    records: frozenset[str]

    @classmethod
    def build(cls, scope: TaskScope, lookup: RecordLookup) -> ReadScopeIndex:
        customers: set[str] = set()
        records: set[str] = set()
        for grant in scope.read_grants:
            if lookup.get(grant.record_id) is None:
                continue
            records.add(grant.record_id)
            if (
                grant.relation is ReadRelation.CHILDREN
                and entity_type_of(grant.record_id) is EntityType.CUSTOMER
            ):
                customers.add(grant.record_id)
            elif grant.relation is ReadRelation.PARENT:
                parent = lookup.customer_of(grant.record_id)
                if parent:
                    customers.add(parent)
        for customer_id in customers:
            records.add(customer_id)
            for entity in _CHILD_ENTITIES:
                records.update(r.id for r in lookup.children_of(customer_id, entity))
        return cls(customers=frozenset(customers), records=frozenset(records))

    def readable(self, record_id: str) -> bool:
        return record_id in self.records
