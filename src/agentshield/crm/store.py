"""Mutable in-memory CRM state with immutable snapshots and field-level diffs.

Records are frozen Pydantic models, so a snapshot is a cheap copy of the record maps and
can never be mutated through a reference held elsewhere. One store per episode.
"""

from __future__ import annotations

import threading
from decimal import Decimal
from typing import Any

from agentshield.crm.fixtures import CRMFixture
from agentshield.hashing import stable_hash
from agentshield.schemas.common import EntityType, StrictModel, entity_type_of
from agentshield.schemas.domain import (
    Customer,
    InternalMessage,
    Invoice,
    InvoiceStatus,
    Opportunity,
    RecipientAlias,
    SupportCase,
)
from agentshield.schemas.events import StateChange

Record = Customer | Invoice | Opportunity | SupportCase | InternalMessage

_ENTITY_ORDER = (
    EntityType.CUSTOMER,
    EntityType.INVOICE,
    EntityType.OPPORTUNITY,
    EntityType.CASE,
    EntityType.MESSAGE,
)


class CRMState(StrictModel):
    """A point-in-time snapshot. Treat as a value; never mutate its dicts."""

    fixture_id: str
    customers: dict[str, Customer]
    invoices: dict[str, Invoice]
    opportunities: dict[str, Opportunity]
    cases: dict[str, SupportCase]
    messages: dict[str, InternalMessage]
    aliases: dict[str, RecipientAlias]

    def collection(self, entity: EntityType) -> dict[str, Any]:
        collections: dict[EntityType, dict[str, Any]] = {
            EntityType.CUSTOMER: self.customers,
            EntityType.INVOICE: self.invoices,
            EntityType.OPPORTUNITY: self.opportunities,
            EntityType.CASE: self.cases,
            EntityType.MESSAGE: self.messages,
        }
        return collections[entity]

    def state_hash(self) -> str:
        return stable_hash(self)


class RecordNotFoundError(KeyError):
    pass


class CRMStore:
    def __init__(self, state: CRMState) -> None:
        self._fixture_id = state.fixture_id
        self._records: dict[EntityType, dict[str, Any]] = {
            entity: dict(state.collection(entity)) for entity in _ENTITY_ORDER
        }
        self._aliases: dict[str, RecipientAlias] = dict(state.aliases)
        self._lock = threading.RLock()
        self._next_message_number = 1 + max(
            (int(mid.split("-")[1]) for mid in self._records[EntityType.MESSAGE]), default=0
        )

    @classmethod
    def from_fixture(cls, fixture: CRMFixture) -> CRMStore:
        return cls(initial_state(fixture))

    @property
    def lock(self) -> threading.RLock:
        """Held by the dispatcher so authorization and mutation happen atomically."""
        return self._lock

    def snapshot(self) -> CRMState:
        with self._lock:
            return CRMState(
                fixture_id=self._fixture_id,
                customers=dict(self._records[EntityType.CUSTOMER]),
                invoices=dict(self._records[EntityType.INVOICE]),
                opportunities=dict(self._records[EntityType.OPPORTUNITY]),
                cases=dict(self._records[EntityType.CASE]),
                messages=dict(self._records[EntityType.MESSAGE]),
                aliases=dict(self._aliases),
            )

    # ---- reads -----------------------------------------------------------------------

    def get(self, record_id: str) -> Record | None:
        entity = entity_type_of(record_id)
        if entity is None:
            return None
        record: Record | None = self._records[entity].get(record_id)
        return record

    def customer(self, customer_id: str) -> Customer | None:
        return self._records[EntityType.CUSTOMER].get(customer_id)

    def invoice(self, invoice_id: str) -> Invoice | None:
        return self._records[EntityType.INVOICE].get(invoice_id)

    def opportunity(self, opportunity_id: str) -> Opportunity | None:
        return self._records[EntityType.OPPORTUNITY].get(opportunity_id)

    def case(self, case_id: str) -> SupportCase | None:
        return self._records[EntityType.CASE].get(case_id)

    def alias(self, alias: str) -> RecipientAlias | None:
        return self._aliases.get(alias)

    def children_of(self, customer_id: str, entity: EntityType) -> list[Any]:
        records = self._records[entity].values()
        return sorted((r for r in records if r.customer_id == customer_id), key=lambda r: r.id)

    def tenant_of(self, record_id: str) -> str | None:
        record = self.get(record_id)
        return None if record is None else record.tenant_id

    def customer_of(self, record_id: str) -> str | None:
        """Trusted foreign-key lookup (never derived from free-text tool output)."""
        record = self.get(record_id)
        if record is None:
            return None
        if isinstance(record, Customer):
            return record.id
        if isinstance(record, InternalMessage):
            return None
        return record.customer_id

    # ---- mutations ---------------------------------------------------------------------

    def set_invoice_status(self, invoice_id: str, status: InvoiceStatus) -> tuple[StateChange, ...]:
        with self._lock:
            invoice = self.invoice(invoice_id)
            if invoice is None:
                raise RecordNotFoundError(invoice_id)
            return self._replace(EntityType.INVOICE, invoice, {"status": status})

    def set_opportunity_amount(
        self, opportunity_id: str, amount: Decimal
    ) -> tuple[StateChange, ...]:
        with self._lock:
            opportunity = self.opportunity(opportunity_id)
            if opportunity is None:
                raise RecordNotFoundError(opportunity_id)
            return self._replace(EntityType.OPPORTUNITY, opportunity, {"amount": amount})

    def record_message(
        self, *, tenant_id: str, recipient_alias: str, body: str, sender_principal_id: str
    ) -> tuple[InternalMessage, tuple[StateChange, ...]]:
        with self._lock:
            message = InternalMessage(
                id=f"MSG-{self._next_message_number:03d}",
                tenant_id=tenant_id,
                recipient_alias=recipient_alias,
                body=body,
                sent_by_agent=True,
                sender_principal_id=sender_principal_id,
            )
            self._next_message_number += 1
            self._records[EntityType.MESSAGE][message.id] = message
            return message, _record_changes(EntityType.MESSAGE, None, message)

    def _replace(
        self, entity: EntityType, record: Any, update: dict[str, Any]
    ) -> tuple[StateChange, ...]:
        # Re-validate so a mutation can never produce a record the schema would reject.
        new_record = type(record).model_validate({**record.model_dump(), **update})
        self._records[entity][record.id] = new_record
        return _record_changes(entity, record, new_record)


def initial_state(fixture: CRMFixture) -> CRMState:
    return CRMState(
        fixture_id=fixture.fixture_id,
        customers={c.id: c for c in fixture.customers},
        invoices={i.id: i for i in fixture.invoices},
        opportunities={o.id: o for o in fixture.opportunities},
        cases={c.id: c for c in fixture.cases},
        messages={m.id: m for m in fixture.messages},
        aliases={a.alias: a for a in fixture.aliases},
    )


def _record_changes(
    entity: EntityType, before: Any | None, after: Any | None
) -> tuple[StateChange, ...]:
    old = {} if before is None else before.model_dump(mode="json")
    new = {} if after is None else after.model_dump(mode="json")
    reference = after if after is not None else before
    if reference is None:
        return ()
    record_id: str = reference.id
    if before is None:
        kind = "created"
    elif after is None:
        kind = "deleted"
    else:
        kind = "updated"
    changes = []
    for field in sorted(set(old) | set(new)):
        if field == "id" or old.get(field) == new.get(field):
            continue
        changes.append(
            StateChange(
                entity=entity,
                record_id=record_id,
                field=field,
                change=kind,  # type: ignore[arg-type]
                before=old.get(field),
                after=new.get(field),
            )
        )
    return tuple(changes)


def diff_states(before: CRMState, after: CRMState) -> tuple[StateChange, ...]:
    """Normalized field-level diff, ordered by entity, record id and field."""
    changes: list[StateChange] = []
    for entity in _ENTITY_ORDER:
        old, new = before.collection(entity), after.collection(entity)
        for record_id in sorted(set(old) | set(new)):
            o, n = old.get(record_id), new.get(record_id)
            if o != n:
                changes.extend(_record_changes(entity, o, n))
    return tuple(changes)
