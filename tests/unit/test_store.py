from __future__ import annotations

from decimal import Decimal

import pytest

from agentshield.crm.fixtures import CRMFixture
from agentshield.crm.store import CRMStore, RecordNotFoundError, diff_states, initial_state
from agentshield.schemas.common import EntityType
from agentshield.schemas.domain import InvoiceStatus


def test_fresh_stores_are_isolated(fixture: CRMFixture) -> None:
    first = CRMStore.from_fixture(fixture)
    first.set_invoice_status("INV-003", InvoiceStatus.PAID)
    second = CRMStore.from_fixture(fixture)
    assert second.invoice("INV-003").status is InvoiceStatus.OVERDUE  # type: ignore[union-attr]
    assert second.snapshot().state_hash() == initial_state(fixture).state_hash()


def test_snapshot_is_not_affected_by_later_mutation(store: CRMStore) -> None:
    before = store.snapshot()
    store.set_invoice_status("INV-003", InvoiceStatus.PAID)
    assert before.invoices["INV-003"].status is InvoiceStatus.OVERDUE
    assert store.snapshot().invoices["INV-003"].status is InvoiceStatus.PAID


def test_reads_do_not_change_state_hash(store: CRMStore) -> None:
    h = store.snapshot().state_hash()
    store.customer("CUS-001")
    store.children_of("CUS-001", EntityType.INVOICE)
    assert store.snapshot().state_hash() == h


def test_update_returns_field_level_change_and_diff_agrees(store: CRMStore) -> None:
    before = store.snapshot()
    changes = store.set_invoice_status("INV-003", InvoiceStatus.PAID)
    assert len(changes) == 1
    change = changes[0]
    assert (change.entity, change.record_id, change.field) == (
        EntityType.INVOICE,
        "INV-003",
        "status",
    )
    assert (change.change, change.before, change.after) == ("updated", "Overdue", "Paid")
    assert diff_states(before, store.snapshot()) == changes


def test_noop_update_produces_no_diff(store: CRMStore) -> None:
    before = store.snapshot()
    assert store.set_invoice_status("INV-001", InvoiceStatus.PAID) == ()  # already Paid
    assert diff_states(before, store.snapshot()) == ()


def test_amount_update_and_message_creation_diff(store: CRMStore) -> None:
    before = store.snapshot()
    store.set_opportunity_amount("OPP-001", Decimal("1"))
    message, changes = store.record_message(
        tenant_id="T1",
        recipient_alias="sales-review",
        body="hello",
        sender_principal_id="sales_manager_t1",
    )
    assert message.id == "MSG-001"
    assert {c.field for c in changes} == {
        "tenant_id",
        "recipient_alias",
        "body",
        "sent_by_agent",
        "sender_principal_id",
    }
    assert all(c.change == "created" and c.before is None for c in changes)
    diff = diff_states(before, store.snapshot())
    amount = [c for c in diff if c.entity is EntityType.OPPORTUNITY]
    assert amount[0].after == "1.00" and amount[0].before == "213000.00"
    assert {c.record_id for c in diff if c.entity is EntityType.MESSAGE} == {"MSG-001"}


def test_message_ids_are_sequential_and_deterministic(fixture: CRMFixture) -> None:
    ids = []
    for _ in range(2):
        s = CRMStore.from_fixture(fixture)
        m1, _ = s.record_message(
            tenant_id="T1",
            recipient_alias="finance-ops",
            body="a",
            sender_principal_id="auditor_t1",
        )
        m2, _ = s.record_message(
            tenant_id="T1",
            recipient_alias="finance-ops",
            body="b",
            sender_principal_id="auditor_t1",
        )
        ids.append((m1.id, m2.id))
    assert ids[0] == ids[1] == ("MSG-001", "MSG-002")


def test_missing_record_raises(store: CRMStore) -> None:
    with pytest.raises(RecordNotFoundError):
        store.set_invoice_status("INV-999", InvoiceStatus.PAID)


def test_trusted_foreign_key_lookups(store: CRMStore) -> None:
    assert store.customer_of("INV-003") == "CUS-001"
    assert store.customer_of("CUS-002") == "CUS-002"
    assert store.tenant_of("CUS-013") == "T2"
    assert store.customer_of("INV-999") is None
