from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest
from pydantic import ValidationError

from agentshield.hashing import canonical_json, stable_hash
from agentshield.schemas.common import entity_type_of, record_ids_in_text
from agentshield.schemas.domain import (
    Capability,
    Customer,
    InternalMessage,
    Invoice,
    InvoiceStatus,
    Opportunity,
    Principal,
    Role,
    SupportCase,
)


def _invoice(**overrides: object) -> Invoice:
    data: dict[str, object] = {
        "id": "INV-001",
        "tenant_id": "T1",
        "customer_id": "CUS-001",
        "total": "100.5",
        "currency": "USD",
        "due_date": "2026-10-01",
        "status": "Open",
        "notes": "",
    }
    data.update(overrides)
    return Invoice.model_validate(data)


def test_invoice_roundtrip_and_money_quantized() -> None:
    invoice = _invoice()
    assert invoice.total == Decimal("100.50")
    again = Invoice.model_validate_json(invoice.model_dump_json())
    assert again == invoice
    assert invoice.model_dump(mode="json")["total"] == "100.50"


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": "INV-1"},  # malformed id
        {"id": "inv-001"},  # case-sensitive id
        {"customer_id": "OPP-001"},  # wrong entity id
        {"status": "Settled"},  # invalid status
        {"status": "paid"},  # statuses are exact
        {"total": "-1"},  # negative money
        {"total": "NaN"},
        {"currency": "BTC"},
        {"tenant_id": "tenant1"},
        {"notes": "x" * 2001},  # free text bounded
        {"unexpected": 1},  # unknown field rejected
    ],
)
def test_invoice_rejects_invalid_values(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _invoice(**overrides)


def test_required_fields_enforced() -> None:
    with pytest.raises(ValidationError):
        Invoice.model_validate({"id": "INV-001"})


def test_models_are_frozen() -> None:
    invoice = _invoice()
    with pytest.raises(ValidationError):
        invoice.status = InvoiceStatus.PAID  # type: ignore[misc]


def test_customer_email_must_be_reserved_example_domain() -> None:
    ok = Customer(
        id="CUS-001", tenant_id="T1", name="X", tier="Standard", contact_email="a@x.example"
    )
    assert ok.contact_email.endswith(".example")
    with pytest.raises(ValidationError):
        Customer(
            id="CUS-001", tenant_id="T1", name="X", tier="Standard", contact_email="a@gmail.com"
        )


def test_principal_capabilities_sorted_and_deduplicated() -> None:
    p = Principal(
        id="p_one",
        display_name="P",
        role=Role.AUDITOR,
        tenant_id="T1",
        capabilities=(Capability.READ_INVOICES, Capability.READ_CASES, Capability.READ_INVOICES),
    )
    assert p.capabilities == (Capability.READ_CASES, Capability.READ_INVOICES)
    assert p.has(Capability.READ_CASES) and not p.has(Capability.UPDATE_INVOICE_STATUS)


def test_other_entities_roundtrip() -> None:
    opp = Opportunity(
        id="OPP-001",
        tenant_id="T1",
        customer_id="CUS-001",
        name="n",
        amount=Decimal("5"),
        stage="Closed Won",
        description="d",
    )
    case = SupportCase(
        id="CASE-001",
        tenant_id="T1",
        customer_id="CUS-001",
        subject="s",
        priority="High",
        status="Open",
        description="d",
    )
    msg = InternalMessage(
        id="MSG-001", tenant_id="T1", recipient_alias="sales-review", body="b", sent_by_agent=True
    )
    for model in (opp, case, msg):
        assert type(model).model_validate_json(model.model_dump_json()) == model
    with pytest.raises(ValidationError):
        InternalMessage(
            id="MSG-001",
            tenant_id="T1",
            recipient_alias="Sales Review",
            body="b",
            sent_by_agent=True,
        )


def test_entity_type_and_id_extraction() -> None:
    assert entity_type_of("CASE-010").value == "case"
    assert entity_type_of("XYZ-1") is None
    assert record_ids_in_text("see inv-003 and CUS-001, then INV-003") == ("INV-003", "CUS-001")


def test_canonical_json_is_order_independent() -> None:
    a = {"b": 1, "a": [1, 2], "d": date(2026, 1, 2), "m": Decimal("1.50")}
    b = {"m": Decimal("1.50"), "d": date(2026, 1, 2), "a": [1, 2], "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert stable_hash(a) == stable_hash(b)
    assert canonical_json(frozenset({"z", "a"})) == '["a","z"]'
