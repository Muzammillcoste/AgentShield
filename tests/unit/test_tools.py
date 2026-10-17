from __future__ import annotations

import json

import pytest

from agentshield.crm.store import CRMStore
from agentshield.crm.tools import (
    MUTATING_TOOL_NAMES,
    READ_TOOL_NAMES,
    TOOL_NAMES,
    TOOL_REGISTRY,
    ToolAccess,
    ToolContext,
    ToolErrorCode,
    tool_schemas,
)
from agentshield.schemas.common import EntityType

CTX = ToolContext(principal_id="sales_manager_t1", tenant_id="T1")
SPEC_TOOL_NAMES = (
    "get_customer",
    "list_invoices",
    "get_invoice",
    "get_opportunity",
    "list_cases",
    "update_invoice_status",
    "update_opportunity_amount",
    "send_internal_message",
)


def run(store: CRMStore, name: str, **args: object):  # type: ignore[no-untyped-def]
    spec = TOOL_REGISTRY[name]
    return spec.handler(store, CTX, spec.args_model.model_validate(args))


def test_exact_tool_set_and_access_classes() -> None:
    assert TOOL_NAMES == SPEC_TOOL_NAMES
    assert set(MUTATING_TOOL_NAMES) == {
        "update_invoice_status",
        "update_opportunity_amount",
        "send_internal_message",
    }
    assert set(READ_TOOL_NAMES) | set(MUTATING_TOOL_NAMES) == set(TOOL_NAMES)
    assert TOOL_REGISTRY["send_internal_message"].access is ToolAccess.SIDE_EFFECT


@pytest.mark.parametrize("name", SPEC_TOOL_NAMES)
def test_model_schema_matches_argument_model(name: str) -> None:
    spec = TOOL_REGISTRY[name]
    params = spec.parameters
    assert params["type"] == "object" and params["additionalProperties"] is False
    assert set(params["properties"]) == set(spec.args_model.model_fields)
    assert set(params["required"]) == {
        k for k, f in spec.args_model.model_fields.items() if f.is_required()
    }
    assert spec.target_arg in params["properties"]


def test_descriptions_do_not_reveal_evaluation() -> None:
    for schema in tool_schemas():
        text = (schema.description + json.dumps(schema.parameters)).lower()
        for word in ("simulat", "sandbox", "benchmark", "attack", "inject", "security", "test"):
            assert word not in text, (schema.name, word)


def test_tool_schemas_subset_and_unknown() -> None:
    assert [s.name for s in tool_schemas(["get_invoice", "get_customer"])] == [
        "get_customer",
        "get_invoice",
    ]
    with pytest.raises(KeyError):
        tool_schemas(["delete_everything"])


def test_read_tools_return_json_and_expose_records(store: CRMStore) -> None:
    out = run(store, "list_invoices", customer_id="CUS-001")
    assert out.ok and out.exposed_records == ("INV-001", "INV-002", "INV-003")
    json.dumps(out.payload())  # pure JSON types
    assert out.payload()["data"]["invoices"][2] == {
        "invoice_id": "INV-003",
        "customer_id": "CUS-001",
        "total": "47978.50",
        "currency": "USD",
        "due_date": "2026-08-21",
        "status": "Overdue",
        "notes": "",
    }
    assert run(store, "get_customer", customer_id="CUS-001").data["name"] == "Bluefin Logistics"  # type: ignore[index]
    assert run(store, "get_opportunity", opportunity_id="OPP-003").exposed_records == ("OPP-003",)
    assert run(store, "list_cases", customer_id="CUS-002").exposed_records == (
        "CASE-003",
        "CASE-004",
        "CASE-005",
    )
    assert run(store, "get_invoice", invoice_id="INV-007").data["status"] == "Disputed"  # type: ignore[index]


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("get_customer", {"customer_id": "CUS-999"}),
        ("list_invoices", {"customer_id": "CUS-999"}),
        ("get_invoice", {"invoice_id": "INV-999"}),
        ("get_opportunity", {"opportunity_id": "OPP-999"}),
        ("list_cases", {"customer_id": "CUS-999"}),
        ("update_invoice_status", {"invoice_id": "INV-999", "status": "Paid"}),
        ("update_opportunity_amount", {"opportunity_id": "OPP-999", "amount": 5}),
        ("send_internal_message", {"recipient_alias": "nobody-here", "body": "x"}),
    ],
)
def test_not_found_errors_are_structured(
    store: CRMStore, name: str, args: dict[str, object]
) -> None:
    before = store.snapshot().state_hash()
    out = run(store, name, **args)
    assert not out.ok and out.error_code is ToolErrorCode.NOT_FOUND
    assert out.payload()["error"]["code"] == "not_found"
    assert store.snapshot().state_hash() == before


def test_write_tools_mutate_and_report(store: CRMStore) -> None:
    out = run(store, "update_invoice_status", invoice_id="INV-003", status="Paid")
    assert out.data == {"invoice_id": "INV-003", "previous_status": "Overdue", "status": "Paid"}
    assert out.state_changes[0].after == "Paid"
    out = run(store, "update_opportunity_amount", opportunity_id="OPP-004", amount=185000)
    assert out.data["amount"] == "185000.00"  # type: ignore[index]
    out = run(store, "send_internal_message", recipient_alias="sales-review", body="Summary")
    assert out.data == {
        "message_id": "MSG-001",
        "recipient_alias": "sales-review",
        "status": "sent",
    }
    assert store.snapshot().messages["MSG-001"].sender_principal_id == "sales_manager_t1"
    assert any(c.entity is EntityType.MESSAGE for c in out.state_changes)
