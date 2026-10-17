from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentshield.auth.principals import ROLE_CAPABILITIES
from agentshield.crm.fixtures import CRMFixture, build_fixture_v1, dump_fixture, load_fixture
from agentshield.schemas.domain import (
    UNPAID_INVOICE_STATUSES,
    AliasKind,
    Capability,
    InvoiceStatus,
)
from tests.conftest import FIXTURE_PATH


def test_committed_fixture_matches_deterministic_regeneration(tmp_path: Path) -> None:
    fresh = build_fixture_v1()
    out = tmp_path / "fixture.json"
    dump_fixture(fresh, out)
    committed = FIXTURE_PATH.read_bytes().replace(b"\r\n", b"\n")
    assert out.read_bytes() == committed
    assert fresh.fixture_hash() == load_fixture(FIXTURE_PATH).fixture_hash()


def test_fixture_hash_is_stable_across_loads(fixture: CRMFixture) -> None:
    assert fixture.fixture_hash() == load_fixture(FIXTURE_PATH).fixture_hash()


def test_fixture_shape(fixture: CRMFixture) -> None:
    assert {t.id for t in fixture.tenants} == {"T1", "T2"}
    assert len({p.role for p in fixture.principals}) >= 3
    assert any(a.kind is AliasKind.EXTERNAL_BRIDGE for a in fixture.aliases)
    # Write operations must be legitimately possible for some principals.
    writers = [p for p in fixture.principals if Capability.UPDATE_INVOICE_STATUS in p.capabilities]
    assert writers and any(
        Capability.UPDATE_OPPORTUNITY_AMOUNT in p.capabilities for p in fixture.principals
    )
    for principal in fixture.principals:
        assert principal.capabilities == tuple(sorted(ROLE_CAPABILITIES[principal.role]))


def test_every_customer_has_paid_and_unpaid_invoices(fixture: CRMFixture) -> None:
    for customer in fixture.customers:
        statuses = {i.status for i in fixture.invoices if i.customer_id == customer.id}
        assert InvoiceStatus.PAID in statuses
        assert statuses & UNPAID_INVOICE_STATUSES
        assert any(o.customer_id == customer.id for o in fixture.opportunities)
        assert any(c.customer_id == customer.id for c in fixture.cases)


def test_fixture_is_synthetic(fixture: CRMFixture) -> None:
    assert all(c.contact_email.endswith(".example") for c in fixture.customers)
    assert "synthetic" in fixture.description.lower()


def _fixture_dict(fixture: CRMFixture) -> dict[str, Any]:
    return fixture.model_dump(mode="json")


def test_integrity_rejects_duplicate_ids(fixture: CRMFixture) -> None:
    data = _fixture_dict(fixture)
    data["invoices"].append(data["invoices"][0])
    with pytest.raises(ValidationError, match="duplicate invoice"):
        CRMFixture.model_validate(data)


def test_integrity_rejects_unknown_customer_and_tenant_mismatch(fixture: CRMFixture) -> None:
    data = _fixture_dict(fixture)
    data["invoices"][0]["customer_id"] = "CUS-999"
    with pytest.raises(ValidationError, match="unknown CUS-999"):
        CRMFixture.model_validate(data)
    data = _fixture_dict(fixture)
    data["invoices"][0]["tenant_id"] = "T2"
    with pytest.raises(ValidationError, match="tenant differs"):
        CRMFixture.model_validate(data)
