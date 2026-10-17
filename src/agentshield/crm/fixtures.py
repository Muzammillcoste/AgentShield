"""CRM fixture contract, loader, and the deterministic `crm_fixture_v1` generator.

Every name, email and record is synthetic. Emails use the RFC 2606 `.example` domain.
The generator is seeded and uses a fixed `as_of_date`, so regenerating the fixture is
byte-for-byte reproducible (checked by tests against the committed JSON).
"""

from __future__ import annotations

import json
import random
import re
from collections.abc import Iterable
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

from pydantic import model_validator

from agentshield.auth.principals import ROLE_CAPABILITIES
from agentshield.hashing import canonical_json, stable_hash
from agentshield.schemas.common import SCHEMA_VERSION, StrictModel
from agentshield.schemas.domain import (
    AliasKind,
    CasePriority,
    CaseStatus,
    Currency,
    Customer,
    CustomerTier,
    InternalMessage,
    Invoice,
    InvoiceStatus,
    Opportunity,
    OpportunityStage,
    Principal,
    RecipientAlias,
    Role,
    SupportCase,
    Tenant,
)


class CRMFixture(StrictModel):
    schema_version: str = SCHEMA_VERSION
    fixture_id: str
    description: str
    as_of_date: date
    tenants: tuple[Tenant, ...]
    principals: tuple[Principal, ...]
    aliases: tuple[RecipientAlias, ...]
    customers: tuple[Customer, ...]
    invoices: tuple[Invoice, ...]
    opportunities: tuple[Opportunity, ...]
    cases: tuple[SupportCase, ...]
    messages: tuple[InternalMessage, ...] = ()

    @model_validator(mode="after")
    def _check_integrity(self) -> CRMFixture:
        tenant_ids = _unique("tenant", (t.id for t in self.tenants))
        _unique("principal", (p.id for p in self.principals))
        _unique("alias", (a.alias for a in self.aliases))
        customer_tenant = {c.id: c.tenant_id for c in self.customers}
        _unique("customer", (c.id for c in self.customers))
        for group, records in (
            ("invoice", self.invoices),
            ("opportunity", self.opportunities),
            ("case", self.cases),
        ):
            _unique(group, (r.id for r in records))
            for record in records:
                if record.customer_id not in customer_tenant:
                    raise ValueError(f"{record.id} references unknown {record.customer_id}")
                if customer_tenant[record.customer_id] != record.tenant_id:
                    raise ValueError(f"{record.id} tenant differs from its customer's tenant")
        referenced = [x.tenant_id for x in self.principals] + [x.tenant_id for x in self.aliases]
        for tenant_id in referenced + [x.tenant_id for x in self.customers]:
            if tenant_id not in tenant_ids:
                raise ValueError(f"unknown tenant {tenant_id!r}")
        _unique("message", (m.id for m in self.messages))
        return self

    def fixture_hash(self) -> str:
        return stable_hash(self)


def _unique(kind: str, ids: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    for item in ids:
        if item in seen:
            raise ValueError(f"duplicate {kind} id {item!r}")
        seen.add(item)
    return seen


def load_fixture(path: str | Path) -> CRMFixture:
    return CRMFixture.model_validate_json(Path(path).read_text(encoding="utf-8"))


def dump_fixture(fixture: CRMFixture, path: str | Path) -> None:
    """Pretty, key-sorted JSON so diffs are reviewable and output is reproducible."""
    data = json.loads(canonical_json(fixture))
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------------------
# Deterministic generator for crm_fixture_v1
# --------------------------------------------------------------------------------------

FIXTURE_V1_ID = "crm_fixture_v1"
FIXTURE_V1_SEED = 20260930
FIXTURE_V1_AS_OF = date(2026, 9, 30)

_TENANTS = (
    Tenant(id="T1", name="Halcyon Analytics (synthetic tenant)"),
    Tenant(id="T2", name="Meridian Supply (synthetic tenant)"),
)

_PRINCIPALS: tuple[tuple[str, str, Role, str], ...] = (
    ("sales_manager_t1", "Synthetic Sales Manager (T1)", Role.SALES_MANAGER, "T1"),
    ("sales_rep_t1", "Synthetic Sales Rep (T1)", Role.SALES_REP, "T1"),
    ("finance_clerk_t1", "Synthetic Finance Clerk (T1)", Role.FINANCE_CLERK, "T1"),
    ("support_agent_t1", "Synthetic Support Agent (T1)", Role.SUPPORT_AGENT, "T1"),
    ("auditor_t1", "Synthetic Auditor (T1)", Role.AUDITOR, "T1"),
    ("sales_manager_t2", "Synthetic Sales Manager (T2)", Role.SALES_MANAGER, "T2"),
    ("finance_clerk_t2", "Synthetic Finance Clerk (T2)", Role.FINANCE_CLERK, "T2"),
    ("support_agent_t2", "Synthetic Support Agent (T2)", Role.SUPPORT_AGENT, "T2"),
)

_ALIASES: tuple[tuple[str, str, AliasKind, str], ...] = (
    ("sales-review", "T1", AliasKind.INTERNAL_TEAM, "Weekly sales pipeline review group"),
    ("finance-ops", "T1", AliasKind.INTERNAL_TEAM, "Accounts receivable operations team"),
    ("support-leads", "T1", AliasKind.INTERNAL_TEAM, "Support team leads"),
    ("exec-briefing", "T1", AliasKind.INTERNAL_TEAM, "Executive briefing distribution list"),
    ("partner-sync", "T1", AliasKind.EXTERNAL_BRIDGE, "Bridge to a reseller partner workspace"),
    ("meridian-sales", "T2", AliasKind.INTERNAL_TEAM, "Meridian sales team"),
    ("meridian-finance", "T2", AliasKind.INTERNAL_TEAM, "Meridian finance team"),
    (
        "meridian-partner-sync",
        "T2",
        AliasKind.EXTERNAL_BRIDGE,
        "Bridge to a Meridian logistics partner workspace",
    ),
)

_CUSTOMER_NAMES: dict[str, tuple[str, ...]] = {
    "T1": (
        "Bluefin Logistics",
        "Cedar Ridge Dental Group",
        "Harbor & Pike Outfitters",
        "Lumen Grove Schools",
        "Orchid Lane Florists",
        "Quarry Peak Construction",
        "Silverline Clinics",
        "Tidewater Brewing Co",
        "Upland Solar Cooperative",
        "Verdant Labs",
        "Willow Creek Veterinary",
        "Zephyr Bike Works",
    ),
    "T2": (
        "Amberly Textiles",
        "Brightwater Utilities",
        "Copperleaf Hotels",
        "Driftwood Marine Supply",
        "Emberfield Bakery",
        "Foxglove Pharmacy",
        "Granite Bay Storage",
        "Hollow Oak Furniture",
    ),
}

_TIERS = (
    CustomerTier.STANDARD,
    CustomerTier.PREMIUM,
    CustomerTier.ENTERPRISE,
    CustomerTier.STANDARD,
)

# Cyclic so any 3 consecutive invoices contain at least one paid and one unpaid status.
_INVOICE_STATUS_CYCLE = (
    InvoiceStatus.PAID,
    InvoiceStatus.OPEN,
    InvoiceStatus.OVERDUE,
    InvoiceStatus.PAID,
    InvoiceStatus.DISPUTED,
)

_INVOICE_NOTES = (
    "",
    "Net 30 payment terms.",
    "PO 4471 referenced on remittance advice.",
    "Partial shipment; balance invoiced separately.",
    "Tax-exempt certificate on file.",
    "Annual subscription, billed in advance.",
    "Includes onboarding services (8 hours).",
    "5% discount applied per renewal agreement.",
    "Remittance expected via ACH.",
    "Quarterly usage true-up.",
    "Consolidated billing for three sites.",
)

_OPP_PRODUCTS = (
    "Analytics seats expansion",
    "Data platform migration",
    "Premium support renewal",
    "Regional rollout",
    "Forecasting add-on",
    "Training package",
    "Multi-year renewal",
    "Integration services",
)

_OPP_DESCRIPTIONS = (
    "Champion is the operations director; budget approved for next quarter.",
    "Competing evaluation underway; pricing review scheduled.",
    "Expansion tied to a new regional office opening.",
    "Renewal with a possible seat increase.",
    "Technical validation complete; awaiting procurement.",
    "Pilot ran for 60 days with positive feedback.",
    "Legal review of the master agreement in progress.",
    "Budget holder changed recently; re-qualification needed.",
)

_OPP_STAGES = (
    OpportunityStage.PROSPECTING,
    OpportunityStage.QUALIFICATION,
    OpportunityStage.PROPOSAL,
    OpportunityStage.NEGOTIATION,
    OpportunityStage.CLOSED_WON,
    OpportunityStage.PROPOSAL,
    OpportunityStage.CLOSED_LOST,
)

_CASES = (
    ("CSV export times out", "Exports covering large date ranges time out after 60 seconds."),
    ("Login issue for new users", "Two newly provisioned users cannot complete sign-in."),
    ("Invoice PDF formatting", "Line items wrap incorrectly on the PDF version of invoices."),
    ("Dashboard data delay", "Dashboard metrics lag roughly two hours behind source data."),
    ("Reporting API limits", "Customer asked about rate limits for the reporting API."),
    ("Billing contact update", "Customer wants the billing contact changed to their AP mailbox."),
    ("Scheduled report failure", "The scheduled weekly report did not run on Monday."),
    ("SSO feature request", "Customer requested SAML single sign-on support."),
)

_CASE_STATUSES = (
    CaseStatus.OPEN,
    CaseStatus.PENDING,
    CaseStatus.ESCALATED,
    CaseStatus.CLOSED,
    CaseStatus.NEW,
)

_CASE_PRIORITIES = (CasePriority.MEDIUM, CasePriority.HIGH, CasePriority.LOW, CasePriority.URGENT)


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower().replace("&", "and")).strip("-")


def _due_date(rng: random.Random, status: InvoiceStatus, as_of: date) -> date:
    offsets = {
        InvoiceStatus.OPEN: rng.randint(3, 60),
        InvoiceStatus.OVERDUE: -rng.randint(5, 90),
        InvoiceStatus.DISPUTED: -rng.randint(1, 45),
        InvoiceStatus.PAID: -rng.randint(10, 120),
        InvoiceStatus.VOID: -rng.randint(20, 150),
    }
    return as_of + timedelta(days=offsets[status])


def build_fixture_v1(seed: int = FIXTURE_V1_SEED, as_of: date = FIXTURE_V1_AS_OF) -> CRMFixture:
    rng = random.Random(seed)
    principals = tuple(
        Principal(
            id=pid,
            display_name=name,
            role=role,
            tenant_id=tenant,
            capabilities=ROLE_CAPABILITIES[role],
        )
        for pid, name, role, tenant in _PRINCIPALS
    )
    aliases = tuple(
        RecipientAlias(alias=alias, tenant_id=tenant, kind=kind, description=desc)
        for alias, tenant, kind, desc in _ALIASES
    )

    customers: list[Customer] = []
    invoices: list[Invoice] = []
    opportunities: list[Opportunity] = []
    cases: list[SupportCase] = []

    customer_index = 0
    for tenant in _TENANTS:
        for name in _CUSTOMER_NAMES[tenant.id]:
            customer_index += 1
            idx = customer_index - 1
            cid = f"CUS-{customer_index:03d}"
            customers.append(
                Customer(
                    id=cid,
                    tenant_id=tenant.id,
                    name=name,
                    tier=_TIERS[idx % len(_TIERS)],
                    contact_email=f"billing@{_slug(name)}.example",
                )
            )

            currency = Currency.USD
            if idx % 5 == 4:
                currency = Currency.EUR if tenant.id == "T1" else Currency.GBP
            for k in range(3 + idx % 3):
                status = _INVOICE_STATUS_CYCLE[(k + idx) % len(_INVOICE_STATUS_CYCLE)]
                cents = rng.randrange(45_000, 4_800_000)
                invoices.append(
                    Invoice(
                        id=f"INV-{len(invoices) + 1:03d}",
                        tenant_id=tenant.id,
                        customer_id=cid,
                        total=Decimal(cents) / 100,
                        currency=currency,
                        due_date=_due_date(rng, status, as_of),
                        status=status,
                        notes=rng.choice(_INVOICE_NOTES),
                    )
                )

            for _ in range(1 + idx % 2):
                n = len(opportunities)
                opportunities.append(
                    Opportunity(
                        id=f"OPP-{n + 1:03d}",
                        tenant_id=tenant.id,
                        customer_id=cid,
                        name=f"{name} - {_OPP_PRODUCTS[n % len(_OPP_PRODUCTS)]}",
                        amount=Decimal(rng.randrange(10, 500) * 500),
                        stage=_OPP_STAGES[n % len(_OPP_STAGES)],
                        description=rng.choice(_OPP_DESCRIPTIONS),
                    )
                )

            for _ in range(1 + (idx + 1) % 3):
                n = len(cases)
                subject, description = _CASES[(n * 3 + idx) % len(_CASES)]
                cases.append(
                    SupportCase(
                        id=f"CASE-{n + 1:03d}",
                        tenant_id=tenant.id,
                        customer_id=cid,
                        subject=subject,
                        priority=_CASE_PRIORITIES[n % len(_CASE_PRIORITIES)],
                        status=_CASE_STATUSES[n % len(_CASE_STATUSES)],
                        description=description,
                    )
                )

    return CRMFixture(
        fixture_id=FIXTURE_V1_ID,
        description=(
            "Fully synthetic two-tenant CRM fixture for AgentShield. No real organizations, "
            "people, accounts or credentials. Generated by scripts/generate_fixtures.py."
        ),
        as_of_date=as_of,
        tenants=_TENANTS,
        principals=principals,
        aliases=aliases,
        customers=tuple(customers),
        invoices=tuple(invoices),
        opportunities=tuple(opportunities),
        cases=tuple(cases),
    )
