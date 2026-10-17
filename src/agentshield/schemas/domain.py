"""Synthetic CRM domain entities and trusted identity records."""

from __future__ import annotations

from datetime import date
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, Field, StringConstraints, field_validator

from agentshield.schemas.common import (
    CaseId,
    CustomerId,
    InvoiceId,
    MessageId,
    OpportunityId,
    PrincipalId,
    RecipientAliasName,
    StrictModel,
    TenantId,
)

_CENT = Decimal("0.01")
MAX_MONEY = Decimal("100000000.00")
MAX_FREE_TEXT = 2000


def _quantize_money(value: Decimal) -> Decimal:
    return value.quantize(_CENT, rounding=ROUND_HALF_UP)


Money = Annotated[Decimal, Field(ge=0, le=MAX_MONEY), AfterValidator(_quantize_money)]
FreeText = Annotated[str, StringConstraints(max_length=MAX_FREE_TEXT)]
SyntheticEmail = Annotated[
    str,
    # RFC 2606 reserves `.example`; enforcing it guarantees no real mailbox is referenced.
    StringConstraints(pattern=r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.example$"),
]


class Role(StrEnum):
    SALES_REP = "sales_rep"
    SALES_MANAGER = "sales_manager"
    FINANCE_CLERK = "finance_clerk"
    SUPPORT_AGENT = "support_agent"
    AUDITOR = "auditor"


class Capability(StrEnum):
    """General role abilities (level (a) in the D5 hierarchy). Never proof of task intent."""

    READ_CUSTOMERS = "read_customers"
    READ_INVOICES = "read_invoices"
    READ_OPPORTUNITIES = "read_opportunities"
    READ_CASES = "read_cases"
    UPDATE_INVOICE_STATUS = "update_invoice_status"
    UPDATE_OPPORTUNITY_AMOUNT = "update_opportunity_amount"
    SEND_INTERNAL_MESSAGE = "send_internal_message"


class CustomerTier(StrEnum):
    STANDARD = "Standard"
    PREMIUM = "Premium"
    ENTERPRISE = "Enterprise"


class InvoiceStatus(StrEnum):
    OPEN = "Open"
    OVERDUE = "Overdue"
    DISPUTED = "Disputed"
    PAID = "Paid"
    VOID = "Void"


# "Unpaid" is defined explicitly so answer grading does not depend on interpretation.
UNPAID_INVOICE_STATUSES: frozenset[InvoiceStatus] = frozenset(
    {InvoiceStatus.OPEN, InvoiceStatus.OVERDUE, InvoiceStatus.DISPUTED}
)


class Currency(StrEnum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"


class OpportunityStage(StrEnum):
    PROSPECTING = "Prospecting"
    QUALIFICATION = "Qualification"
    PROPOSAL = "Proposal"
    NEGOTIATION = "Negotiation"
    CLOSED_WON = "Closed Won"
    CLOSED_LOST = "Closed Lost"


class CaseStatus(StrEnum):
    NEW = "New"
    OPEN = "Open"
    PENDING = "Pending"
    ESCALATED = "Escalated"
    CLOSED = "Closed"


OPEN_CASE_STATUSES: frozenset[CaseStatus] = frozenset(
    {CaseStatus.NEW, CaseStatus.OPEN, CaseStatus.PENDING, CaseStatus.ESCALATED}
)


class CasePriority(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    URGENT = "Urgent"


class AliasKind(StrEnum):
    INTERNAL_TEAM = "internal_team"
    # A simulated bridge that, in a real deployment, would leave the tenant boundary.
    # Sending here is still only a local recorded event; it exists to model S4 disclosure.
    EXTERNAL_BRIDGE = "external_bridge"


class Tenant(StrictModel):
    id: TenantId
    name: str


class Principal(StrictModel):
    """Authenticated synthetic user. Trusted fixture data; never derived from tool output."""

    id: PrincipalId
    display_name: str
    role: Role
    tenant_id: TenantId
    capabilities: tuple[Capability, ...]

    @field_validator("capabilities")
    @classmethod
    def _sorted_unique(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        return tuple(sorted(set(value)))

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities


class RecipientAlias(StrictModel):
    alias: RecipientAliasName
    tenant_id: TenantId
    kind: AliasKind
    description: str


class Customer(StrictModel):
    id: CustomerId
    tenant_id: TenantId
    name: str
    tier: CustomerTier
    contact_email: SyntheticEmail


class Invoice(StrictModel):
    id: InvoiceId
    tenant_id: TenantId
    customer_id: CustomerId
    total: Money
    currency: Currency
    due_date: date
    status: InvoiceStatus
    notes: FreeText = ""


class Opportunity(StrictModel):
    id: OpportunityId
    tenant_id: TenantId
    customer_id: CustomerId
    name: str
    amount: Money
    stage: OpportunityStage
    description: FreeText = ""


class SupportCase(StrictModel):
    id: CaseId
    tenant_id: TenantId
    customer_id: CustomerId
    subject: str
    priority: CasePriority
    status: CaseStatus
    description: FreeText = ""


class InternalMessage(StrictModel):
    """A locally recorded message event. Nothing is ever delivered anywhere."""

    id: MessageId
    tenant_id: TenantId
    recipient_alias: RecipientAliasName
    body: Annotated[str, StringConstraints(min_length=1, max_length=4000)]
    sent_by_agent: bool
    sender_principal_id: PrincipalId | None = None
