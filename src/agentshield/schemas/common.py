"""Shared base model, identifier formats and small enums."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, StringConstraints

SCHEMA_VERSION: Final = "1.0"


class StrictModel(BaseModel):
    """Immutable model that rejects unknown fields (typos in data files fail loudly)."""

    model_config = ConfigDict(extra="forbid", frozen=True)


TENANT_ID_PATTERN = r"^T\d$"
PRINCIPAL_ID_PATTERN = r"^[a-z][a-z0-9_]{2,63}$"
CUSTOMER_ID_PATTERN = r"^CUS-\d{3,4}$"
INVOICE_ID_PATTERN = r"^INV-\d{3,4}$"
OPPORTUNITY_ID_PATTERN = r"^OPP-\d{3,4}$"
CASE_ID_PATTERN = r"^CASE-\d{3,4}$"
MESSAGE_ID_PATTERN = r"^MSG-\d{3,4}$"
ALIAS_PATTERN = r"^[a-z][a-z0-9-]{1,62}$"

TenantId = Annotated[str, StringConstraints(pattern=TENANT_ID_PATTERN)]
PrincipalId = Annotated[str, StringConstraints(pattern=PRINCIPAL_ID_PATTERN)]
CustomerId = Annotated[str, StringConstraints(pattern=CUSTOMER_ID_PATTERN)]
InvoiceId = Annotated[str, StringConstraints(pattern=INVOICE_ID_PATTERN)]
OpportunityId = Annotated[str, StringConstraints(pattern=OPPORTUNITY_ID_PATTERN)]
CaseId = Annotated[str, StringConstraints(pattern=CASE_ID_PATTERN)]
MessageId = Annotated[str, StringConstraints(pattern=MESSAGE_ID_PATTERN)]
RecipientAliasName = Annotated[str, StringConstraints(pattern=ALIAS_PATTERN)]

# JSON scalar used in state diffs and change patterns (Decimal/date values are strings).
JsonScalar = str | int | float | bool | None


class EntityType(StrEnum):
    CUSTOMER = "customer"
    INVOICE = "invoice"
    OPPORTUNITY = "opportunity"
    CASE = "case"
    MESSAGE = "message"


_ID_PATTERNS: dict[EntityType, re.Pattern[str]] = {
    EntityType.CUSTOMER: re.compile(CUSTOMER_ID_PATTERN),
    EntityType.INVOICE: re.compile(INVOICE_ID_PATTERN),
    EntityType.OPPORTUNITY: re.compile(OPPORTUNITY_ID_PATTERN),
    EntityType.CASE: re.compile(CASE_ID_PATTERN),
    EntityType.MESSAGE: re.compile(MESSAGE_ID_PATTERN),
}

# Matches any record identifier embedded in free text (requests, message bodies).
RECORD_ID_IN_TEXT = re.compile(r"\b(?:CUS|INV|OPP|CASE|MSG)-\d{3,4}\b", re.IGNORECASE)


def entity_type_of(record_id: str) -> EntityType | None:
    """Infer the entity type from a record identifier, or None if it is not a known format."""
    for entity, pattern in _ID_PATTERNS.items():
        if pattern.match(record_id):
            return entity
    return None


def record_ids_in_text(text: str) -> tuple[str, ...]:
    """All record identifiers mentioned in ``text``, upper-cased, de-duplicated, in order."""
    seen: dict[str, None] = {}
    for match in RECORD_ID_IN_TEXT.finditer(text):
        seen.setdefault(match.group(0).upper(), None)
    return tuple(seen)
