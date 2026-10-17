"""Trusted task-scope resolver: a small, transparent, deterministic request grammar.

The scope is derived ONLY from the verbatim trusted user request. It never reads tool
results, CRM free text, scenario labels or private ground truth, so retrieved (possibly
attacker-controlled) data cannot widen authorization.

This grammar is a controlled laboratory approximation, not a general natural-language
authorization system. Requests outside it resolve to a restricted read-only scope with an
explicit failure reason (deny-write by default); intent is never guessed.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable
from decimal import Decimal, InvalidOperation
from enum import StrEnum

from agentshield.crm.tools import READ_TOOL_NAMES
from agentshield.hashing import sha256_text, stable_hash
from agentshield.schemas.common import EntityType, StrictModel, record_ids_in_text
from agentshield.schemas.domain import MAX_MONEY, InvoiceStatus

GRAMMAR_VERSION = "scope-grammar-v1"
MAX_CLAUSES = 3


class TaskIntent(StrEnum):
    SUMMARIZE_INVOICES = "summarize_invoices"
    UPDATE_INVOICE_STATUS = "update_invoice_status"
    UPDATE_OPPORTUNITY_AMOUNT = "update_opportunity_amount"
    SUMMARIZE_OPPORTUNITY = "summarize_opportunity"
    LIST_CASES = "list_cases"
    SEND_CUSTOMER_SUMMARY = "send_customer_summary"
    SUMMARIZE_CUSTOMER = "summarize_customer"


class ScopeResolution(StrEnum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"


class ReadRelation(StrEnum):
    SELF = "self"
    CHILDREN = "children"  # a customer and its invoices/opportunities/cases
    PARENT = "parent"  # a record and its parent customer (resolved via trusted FK)


class ReadGrant(StrictModel):
    record_id: str
    relation: ReadRelation


class WriteGrant(StrictModel):
    tool_name: str
    entity: EntityType
    record_id: str
    field: str
    value: str  # canonical string form, e.g. "Paid" or "75000.00"


class SendGrant(StrictModel):
    recipient_alias: str
    subject_customer_id: str


class TaskScope(StrictModel):
    grammar_version: str = GRAMMAR_VERSION
    request_sha256: str
    resolution: ScopeResolution
    matched_rules: tuple[str, ...] = ()
    intents: tuple[TaskIntent, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    read_grants: tuple[ReadGrant, ...] = ()
    write_grants: tuple[WriteGrant, ...] = ()
    send_grants: tuple[SendGrant, ...] = ()
    failure_reason: str | None = None

    def scope_hash(self) -> str:
        return stable_hash(self)

    @property
    def permits_mutation(self) -> bool:
        return bool(self.write_grants or self.send_grants)


INTENT_TOOLS: dict[TaskIntent, tuple[str, ...]] = {
    TaskIntent.SUMMARIZE_INVOICES: ("get_customer", "list_invoices", "get_invoice"),
    TaskIntent.UPDATE_INVOICE_STATUS: (
        "get_invoice",
        "get_customer",
        "list_invoices",
        "update_invoice_status",
    ),
    TaskIntent.UPDATE_OPPORTUNITY_AMOUNT: (
        "get_opportunity",
        "get_customer",
        "update_opportunity_amount",
    ),
    TaskIntent.SUMMARIZE_OPPORTUNITY: ("get_opportunity", "get_customer"),
    TaskIntent.LIST_CASES: ("get_customer", "list_cases"),
    TaskIntent.SEND_CUSTOMER_SUMMARY: (
        "get_customer",
        "list_invoices",
        "get_invoice",
        "list_cases",
        "send_internal_message",
    ),
    TaskIntent.SUMMARIZE_CUSTOMER: ("get_customer", "list_invoices", "get_invoice", "list_cases"),
}


class _ClauseScope(StrictModel):
    rule: str
    intent: TaskIntent
    reads: tuple[ReadGrant, ...] = ()
    writes: tuple[WriteGrant, ...] = ()
    sends: tuple[SendGrant, ...] = ()


class _ClauseError(ValueError):
    pass


_P = "(?:please )?"
_CUS = r"(?P<cid>cus-\d{3,4})"
_INV = r"(?P<iid>inv-\d{3,4})"
_OPP = r"(?P<oid>opp-\d{3,4})"
_STATUS = r"(?P<status>open|overdue|disputed|paid|void)"
_AMOUNT = r"(?P<amount>\$?\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\$?\d+(?:\.\d{1,2})?)"


def _customer_children(m: re.Match[str]) -> tuple[ReadGrant, ...]:
    return (ReadGrant(record_id=m["cid"].upper(), relation=ReadRelation.CHILDREN),)


def _summarize_invoices(m: re.Match[str]) -> _ClauseScope:
    return _ClauseScope(
        rule="summarize_invoices",
        intent=TaskIntent.SUMMARIZE_INVOICES,
        reads=_customer_children(m),
    )


def _update_invoice_status(m: re.Match[str]) -> _ClauseScope:
    invoice_id = m["iid"].upper()
    status = InvoiceStatus(m["status"].title())
    return _ClauseScope(
        rule="update_invoice_status",
        intent=TaskIntent.UPDATE_INVOICE_STATUS,
        reads=(ReadGrant(record_id=invoice_id, relation=ReadRelation.PARENT),),
        writes=(
            WriteGrant(
                tool_name="update_invoice_status",
                entity=EntityType.INVOICE,
                record_id=invoice_id,
                field="status",
                value=status.value,
            ),
        ),
    )


def _update_opportunity_amount(m: re.Match[str]) -> _ClauseScope:
    opportunity_id = m["oid"].upper()
    raw = m["amount"].replace("$", "").replace(",", "")
    try:
        amount = Decimal(raw).quantize(Decimal("0.01"))
    except InvalidOperation as exc:
        raise _ClauseError(f"unparseable amount {m['amount']!r}") from exc
    if not Decimal(0) < amount <= MAX_MONEY:
        raise _ClauseError(f"amount {amount} outside permitted range")
    return _ClauseScope(
        rule="update_opportunity_amount",
        intent=TaskIntent.UPDATE_OPPORTUNITY_AMOUNT,
        reads=(ReadGrant(record_id=opportunity_id, relation=ReadRelation.PARENT),),
        writes=(
            WriteGrant(
                tool_name="update_opportunity_amount",
                entity=EntityType.OPPORTUNITY,
                record_id=opportunity_id,
                field="amount",
                value=str(amount),
            ),
        ),
    )


def _summarize_opportunity(m: re.Match[str]) -> _ClauseScope:
    return _ClauseScope(
        rule="summarize_opportunity",
        intent=TaskIntent.SUMMARIZE_OPPORTUNITY,
        reads=(ReadGrant(record_id=m["oid"].upper(), relation=ReadRelation.PARENT),),
    )


def _list_cases(m: re.Match[str]) -> _ClauseScope:
    return _ClauseScope(
        rule="list_cases", intent=TaskIntent.LIST_CASES, reads=_customer_children(m)
    )


def _send_customer_summary(m: re.Match[str]) -> _ClauseScope:
    customer_id = m["cid"].upper()
    return _ClauseScope(
        rule="send_customer_summary",
        intent=TaskIntent.SEND_CUSTOMER_SUMMARY,
        reads=_customer_children(m),
        sends=(SendGrant(recipient_alias=m["alias"].lower(), subject_customer_id=customer_id),),
    )


def _summarize_customer(m: re.Match[str]) -> _ClauseScope:
    return _ClauseScope(
        rule="summarize_customer",
        intent=TaskIntent.SUMMARIZE_CUSTOMER,
        reads=_customer_children(m),
    )


_RULES: tuple[tuple[re.Pattern[str], Callable[[re.Match[str]], _ClauseScope]], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), builder)
    for pattern, builder in (
        (
            _P + r"summari[sz]e (?:all |the )?"
            r"(?:(?:unpaid|open|overdue|outstanding|paid|disputed) )?"
            r"invoices (?:for|of) customer " + _CUS,
            _summarize_invoices,
        ),
        (
            _P
            + r"(?:change|set|update) (?:the )?(?:status of )?invoice "
            + _INV
            + r"(?: status)? to "
            + _STATUS,
            _update_invoice_status,
        ),
        (_P + r"mark invoice " + _INV + r" as " + _STATUS, _update_invoice_status),
        (
            _P
            + r"(?:change|set|update) (?:the )?(?:amount of )?opportunity "
            + _OPP
            + r"(?: amount)? to "
            + _AMOUNT,
            _update_opportunity_amount,
        ),
        (_P + r"summari[sz]e opportunity " + _OPP, _summarize_opportunity),
        (
            _P + r"list (?:all |the )?(?:(?:open|closed|escalated) )?(?:support )?"
            r"cases for customer " + _CUS,
            _list_cases,
        ),
        (
            _P
            + r"send an? (?:brief |short )?internal summary of customer "
            + _CUS
            + r" to (?P<alias>[a-z][a-z0-9-]{1,62})",
            _send_customer_summary,
        ),
        (
            _P + r"summari[sz]e (?:the )?(?:account (?:for|of) )?customer " + _CUS,
            _summarize_customer,
        ),
    )
)

_CLAUSE_SPLIT = re.compile(r"\.\s+|;\s*|,\s*(?:and\s+)?then\s+|\s+and\s+then\s+", re.IGNORECASE)
_LEADING_CONNECTIVE = re.compile(r"^(?:and then|then|also)\s+", re.IGNORECASE)


def normalize_request(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return re.sub(r"\s+", " ", text).strip()


def split_clauses(text: str) -> list[str]:
    clauses = []
    for part in _CLAUSE_SPLIT.split(normalize_request(text)):
        part = _LEADING_CONNECTIVE.sub("", part.strip()).rstrip(".!").strip()
        if part:
            clauses.append(part)
    return clauses


def _parse_clause(clause: str) -> _ClauseScope | None:
    for pattern, builder in _RULES:
        match = pattern.fullmatch(clause)
        if match:
            return builder(match)
    return None


def resolve_task_scope(user_request: str) -> TaskScope:
    """Derive the trusted task scope from the verbatim user request (pure function)."""
    request_hash = sha256_text(user_request)
    clauses = split_clauses(user_request)
    if not clauses:
        return _restricted(user_request, request_hash, ScopeResolution.UNRESOLVED, "empty request")
    if len(clauses) > MAX_CLAUSES:
        return _restricted(
            user_request, request_hash, ScopeResolution.UNRESOLVED, "too many clauses"
        )

    parsed: list[_ClauseScope] = []
    for index, clause in enumerate(clauses, start=1):
        try:
            result = _parse_clause(clause)
        except _ClauseError as exc:
            return _restricted(
                user_request, request_hash, ScopeResolution.AMBIGUOUS, f"clause {index}: {exc}"
            )
        if result is None:
            return _restricted(
                user_request,
                request_hash,
                ScopeResolution.UNRESOLVED,
                f"clause {index} not in grammar {GRAMMAR_VERSION}",
            )
        parsed.append(result)

    writes = _dedupe(w for c in parsed for w in c.writes)
    targets: dict[tuple[str, str, str], str] = {}
    for grant in writes:
        key = (grant.tool_name, grant.record_id, grant.field)
        if key in targets and targets[key] != grant.value:
            return _restricted(
                user_request,
                request_hash,
                ScopeResolution.AMBIGUOUS,
                f"conflicting values requested for {grant.record_id}.{grant.field}",
            )
        targets[key] = grant.value

    intents = _dedupe(c.intent for c in parsed)
    tools = sorted({tool for intent in intents for tool in INTENT_TOOLS[intent]})
    return TaskScope(
        request_sha256=request_hash,
        resolution=ScopeResolution.RESOLVED,
        matched_rules=tuple(c.rule for c in parsed),
        intents=intents,
        allowed_tools=tuple(tools),
        read_grants=_dedupe(r for c in parsed for r in c.reads),
        write_grants=writes,
        send_grants=_dedupe(s for c in parsed for s in c.sends),
    )


def _dedupe[T](items: Iterable[T]) -> tuple[T, ...]:
    seen: dict[T, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return tuple(seen)


def _restricted(
    user_request: str, request_hash: str, resolution: ScopeResolution, reason: str
) -> TaskScope:
    """Deny-write fallback: read-only tools, reads limited to records the user named."""
    reads = []
    for record_id in record_ids_in_text(user_request):
        if record_id.startswith("CUS-"):
            reads.append(ReadGrant(record_id=record_id, relation=ReadRelation.CHILDREN))
        elif not record_id.startswith("MSG-"):
            reads.append(ReadGrant(record_id=record_id, relation=ReadRelation.PARENT))
    return TaskScope(
        request_sha256=request_hash,
        resolution=resolution,
        allowed_tools=tuple(sorted(READ_TOOL_NAMES)),
        read_grants=tuple(reads),
        failure_reason=reason,
    )
