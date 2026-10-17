"""Trusted identity store: synthetic principals and their *general* role abilities.

A capability here is level (a) of the D5 hierarchy: what the role may do in general.
It is never evidence that the current request asked for a specific action.
"""

from __future__ import annotations

from collections.abc import Iterable

from agentshield.schemas.domain import Capability, Principal, Role

_ALL_READS = (
    Capability.READ_CUSTOMERS,
    Capability.READ_INVOICES,
    Capability.READ_OPPORTUNITIES,
    Capability.READ_CASES,
)

ROLE_CAPABILITIES: dict[Role, tuple[Capability, ...]] = {
    Role.SALES_REP: (
        *_ALL_READS,
        Capability.UPDATE_OPPORTUNITY_AMOUNT,
        Capability.SEND_INTERNAL_MESSAGE,
    ),
    Role.SALES_MANAGER: (
        *_ALL_READS,
        Capability.UPDATE_INVOICE_STATUS,
        Capability.UPDATE_OPPORTUNITY_AMOUNT,
        Capability.SEND_INTERNAL_MESSAGE,
    ),
    Role.FINANCE_CLERK: (
        Capability.READ_CUSTOMERS,
        Capability.READ_INVOICES,
        Capability.UPDATE_INVOICE_STATUS,
        Capability.SEND_INTERNAL_MESSAGE,
    ),
    Role.SUPPORT_AGENT: (
        Capability.READ_CUSTOMERS,
        Capability.READ_CASES,
        Capability.SEND_INTERNAL_MESSAGE,
    ),
    Role.AUDITOR: _ALL_READS,
}


class UnknownPrincipalError(KeyError):
    pass


class PrincipalDirectory:
    """Read-only lookup of authenticated principals loaded from trusted fixture data."""

    def __init__(self, principals: Iterable[Principal]) -> None:
        self._by_id: dict[str, Principal] = {}
        for principal in principals:
            if principal.id in self._by_id:
                raise ValueError(f"duplicate principal id {principal.id!r}")
            self._by_id[principal.id] = principal

    def get(self, principal_id: str) -> Principal:
        try:
            return self._by_id[principal_id]
        except KeyError:
            raise UnknownPrincipalError(principal_id) from None

    def __contains__(self, principal_id: object) -> bool:
        return principal_id in self._by_id

    def all(self) -> tuple[Principal, ...]:
        return tuple(self._by_id[k] for k in sorted(self._by_id))
