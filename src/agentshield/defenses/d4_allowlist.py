"""D4 — task-specific tool allowlisting (tool *names* only).

The visible tool schemas and this name gate both come from the trusted request scope. D4 does
not look at records, fields or values, so a wrong-record call using a legitimately available
tool passes D4 by design (H2).
"""

from __future__ import annotations

from agentshield.auth.scope_resolver import TaskScope
from agentshield.crm.dispatcher import ActionRequest, GateDecision
from agentshield.schemas.events import DecisionKind

D4_VERSION = "d4-v1"


class ToolAllowlistGate:
    gate_id = "D4"

    def __init__(self, scope: TaskScope) -> None:
        self.allowed = frozenset(scope.allowed_tools)

    def evaluate(self, request: ActionRequest) -> GateDecision:
        if request.tool_name in self.allowed:
            return GateDecision(decision=DecisionKind.ALLOW, reason_code="tool_allowed")
        return GateDecision(decision=DecisionKind.DENY, reason_code="tool_not_allowlisted")


def visible_tools(scope: TaskScope) -> tuple[str, ...]:
    return tuple(scope.allowed_tools)
