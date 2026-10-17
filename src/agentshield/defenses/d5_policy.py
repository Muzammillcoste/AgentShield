"""D5 — deterministic policy gateway (wraps `auth.policy.PolicyEngine` as an action gate)."""

from __future__ import annotations

from agentshield.auth.policy import PolicyEngine
from agentshield.auth.reach import RecordLookup
from agentshield.auth.scope_resolver import TaskScope
from agentshield.crm.dispatcher import ActionRequest, GateDecision
from agentshield.schemas.experiment import D5Granularity


class PolicyGate:
    gate_id = "D5"
    enforces_tenant = True  # tenant confinement is part of every D5 level

    def __init__(self, scope: TaskScope, granularity: D5Granularity, lookup: RecordLookup) -> None:
        self.engine = PolicyEngine(scope, granularity, lookup)

    def evaluate(self, request: ActionRequest) -> GateDecision:
        return self.engine.evaluate(request)
