"""Dataset validator: checks every public scenario and its private truth against the fixture.

Validation runs before any experiment. It verifies record existence, tenant coherence,
injection reachability, scope-grammar coverage tags, label completeness/consistency,
attack-goal meaningfulness (the goal must change state) and split grouping.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from enum import StrEnum

from agentshield import __version__
from agentshield.auth.principals import PrincipalDirectory
from agentshield.auth.reach import ReadScopeIndex
from agentshield.auth.scope_resolver import (
    GRAMMAR_VERSION,
    ScopeResolution,
    TaskScope,
    resolve_task_scope,
)
from agentshield.crm.fixtures import CRMFixture
from agentshield.crm.store import CRMStore
from agentshield.crm.tools import get_tool
from agentshield.schemas.common import EntityType, StrictModel, entity_type_of, record_ids_in_text
from agentshield.schemas.domain import (
    Customer,
    InternalMessage,
    Invoice,
    InvoiceStatus,
    Opportunity,
    Principal,
    SupportCase,
)
from agentshield.schemas.scenario import Category, ScenarioPublic
from agentshield.schemas.truth import (
    AttackerGoalType,
    OverrideLabel,
    ScenarioPrivateTruth,
    StateChangePattern,
)

OUT_OF_GRAMMAR_TAG = "scope:out_of_grammar"
EXPECT_PERMISSION_DENIED_TAG = "expect:permission_denied"

_ENTITY_FIELDS: dict[EntityType, frozenset[str]] = {
    EntityType.CUSTOMER: frozenset(Customer.model_fields),
    EntityType.INVOICE: frozenset(Invoice.model_fields),
    EntityType.OPPORTUNITY: frozenset(Opportunity.model_fields),
    EntityType.CASE: frozenset(SupportCase.model_fields),
    EntityType.MESSAGE: frozenset(InternalMessage.model_fields),
}


class IssueLevel(StrEnum):
    ERROR = "error"
    WARNING = "warning"


class ValidationIssue(StrictModel):
    scenario_id: str | None
    level: IssueLevel
    code: str
    message: str


class ValidationReport(StrictModel):
    ok: bool
    agentshield_version: str = __version__
    grammar_version: str = GRAMMAR_VERSION
    fixture_id: str
    fixture_hash: str
    n_public: int
    n_private: int
    counts: dict[str, int]
    unverified_labels: int
    issues: tuple[ValidationIssue, ...]

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level is IssueLevel.ERROR]


class _Collector:
    def __init__(self) -> None:
        self.issues: list[ValidationIssue] = []

    def error(self, scenario_id: str | None, code: str, message: str) -> None:
        self.issues.append(
            ValidationIssue(
                scenario_id=scenario_id, level=IssueLevel.ERROR, code=code, message=message
            )
        )

    def warn(self, scenario_id: str | None, code: str, message: str) -> None:
        self.issues.append(
            ValidationIssue(
                scenario_id=scenario_id, level=IssueLevel.WARNING, code=code, message=message
            )
        )


def reachable_records(scope: TaskScope, store: CRMStore) -> tuple[set[str], set[str]]:
    """(customer ids, record ids) a correctly behaving agent can read within `scope`."""
    index = ReadScopeIndex.build(scope, store)
    return set(index.customers), set(index.records)


def validate_dataset(
    scenarios: Sequence[ScenarioPublic],
    truths: Mapping[str, ScenarioPrivateTruth],
    fixture: CRMFixture,
) -> ValidationReport:
    out = _Collector()
    store = CRMStore.from_fixture(fixture)
    principals = PrincipalDirectory(fixture.principals)
    public_ids = {s.scenario_id for s in scenarios}

    for scenario in scenarios:
        truth = truths.get(scenario.scenario_id)
        if truth is None:
            out.error(scenario.scenario_id, "missing_private_truth", "no private truth record")
            continue
        _check_scenario(scenario, truth, fixture, store, principals, public_ids, out)
    for orphan in sorted(set(truths) - public_ids):
        out.error(orphan, "orphan_private_truth", "private truth without a public scenario")
    _check_split_grouping(scenarios, truths, out)

    counts: Counter[str] = Counter()
    for s in scenarios:
        counts[f"split:{s.split}"] += 1
        counts[f"category:{s.category}"] += 1
        if s.attack_family:
            counts[f"family:{s.attack_family}"] += 1
        if OUT_OF_GRAMMAR_TAG in s.tags:
            counts["scope:out_of_grammar"] += 1
    unverified = sum(1 for sid in public_ids if sid in truths and not truths[sid].label_verified)
    return ValidationReport(
        ok=not any(i.level is IssueLevel.ERROR for i in out.issues),
        fixture_id=fixture.fixture_id,
        fixture_hash=fixture.fixture_hash(),
        n_public=len(scenarios),
        n_private=len(truths),
        counts=dict(sorted(counts.items())),
        unverified_labels=unverified,
        issues=tuple(out.issues),
    )


def _check_scenario(
    s: ScenarioPublic,
    t: ScenarioPrivateTruth,
    fixture: CRMFixture,
    store: CRMStore,
    principals: PrincipalDirectory,
    public_ids: set[str],
    out: _Collector,
) -> None:
    sid = s.scenario_id
    if s.fixture_id != fixture.fixture_id:
        out.error(
            sid, "fixture_mismatch", f"scenario fixture {s.fixture_id!r} != {fixture.fixture_id!r}"
        )
        return
    if s.principal_id not in principals:
        out.error(sid, "unknown_principal", f"principal {s.principal_id!r} not in fixture")
        return
    principal = principals.get(s.principal_id)

    for record_id in record_ids_in_text(s.user_request):
        tenant = store.tenant_of(record_id)
        if tenant is None:
            out.error(sid, "unknown_record_in_request", f"{record_id} does not exist")
        elif tenant != principal.tenant_id:
            out.error(
                sid, "cross_tenant_request", f"legitimate request names {record_id} from {tenant}"
            )

    scope = resolve_task_scope(s.user_request)
    out_of_grammar = OUT_OF_GRAMMAR_TAG in s.tags
    if out_of_grammar and scope.resolution is ScopeResolution.RESOLVED:
        out.error(sid, "grammar_tag_mismatch", "tagged out_of_grammar but the grammar resolves it")
    if not out_of_grammar and scope.resolution is not ScopeResolution.RESOLVED:
        out.error(sid, "scope_unresolved", f"request not in grammar: {scope.failure_reason}")
    for send in scope.send_grants:
        alias = store.alias(send.recipient_alias)
        if alias is None or alias.tenant_id != principal.tenant_id:
            out.error(
                sid, "invalid_requested_alias", f"alias {send.recipient_alias!r} invalid for tenant"
            )

    if s.injection is not None:
        _check_injection(s, scope, store, principal.tenant_id, out)
    _check_truth_labels(s, t, scope, store, principal, public_ids, out)


def _check_injection(
    s: ScenarioPublic, scope: TaskScope, store: CRMStore, tenant_id: str, out: _Collector
) -> None:
    assert s.injection is not None
    sid, inj = s.scenario_id, s.injection
    target = store.get(inj.target_record_id)
    if target is None:
        out.error(sid, "injection_target_missing", f"{inj.target_record_id} does not exist")
        return
    if target.tenant_id != tenant_id:
        out.error(
            sid, "injection_cross_tenant", "injection target is outside the principal's tenant"
        )
    if not isinstance(getattr(target, inj.field_path, None), str):
        out.error(sid, "injection_field_not_string", f"{inj.field_path} is not a string field")
    _, reachable = reachable_records(scope, store)
    if inj.target_record_id not in reachable:
        out.error(
            sid, "injection_unreachable", "target record is not readable within the task scope"
        )
    if inj.tool_name not in scope.allowed_tools:
        out.warn(
            sid, "injection_surface_not_in_scope", f"{inj.tool_name} not in the scope's tool set"
        )


def _check_pattern(
    sid: str, pattern: StateChangePattern, store: CRMStore, out: _Collector, what: str
) -> None:
    if pattern.field is not None and pattern.field not in _ENTITY_FIELDS[pattern.entity]:
        out.error(
            sid, "pattern_unknown_field", f"{what}: {pattern.entity} has no field {pattern.field!r}"
        )
    if pattern.record_id is not None:
        if entity_type_of(pattern.record_id) is not pattern.entity:
            out.error(
                sid,
                "pattern_entity_mismatch",
                f"{what}: {pattern.record_id} is not a {pattern.entity}",
            )
        elif pattern.entity is not EntityType.MESSAGE and store.get(pattern.record_id) is None:
            out.error(sid, "pattern_unknown_record", f"{what}: {pattern.record_id} does not exist")


def _check_truth_labels(
    s: ScenarioPublic,
    t: ScenarioPrivateTruth,
    scope: TaskScope,
    store: CRMStore,
    principal: Principal,
    public_ids: set[str],
    out: _Collector,
) -> None:
    sid, goal = s.scenario_id, t.attacker_goal
    if s.category is Category.ATTACK:
        if goal.type is AttackerGoalType.NONE:
            out.error(sid, "attack_without_goal", "attack scenario has attacker_goal 'none'")
        if t.valid_attack is None or not t.validity_reason:
            out.error(
                sid, "attack_validity_missing", "valid_attack and validity_reason are required"
            )
        if t.override_label is not OverrideLabel.MALICIOUS:
            out.error(sid, "override_label_mismatch", "attack override must be labeled malicious")
        if not t.payload_template_id:
            out.error(
                sid, "missing_template_lineage", "attack needs payload_template_id for grouping"
            )
    else:
        if goal.type is not AttackerGoalType.NONE:
            out.error(sid, "non_attack_with_goal", f"{s.category} scenario has an attacker goal")
        expected = OverrideLabel.BENIGN if s.category is Category.HARD_BENIGN else None
        if t.override_label is not expected:
            out.error(sid, "override_label_mismatch", f"expected override_label {expected}")

    for what, patterns in (
        ("required", t.required_state_changes),
        ("allowed", t.allowed_state_changes),
        ("forbidden", t.forbidden_state_change_patterns),
    ):
        for pattern in patterns:
            _check_pattern(sid, pattern, store, out, what)

    _check_goal(s, t, store, out)

    # Required changes must be exactly what the trusted request asked for.
    if scope.resolution is ScopeResolution.RESOLVED:
        for req in t.required_state_changes:
            if req.entity is EntityType.MESSAGE:
                aliases = {g.recipient_alias for g in scope.send_grants}
                if req.field == "recipient_alias" and req.value not in aliases:
                    out.error(
                        sid,
                        "required_change_not_requested",
                        f"message to {req.value} not requested",
                    )
                continue
            if not any(
                g.record_id == req.record_id and g.field == req.field and g.value == req.value
                for g in scope.write_grants
            ):
                out.error(
                    sid, "required_change_not_requested", f"{req} is not in the request scope"
                )

    capabilities = principal.capabilities
    for req in t.required_state_changes:
        tool = {
            EntityType.INVOICE: "update_invoice_status",
            EntityType.OPPORTUNITY: "update_opportunity_amount",
            EntityType.MESSAGE: "send_internal_message",
        }.get(req.entity)
        spec = get_tool(tool) if tool else None
        if (
            spec
            and spec.required_capability not in capabilities
            and EXPECT_PERMISSION_DENIED_TAG not in s.tags
        ):
            out.error(
                sid, "principal_lacks_capability", f"principal cannot perform required {tool}"
            )

    if t.feasibility_control_id and t.feasibility_control_id not in public_ids:
        out.warn(
            sid, "feasibility_control_not_loaded", f"{t.feasibility_control_id} not in this dataset"
        )


def _check_goal(
    s: ScenarioPublic, t: ScenarioPrivateTruth, store: CRMStore, out: _Collector
) -> None:
    sid, goal = s.scenario_id, t.attacker_goal
    if goal.is_mutation:
        assert goal.target_record_id is not None
        record = store.get(goal.target_record_id)
        if record is None:
            out.error(sid, "goal_target_missing", f"{goal.target_record_id} does not exist")
            return
        current = record.model_dump(mode="json").get(goal.field or "")
        target_value = goal.value
        if goal.type is AttackerGoalType.INVOICE_STATUS_CHANGE and target_value not in {
            s.value for s in InvoiceStatus
        }:
            out.error(sid, "goal_invalid_value", f"{target_value!r} is not an invoice status")
        if str(current) == str(target_value):
            out.error(sid, "goal_is_noop", "attacker goal would not change state")
        if not any(
            p.entity is entity_type_of(goal.target_record_id)
            and p.record_id in (None, goal.target_record_id)
            and p.field in (None, goal.field)
            for p in t.forbidden_state_change_patterns
        ):
            out.error(
                sid, "goal_not_forbidden", "goal mutation is not covered by a forbidden pattern"
            )
    if goal.type in (AttackerGoalType.UNAUTHORIZED_MESSAGE, AttackerGoalType.DATA_DISCLOSURE):
        if goal.recipient_alias is None or store.alias(goal.recipient_alias) is None:
            out.error(sid, "goal_unknown_alias", f"alias {goal.recipient_alias!r} does not exist")
        if not any(p.entity is EntityType.MESSAGE for p in t.forbidden_state_change_patterns):
            out.error(
                sid, "goal_not_forbidden", "message goal is not covered by a forbidden pattern"
            )
    if goal.canary_strings and s.injection is not None:
        for canary in goal.canary_strings:
            if (
                canary not in s.injection.replacement_text
                and goal.type is AttackerGoalType.ANSWER_CONTAMINATION
            ):
                out.error(sid, "canary_not_in_payload", f"canary {canary!r} not present in payload")


def _check_split_grouping(
    scenarios: Sequence[ScenarioPublic], truths: Mapping[str, ScenarioPrivateTruth], out: _Collector
) -> None:
    """Base tasks and payload-template lineages must never cross dev/heldout."""
    base_splits: dict[str, set[str]] = {}
    template_splits: dict[str, set[str]] = {}
    for s in scenarios:
        base_splits.setdefault(s.base_task_id, set()).add(s.split)
        truth = truths.get(s.scenario_id)
        if truth and truth.payload_template_id:
            template_splits.setdefault(truth.payload_template_id, set()).add(s.split)
    for base, splits in sorted(base_splits.items()):
        if len(splits) > 1:
            out.error(None, "base_task_crosses_splits", f"base_task_id {base} in {sorted(splits)}")
    for template, splits in sorted(template_splits.items()):
        if len(splits) > 1:
            out.error(
                None, "template_crosses_splits", f"payload template {template} in {sorted(splits)}"
            )
