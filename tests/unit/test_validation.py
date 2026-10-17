from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from agentshield.benchmark.loader import load_public_scenarios
from agentshield.benchmark.truth_store import load_private_truth
from agentshield.benchmark.validation import IssueLevel, validate_dataset
from agentshield.crm.fixtures import CRMFixture
from agentshield.schemas.scenario import ScenarioPublic
from agentshield.schemas.truth import ScenarioPrivateTruth
from tests.conftest import EXAMPLES_PRIVATE, EXAMPLES_PUBLIC

Public = list[ScenarioPublic]
Truths = dict[str, ScenarioPrivateTruth]


@pytest.fixture
def data() -> tuple[Public, Truths]:
    return load_public_scenarios(EXAMPLES_PUBLIC), load_private_truth(EXAMPLES_PRIVATE)


def _edit_public(scenarios: Public, sid: str, **update: Any) -> Public:
    return [
        ScenarioPublic.model_validate({**s.model_dump(), **update}) if s.scenario_id == sid else s
        for s in scenarios
    ]


def _edit_truth(truths: Truths, sid: str, **update: Any) -> Truths:
    out = dict(truths)
    out[sid] = ScenarioPrivateTruth.model_validate({**truths[sid].model_dump(), **update})
    return out


def _injection(scenarios: Public, sid: str, **update: Any) -> dict[str, Any]:
    scenario = next(s for s in scenarios if s.scenario_id == sid)
    assert scenario.injection is not None
    return {**scenario.injection.model_dump(), **update}


def _codes(scenarios: Public, truths: Truths, fixture: CRMFixture) -> set[str]:
    report = validate_dataset(scenarios, truths, fixture)
    return {i.code for i in report.issues if i.level is IssueLevel.ERROR}


def test_examples_are_valid(data: tuple[Public, Truths], fixture: CRMFixture) -> None:
    report = validate_dataset(*data, fixture)
    assert report.ok, report.issues
    assert report.n_public == report.n_private == 11
    assert report.counts["category:attack"] == 5
    assert report.unverified_labels == 11  # honest: labels are not yet human-verified
    families = {k for k in report.counts if k.startswith("family:")}
    assert len(families) == 5


ATTACK = "ex-attack-workflow-hijack-001"
SWAP = "ex-attack-parameter-swap-001"
CLEAN_WRITE = "ex-clean-invoice-status-update-001"
CONTAM = "ex-attack-answer-contamination-001"

Mutation = Callable[[Public, Truths], tuple[Public, Truths]]

CASES: list[tuple[str, Mutation]] = [
    ("unknown_principal", lambda p, t: (_edit_public(p, ATTACK, principal_id="ghost_user"), t)),
    ("fixture_mismatch", lambda p, t: (_edit_public(p, ATTACK, fixture_id="other"), t)),
    (
        "unknown_record_in_request",
        lambda p, t: (
            _edit_public(p, CLEAN_WRITE, user_request="Mark invoice INV-999 as Paid."),
            t,
        ),
    ),
    (
        "cross_tenant_request",
        lambda p, t: (
            _edit_public(p, CLEAN_WRITE, user_request="Mark invoice INV-049 as Paid."),
            t,
        ),
    ),
    (
        "scope_unresolved",
        lambda p, t: (
            _edit_public(p, CLEAN_WRITE, user_request="Please sort out INV-003 for me."),
            t,
        ),
    ),
    (
        "grammar_tag_mismatch",
        lambda p, t: (_edit_public(p, CLEAN_WRITE, tags=("scope:out_of_grammar",)), t),
    ),
    (
        "injection_unreachable",
        lambda p, t: (
            _edit_public(
                p,
                ATTACK,
                injection=_injection(p, ATTACK, target_record_id="INV-010"),
            ),
            t,
        ),
    ),
    (
        "injection_target_missing",
        lambda p, t: (
            _edit_public(
                p,
                ATTACK,
                injection=_injection(p, ATTACK, target_record_id="INV-999"),
            ),
            t,
        ),
    ),
    (
        "goal_is_noop",
        lambda p, t: (
            p,
            _edit_truth(
                t,
                SWAP,
                attacker_goal={**t[SWAP].attacker_goal.model_dump(), "target_record_id": "INV-006"},
                forbidden_state_change_patterns=[
                    {"entity": "invoice", "record_id": "INV-006", "field": "status"}
                ],
            ),
        ),
    ),
    (
        "goal_not_forbidden",
        lambda p, t: (p, _edit_truth(t, ATTACK, forbidden_state_change_patterns=[])),
    ),
    (
        "attack_without_goal",
        lambda p, t: (p, _edit_truth(t, ATTACK, attacker_goal={"type": "none"})),
    ),
    ("override_label_mismatch", lambda p, t: (p, _edit_truth(t, ATTACK, override_label="benign"))),
    (
        "missing_template_lineage",
        lambda p, t: (p, _edit_truth(t, ATTACK, payload_template_id=None)),
    ),
    (
        "canary_not_in_payload",
        lambda p, t: (
            p,
            _edit_truth(
                t,
                CONTAM,
                attacker_goal={
                    **t[CONTAM].attacker_goal.model_dump(),
                    "canary_strings": ["ZZ-404"],
                },
            ),
        ),
    ),
    (
        "required_change_not_requested",
        lambda p, t: (
            p,
            _edit_truth(
                t,
                CLEAN_WRITE,
                required_state_changes=[
                    {
                        "entity": "invoice",
                        "record_id": "INV-003",
                        "field": "status",
                        "value": "Void",
                    }
                ],
                allowed_state_changes=[
                    {
                        "entity": "invoice",
                        "record_id": "INV-003",
                        "field": "status",
                        "value": "Void",
                    }
                ],
            ),
        ),
    ),
    (
        "principal_lacks_capability",
        lambda p, t: (_edit_public(p, CLEAN_WRITE, principal_id="auditor_t1"), t),
    ),
    (
        "pattern_unknown_field",
        lambda p, t: (
            p,
            _edit_truth(
                t,
                ATTACK,
                forbidden_state_change_patterns=[{"entity": "invoice", "field": "colour"}],
            ),
        ),
    ),
    ("missing_private_truth", lambda p, t: (p, {k: v for k, v in t.items() if k != ATTACK})),
    ("base_task_crosses_splits", lambda p, t: (_edit_public(p, ATTACK, split="heldout"), t)),
]


@pytest.mark.parametrize(("code", "mutate"), CASES, ids=[c for c, _ in CASES])
def test_validator_detects(
    code: str, mutate: Mutation, data: tuple[Public, Truths], fixture: CRMFixture
) -> None:
    scenarios, truths = mutate(*data)
    assert code in _codes(scenarios, truths, fixture)


def test_orphan_truth_and_template_crossing(
    data: tuple[Public, Truths], fixture: CRMFixture
) -> None:
    scenarios, truths = data
    only_attack = [s for s in scenarios if s.scenario_id != ATTACK]
    assert "orphan_private_truth" in _codes(only_attack, truths, fixture)

    # Same payload template used in dev and heldout (different base tasks) must be rejected.
    moved = _edit_public(scenarios, SWAP, split="heldout")
    shared = _edit_truth(truths, SWAP, payload_template_id=truths[ATTACK].payload_template_id)
    assert "template_crosses_splits" in _codes(moved, shared, fixture)
