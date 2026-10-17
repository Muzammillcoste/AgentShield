"""Benchmark dataset properties (spec §7, D-041, D-046..D-049)."""

from __future__ import annotations

from collections import Counter
from typing import Any

import pytest

from agentshield.auth.scope_resolver import ScopeResolution, resolve_task_scope
from agentshield.benchmark.dataset_builder import BASE_TASKS, build_dataset
from agentshield.benchmark.loader import load_public_scenarios
from agentshield.benchmark.truth_store import load_private_truth
from agentshield.benchmark.validation import validate_dataset
from agentshield.crm.fixtures import CRMFixture
from agentshield.crm.store import CRMStore
from agentshield.schemas.common import record_ids_in_text
from agentshield.schemas.scenario import ScenarioPublic
from tests.conftest import ROOT

PUB = ROOT / "data" / "public"
PRIV = ROOT / "data" / "private"
Data = dict[str, tuple[list[ScenarioPublic], dict[str, Any]]]


@pytest.fixture(scope="module")
def data() -> Data:
    return {
        s: (
            load_public_scenarios(PUB / f"{s}.jsonl"),
            load_private_truth(PRIV / f"{s}_truth.jsonl"),
        )
        for s in ("dev", "heldout")
    }


def test_committed_dataset_matches_generator(fixture: CRMFixture, data: Data) -> None:
    generated = build_dataset(fixture)
    for split, (public, truths) in data.items():
        gen = [(p, t) for p, t in generated if p.split.value == split]
        assert [p for p, _ in gen] == public
        assert {t.scenario_id: t for _, t in gen} == truths


def test_composition(data: Data) -> None:
    total: Counter[str] = Counter()
    for split, expected in (("dev", 80), ("heldout", 40)):
        public, _ = data[split]
        assert len(public) == expected
        total.update(p.category.value for p in public)
        families = Counter(p.attack_family.value for p in public if p.attack_family)
        assert set(families.values()) == {8 if split == "dev" else 4} and len(families) == 5
    assert total == {"clean": 40, "attack": 60, "hard_benign": 20}


def test_legit_writes_and_out_of_grammar_share(data: Data) -> None:
    clean = [p for split in data.values() for p in split[0] if p.category.value == "clean"]
    writes = [p for p in clean if {"legit_write", "legit_send"} & set(p.tags)]
    oog = [p for p in writes if "scope:out_of_grammar" in p.tags]
    assert len(writes) >= 20 and len(writes) >= len(clean) / 2
    assert 0.15 <= len(oog) / len(writes) <= 0.25
    for p in clean:
        resolved = resolve_task_scope(p.user_request).resolution is ScopeResolution.RESOLVED
        assert resolved is ("scope:out_of_grammar" not in p.tags)


def test_no_leakage_between_splits(data: Data, fixture: CRMFixture) -> None:
    store = CRMStore.from_fixture(fixture)

    def customers(public: list[ScenarioPublic]) -> set[str | None]:
        out: set[str | None] = set()
        for p in public:
            out.update(store.customer_of(rid) for rid in record_ids_in_text(p.user_request))
            if p.injection:
                out.add(store.customer_of(p.injection.target_record_id))
        return out

    def templates(truths: dict[str, Any]) -> set[str]:
        return {t.payload_template_id for t in truths.values() if t.payload_template_id}

    def texts(public: list[ScenarioPublic]) -> set[str]:
        return {p.injection.replacement_text for p in public if p.injection}

    dev, held = data["dev"], data["heldout"]
    assert not customers(dev[0]) & customers(held[0])
    assert not {p.base_task_id for p in dev[0]} & {p.base_task_id for p in held[0]}
    assert not templates(dev[1]) & templates(held[1])
    assert not texts(dev[0]) & texts(held[0])


def test_dataset_validates_cleanly(data: Data, fixture: CRMFixture) -> None:
    public = [p for split in data.values() for p in split[0]]
    truths = {k: v for split in data.values() for k, v in split[1].items()}
    report = validate_dataset(public, truths, fixture)
    assert report.ok and not report.issues


def test_attacks_sit_on_records_the_task_reads(data: Data) -> None:
    # D-041: the injected record must be returned by a tool the legitimate request needs.
    for public, _ in data.values():
        for p in public:
            if p.injection is None:
                continue
            scope = resolve_task_scope(p.user_request)
            assert p.injection.tool_name in scope.allowed_tools
            assert p.injection.apply_on_nth_matching_tool_result is None


def test_feasibility_controls_in_same_split(data: Data) -> None:
    for split, (public, truths) in data.items():
        ids = {p.scenario_id for p in public}
        for p in public:
            control = truths[p.scenario_id].feasibility_control_id
            if control:
                assert control in ids, (split, p.scenario_id, control)


def test_base_tasks_unique() -> None:
    assert len({t.base_id for t in BASE_TASKS}) == len(BASE_TASKS) == 40
    assert len({t.request for t in BASE_TASKS}) == 40
