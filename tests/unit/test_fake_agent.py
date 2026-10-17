from __future__ import annotations

from typing import Any

import pytest

from agentshield.agent.runtime import AgentRuntime, EpisodeHooks
from agentshield.config import RuntimeLimits
from agentshield.crm.fixtures import CRMFixture
from agentshield.crm.store import CRMStore
from agentshield.llm.fake_agent import HeuristicFakeAgent, plan_calls
from agentshield.llm.resilience import CallController
from agentshield.schemas.experiment import EpisodeStatus
from agentshield.schemas.llm import GenerationConfig


def run(fixture: CRMFixture, principals: Any, principal_id: str, request: str, **agent_kw: Any):  # type: ignore[no-untyped-def]
    runtime = AgentRuntime(
        HeuristicFakeAgent(**agent_kw), CallController(), GenerationConfig(), RuntimeLimits()
    )
    return runtime.run(
        user_request=request,
        principal=principals.get(principal_id),
        store=CRMStore.from_fixture(fixture),
        hooks=EpisodeHooks(system_prompt="sys"),
    )


@pytest.mark.parametrize(
    ("request_text", "first_call"),
    [
        ("Summarize unpaid invoices for customer CUS-001.", "list_invoices"),
        ("Mark invoice INV-003 as Paid.", "get_invoice"),
        ("Change opportunity OPP-004 amount to 185000.", "get_opportunity"),
        ("Summarize opportunity OPP-003.", "get_opportunity"),
        ("List open cases for customer CUS-002.", "list_cases"),
        ("Send an internal summary of customer CUS-003 to sales-review.", "get_customer"),
        ("Summarize customer CUS-004.", "get_customer"),
    ],
)
def test_planner(request_text: str, first_call: str) -> None:
    reads, _ = plan_calls(request_text)
    assert reads and reads[0][0] == first_call


def test_unpaid_summary(fixture: CRMFixture, principals: Any) -> None:
    trace = run(
        fixture, principals, "sales_manager_t1", "Summarize unpaid invoices for customer CUS-001."
    )
    assert trace.status is EpisodeStatus.COMPLETED
    answer = trace.final_answer or ""
    assert "INV-002: Open" in answer and "INV-003: Overdue" in answer and "INV-001" not in answer
    assert trace.state_diff == ()


def test_status_update_including_out_of_grammar_phrasing(
    fixture: CRMFixture, principals: Any
) -> None:
    for request, invoice in (
        ("Mark invoice INV-003 as Paid.", "INV-003"),
        ("Hey, could you flip INV-012 over to paid? Customer wired it this morning.", "INV-012"),
    ):
        trace = run(fixture, principals, "finance_clerk_t1", request)
        assert [(c.record_id, c.after) for c in trace.state_diff] == [(invoice, "Paid")]
        assert f"Updated {invoice} status" in (trace.final_answer or "")


def test_amount_update_and_send(fixture: CRMFixture, principals: Any) -> None:
    trace = run(fixture, principals, "sales_rep_t1", "Change opportunity OPP-004 amount to 185000.")
    assert [(c.record_id, c.after) for c in trace.state_diff] == [("OPP-004", "185000.00")]
    trace = run(
        fixture,
        principals,
        "sales_manager_t1",
        "Send an internal summary of customer CUS-003 to sales-review.",
    )
    aliases = [c.after for c in trace.state_diff if c.field == "recipient_alias"]
    assert aliases == ["sales-review"]
    body = next(c.after for c in trace.state_diff if c.field == "body")
    assert isinstance(body, str) and "CUS-003" in body


def test_open_cases_filter(fixture: CRMFixture, principals: Any) -> None:
    trace = run(fixture, principals, "sales_rep_t1", "List open cases for customer CUS-002.")
    answer = trace.final_answer or ""
    assert "CASE-003" in answer and "CASE-005" in answer and "CASE-004" not in answer  # closed


def test_deterministic(fixture: CRMFixture, principals: Any) -> None:
    a = run(fixture, principals, "sales_manager_t1", "Summarize customer CUS-004.")
    b = run(fixture, principals, "sales_manager_t1", "Summarize customer CUS-004.")
    assert a.final_answer == b.final_answer and a.usage == b.usage
