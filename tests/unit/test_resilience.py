from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from agentshield.config import BudgetLimits, ModelPrice
from agentshield.llm.protocol import LLMError, LLMErrorKind
from agentshield.llm.resilience import (
    AttemptRecord,
    BudgetExceededError,
    BudgetGuard,
    CallController,
    RateLimitTracker,
    RetryPolicy,
    estimate_prompt_tokens,
    parse_duration,
)
from agentshield.schemas.llm import (
    ChatMessage,
    FinishReason,
    GenerationConfig,
    MessageRole,
    ModelResponse,
    ProviderKind,
    ToolSchema,
    Usage,
)

MSGS = [ChatMessage(role=MessageRole.USER, content="x" * 400)]  # ~100 tokens
CFG = GenerationConfig(max_output_tokens=100)


def ok_response(
    headers: dict[str, str] | None = None, tokens: tuple[int, int] = (100, 20)
) -> ModelResponse:
    return ModelResponse(
        assistant_text="ok",
        usage=Usage(input_tokens=tokens[0], output_tokens=tokens[1]),
        finish_reason=FinishReason.STOP,
        model_id="m",
        provider_kind=ProviderKind.REAL,
        rate_limit_headers=headers or {},
    )


@dataclass
class ScriptedClient:
    outcomes: list[ModelResponse | LLMError]
    calls: int = 0

    @property
    def provider_kind(self) -> ProviderKind:
        return ProviderKind.REAL

    @property
    def model_id(self) -> str:
        return "m"

    def complete(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSchema], config: GenerationConfig
    ) -> ModelResponse:
        outcome = self.outcomes[self.calls]
        self.calls += 1
        if isinstance(outcome, LLMError):
            raise outcome
        return outcome


@dataclass
class FakeTime:
    now: float = 1000.0
    sleeps: list[float] = field(default_factory=list)

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def controller(t: FakeTime, **kw: object) -> CallController:
    return CallController(sleep=t.sleep, clock=t.clock, **kw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("2m59.56s", 179.56),
        ("7.66s", 7.66),
        ("1h2m3s", 3723.0),
        ("250ms", 0.25),
        ("3", 3.0),
        ("24h0m0s", 86400.0),
    ],
)
def test_parse_duration(text: str, seconds: float) -> None:
    assert parse_duration(text) == pytest.approx(seconds)


@pytest.mark.parametrize("text", ["", "soon", "m"])
def test_parse_duration_rejects_garbage(text: str) -> None:
    assert parse_duration(text) is None


def test_token_estimate_counts_messages_and_tools() -> None:
    tool = ToolSchema(name="t", description="d" * 40, parameters={"type": "object"})
    assert estimate_prompt_tokens(MSGS, []) == 104
    assert estimate_prompt_tokens(MSGS, [tool]) > 104


def test_rate_tracker_waits_for_token_window() -> None:
    tracker = RateLimitTracker()
    tracker.update(
        {
            "x-ratelimit-remaining-tokens": "50",
            "x-ratelimit-reset-tokens": "7.5s",
            "x-ratelimit-remaining-requests": "900",
            "x-ratelimit-reset-requests": "1m",
        },
        now=0.0,
    )
    assert tracker.wait_seconds(estimated_tokens=40, now=0.0) == 0.0
    assert tracker.wait_seconds(estimated_tokens=400, now=0.0) == pytest.approx(7.5)
    assert tracker.wait_seconds(estimated_tokens=400, now=8.0) == 0.0  # window has reset
    tracker.update(
        {"x-ratelimit-remaining-requests": "0", "x-ratelimit-reset-requests": "2h"}, now=10.0
    )
    assert tracker.wait_seconds(estimated_tokens=1, now=10.0) == pytest.approx(7200)


def test_controller_retries_transient_errors_with_backoff_and_retry_after() -> None:
    t = FakeTime()
    client = ScriptedClient(
        [
            LLMError(LLMErrorKind.SERVER, "503"),
            LLMError(LLMErrorKind.RATE_LIMIT, "429", retry_after_s=4.0),
            ok_response(),
        ]
    )
    records: list[AttemptRecord] = []
    c = controller(t, retry=RetryPolicy(max_retries=3, backoff_initial_s=1.0))
    response = c.call(client, MSGS, [], CFG, on_attempt=records.append)
    assert response.assistant_text == "ok" and client.calls == 3
    assert t.sleeps == [1.0, 4.0]
    assert [(r.attempt, r.ok, r.error_kind) for r in records] == [
        (1, False, LLMErrorKind.SERVER),
        (2, False, LLMErrorKind.RATE_LIMIT),
        (3, True, None),
    ]


def test_controller_does_not_retry_permanent_errors() -> None:
    t = FakeTime()
    client = ScriptedClient([LLMError(LLMErrorKind.AUTH, "401"), ok_response()])
    with pytest.raises(LLMError) as info:
        controller(t).call(client, MSGS, [], CFG)
    assert info.value.kind is LLMErrorKind.AUTH and client.calls == 1 and t.sleeps == []


def test_controller_gives_up_after_max_retries() -> None:
    t = FakeTime()
    client = ScriptedClient([LLMError(LLMErrorKind.TIMEOUT, "t")] * 3)
    with pytest.raises(LLMError):
        controller(t, retry=RetryPolicy(max_retries=2, backoff_initial_s=1.0)).call(
            client, MSGS, [], CFG
        )
    assert client.calls == 3 and t.sleeps == [1.0, 2.0]


def test_controller_refuses_excessive_retry_after() -> None:
    t = FakeTime()
    client = ScriptedClient([LLMError(LLMErrorKind.RATE_LIMIT, "daily", retry_after_s=3600)])
    with pytest.raises(LLMError) as info:
        controller(t, max_rate_wait_s=90).call(client, MSGS, [], CFG)
    assert info.value.kind is LLMErrorKind.RATE_LIMIT and not info.value.retryable


def test_controller_waits_for_rate_window_from_previous_headers() -> None:
    t = FakeTime()
    client = ScriptedClient(
        [
            ok_response({"x-ratelimit-remaining-tokens": "10", "x-ratelimit-reset-tokens": "5s"}),
            ok_response(),
        ]
    )
    c = controller(t)
    c.call(client, MSGS, [], CFG)
    c.call(client, MSGS, [], CFG)
    assert t.sleeps == [pytest.approx(5.0)]


def test_controller_fails_when_window_exceeds_max_wait() -> None:
    t = FakeTime()
    client = ScriptedClient(
        [
            ok_response(
                {"x-ratelimit-remaining-requests": "0", "x-ratelimit-reset-requests": "3h"}
            ),
            ok_response(),
        ]
    )
    c = controller(t, max_rate_wait_s=90)
    c.call(client, MSGS, [], CFG)
    with pytest.raises(LLMError, match="quota"):
        c.call(client, MSGS, [], CFG)
    assert client.calls == 1


def test_budget_guard_blocks_before_call_and_records_usage() -> None:
    t = FakeTime()
    budget = BudgetGuard(BudgetLimits(max_total_tokens=400, max_requests=5))
    client = ScriptedClient([ok_response(tokens=(150, 30))] * 5)
    c = controller(t, budget=budget)
    c.call(client, MSGS, [], CFG)  # projected 0 + 104 + 100 <= 400
    assert budget.snapshot().total_tokens == 180
    with pytest.raises(BudgetExceededError):  # 180 + 104 + 100 = 384 ok; then 360+204 > 400
        c.call(client, MSGS, [], CFG)
        c.call(client, MSGS, [], CFG)
    assert client.calls == 2


def test_budget_guard_requests_and_usd() -> None:
    guard = BudgetGuard(BudgetLimits(max_requests=1))
    guard.check(10, 10)
    guard.record(Usage(input_tokens=1, output_tokens=1))
    with pytest.raises(BudgetExceededError):
        guard.check(10, 10)
    priced = BudgetGuard(
        BudgetLimits(max_usd=0.001), ModelPrice(input_usd_per_mtok=1.0, output_usd_per_mtok=4.0)
    )
    priced.check(500, 100)  # $0.0009
    with pytest.raises(BudgetExceededError):
        priced.check(500, 200)  # $0.0013
    priced.record(Usage(input_tokens=1000, output_tokens=0))
    assert priced.snapshot().usd == pytest.approx(0.001)
    with pytest.raises(ValueError, match="price"):
        BudgetGuard(BudgetLimits(max_usd=1.0))


def test_failed_attempts_count_as_requests() -> None:
    t = FakeTime()
    budget = BudgetGuard(BudgetLimits(max_requests=10))
    client = ScriptedClient([LLMError(LLMErrorKind.SERVER, "x"), ok_response()])
    controller(t, budget=budget).call(client, MSGS, [], CFG)
    assert budget.snapshot().requests == 2


def test_backoff_is_reported_and_throttle_reserves_max_output() -> None:
    t = FakeTime()
    client = ScriptedClient(
        [
            LLMError(LLMErrorKind.SERVER, "503"),
            ok_response({"x-ratelimit-remaining-tokens": "200", "x-ratelimit-reset-tokens": "9s"}),
            ok_response(),
        ]
    )
    records: list[AttemptRecord] = []
    c = controller(t, retry=RetryPolicy(max_retries=1, backoff_initial_s=2.0))
    c.call(client, MSGS, [], CFG, on_attempt=records.append)
    assert [r.waited_s for r in records] == [0.0, 2.0]
    # 200 remaining < ceil(1.25 * 104) + 100 max output = 230 -> wait for the window
    c.call(client, MSGS, [], CFG)
    assert t.sleeps == [2.0, pytest.approx(9.0)]
