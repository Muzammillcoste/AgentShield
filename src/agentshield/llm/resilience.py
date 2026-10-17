"""Retries with backoff, provider rate-limit throttling and hard usage budgets.

All model calls in an experiment go through one `CallController`, which:
1. refuses a call that could exceed the token/request/USD budget (`BudgetExceededError`);
2. waits for the provider's rate-limit window using the `x-ratelimit-*` headers of earlier
   responses (fails instead of waiting longer than `max_rate_wait_s`, e.g. a daily quota);
3. retries transient errors with exponential backoff, honoring `retry-after`;
4. reports every attempt to an observer so traces show retries explicitly.
Token estimates are rough (characters / 4) and only used for pre-call checks; recorded usage
always comes from the provider.
"""

from __future__ import annotations

import json
import math
import re
import threading
import time
from collections.abc import Callable, Mapping, Sequence

from agentshield.config import BudgetLimits, ModelPrice
from agentshield.llm.protocol import LLMClient, LLMError, LLMErrorKind
from agentshield.schemas.common import StrictModel
from agentshield.schemas.llm import ChatMessage, GenerationConfig, ModelResponse, ToolSchema, Usage

CHARS_PER_TOKEN = 4
# Rate windows: chars/4 undercounts real tokenizers, and providers may reserve the full
# max_output_tokens against output-token limits, so waits use a conservative estimate.
RATE_INPUT_SAFETY = 1.25


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN) if text else 0


def estimate_prompt_tokens(messages: Sequence[ChatMessage], tools: Sequence[ToolSchema]) -> int:
    total = 0
    for message in messages:
        total += estimate_tokens(message.content or "") + 4
        for call in message.tool_calls:
            total += estimate_tokens(call.name + call.arguments_json) + 4
    for tool in tools:
        total += estimate_tokens(tool.name + tool.description + json.dumps(tool.parameters))
    return total


_DURATION = re.compile(
    r"^(?:(?P<h>\d+(?:\.\d+)?)h)?(?:(?P<m>\d+(?:\.\d+)?)m(?!s))?"
    r"(?:(?P<s>\d+(?:\.\d+)?)s)?(?:(?P<ms>\d+(?:\.\d+)?)ms)?$"
)


def parse_duration(value: str) -> float | None:
    """Parse provider reset durations such as '2m59.56s', '7.66s', '1h2m', '250ms', '3'."""
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    match = _DURATION.match(value)
    if not match or not any(match.groupdict().values()):
        return None
    parts = {k: float(v) for k, v in match.groupdict().items() if v}
    return (
        parts.get("h", 0) * 3600
        + parts.get("m", 0) * 60
        + parts.get("s", 0)
        + parts.get("ms", 0) / 1000
    )


class RateLimitTracker:
    """Tracks remaining requests/tokens from response headers and computes waits."""

    def __init__(self) -> None:
        self.limit_requests: int | None = None
        self.limit_tokens: int | None = None
        self.remaining_requests: int | None = None
        self.remaining_tokens: int | None = None
        self.requests_reset_at: float | None = None
        self.tokens_reset_at: float | None = None

    @staticmethod
    def _int(headers: Mapping[str, str], name: str) -> int | None:
        try:
            return int(float(headers[name]))
        except (KeyError, ValueError):
            return None

    def update(self, headers: Mapping[str, str], now: float) -> None:
        h = {k.lower(): v for k, v in headers.items()}
        self.limit_requests = self._int(h, "x-ratelimit-limit-requests") or self.limit_requests
        self.limit_tokens = self._int(h, "x-ratelimit-limit-tokens") or self.limit_tokens
        remaining = self._int(h, "x-ratelimit-remaining-requests")
        if remaining is not None:
            self.remaining_requests = remaining
            reset = parse_duration(h.get("x-ratelimit-reset-requests", ""))
            self.requests_reset_at = now + reset if reset is not None else None
        remaining = self._int(h, "x-ratelimit-remaining-tokens")
        if remaining is not None:
            self.remaining_tokens = remaining
            reset = parse_duration(h.get("x-ratelimit-reset-tokens", ""))
            self.tokens_reset_at = now + reset if reset is not None else None

    def wait_seconds(self, estimated_tokens: int, now: float) -> float:
        waits = [0.0]
        if (
            self.remaining_requests is not None
            and self.remaining_requests <= 0
            and self.requests_reset_at is not None
            and now < self.requests_reset_at
        ):
            waits.append(self.requests_reset_at - now)
        if (
            self.remaining_tokens is not None
            and self.remaining_tokens < estimated_tokens
            and self.tokens_reset_at is not None
            and now < self.tokens_reset_at
        ):
            waits.append(self.tokens_reset_at - now)
        return max(waits)

    def snapshot(self) -> dict[str, int | None]:
        return {
            "limit_requests": self.limit_requests,
            "limit_tokens": self.limit_tokens,
            "remaining_requests": self.remaining_requests,
            "remaining_tokens": self.remaining_tokens,
        }


class BudgetExceededError(LLMError):
    def __init__(self, message: str) -> None:
        super().__init__(LLMErrorKind.BUDGET_EXCEEDED, message, retryable=False)


class BudgetSnapshot(StrictModel):
    requests: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    usd: float | None
    limits: BudgetLimits


class BudgetGuard:
    """Hard caps on requests, tokens and (when prices are configured) USD. Thread-safe."""

    def __init__(self, limits: BudgetLimits, price: ModelPrice | None = None) -> None:
        if limits.max_usd is not None and price is None:
            raise ValueError("a USD budget needs a configured model price (pricing YAML)")
        self.limits = limits
        self.price = price
        self._lock = threading.Lock()
        self.requests = 0
        self.input_tokens = 0
        self.output_tokens = 0

    def _usd(self, input_tokens: int, output_tokens: int) -> float | None:
        if self.price is None:
            return None
        return (
            input_tokens * self.price.input_usd_per_mtok
            + output_tokens * self.price.output_usd_per_mtok
        ) / 1_000_000

    def check(self, estimated_input: int, max_output: int) -> None:
        with self._lock:
            limits = self.limits
            if limits.max_requests is not None and self.requests + 1 > limits.max_requests:
                raise BudgetExceededError(f"request budget of {limits.max_requests} reached")
            projected = self.input_tokens + self.output_tokens + estimated_input + max_output
            if limits.max_total_tokens is not None and projected > limits.max_total_tokens:
                raise BudgetExceededError(
                    f"next call could exceed the token budget of {limits.max_total_tokens}"
                )
            if limits.max_usd is not None:
                usd = self._usd(
                    self.input_tokens + estimated_input, self.output_tokens + max_output
                )
                if usd is not None and usd > limits.max_usd:
                    raise BudgetExceededError(f"next call could exceed ${limits.max_usd:.2f}")

    def record(self, usage: Usage) -> None:
        with self._lock:
            self.requests += usage.requests
            self.input_tokens += usage.input_tokens
            self.output_tokens += usage.output_tokens

    def record_failed_request(self) -> None:
        with self._lock:
            self.requests += 1

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            return BudgetSnapshot(
                requests=self.requests,
                input_tokens=self.input_tokens,
                output_tokens=self.output_tokens,
                total_tokens=self.input_tokens + self.output_tokens,
                usd=self._usd(self.input_tokens, self.output_tokens),
                limits=self.limits,
            )


class RetryPolicy(StrictModel):
    max_retries: int = 3
    backoff_initial_s: float = 1.0
    backoff_max_s: float = 30.0

    def delay(self, attempt: int, retry_after_s: float | None) -> float:
        if retry_after_s is not None:
            return max(0.0, retry_after_s)
        return float(min(self.backoff_max_s, self.backoff_initial_s * 2 ** (attempt - 1)))


class AttemptRecord(StrictModel):
    attempt: int
    ok: bool
    latency_ms: float
    waited_s: float = 0.0
    error_kind: LLMErrorKind | None = None
    error_message: str | None = None
    response: ModelResponse | None = None


class CallController:
    def __init__(
        self,
        *,
        retry: RetryPolicy | None = None,
        budget: BudgetGuard | None = None,
        rate: RateLimitTracker | None = None,
        max_rate_wait_s: float = 90.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.retry = retry or RetryPolicy()
        self.budget = budget
        self.rate = rate or RateLimitTracker()
        self.max_rate_wait_s = max_rate_wait_s
        self._sleep = sleep
        self._clock = clock

    def call(
        self,
        client: LLMClient,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSchema],
        config: GenerationConfig,
        on_attempt: Callable[[AttemptRecord], None] | None = None,
    ) -> ModelResponse:
        estimated_input = estimate_prompt_tokens(messages, tools)
        attempt = 0
        backoff = 0.0  # retry delay slept before this attempt (reported in waited_s)
        while True:
            attempt += 1
            if self.budget is not None:
                self.budget.check(estimated_input, config.max_output_tokens)
            waited = backoff + self._wait_for_window(
                math.ceil(estimated_input * RATE_INPUT_SAFETY) + config.max_output_tokens
            )
            backoff = 0.0
            started = self._clock()
            try:
                response = client.complete(messages, tools, config)
            except LLMError as exc:
                latency = (self._clock() - started) * 1000
                self.rate.update(exc.headers, self._clock())
                if self.budget is not None:
                    self.budget.record_failed_request()
                if on_attempt:
                    on_attempt(
                        AttemptRecord(
                            attempt=attempt,
                            ok=False,
                            latency_ms=latency,
                            waited_s=waited,
                            error_kind=exc.kind,
                            error_message=exc.message,
                        )
                    )
                if not exc.retryable:
                    raise
                delay = self.retry.delay(attempt, exc.retry_after_s)
                if delay > self.max_rate_wait_s:
                    # e.g. a daily quota: stop the run (non-retryable) instead of failing episodes
                    raise LLMError(
                        LLMErrorKind.RATE_LIMIT,
                        f"provider asked to wait {delay:.0f}s (> {self.max_rate_wait_s:.0f}s); "
                        f"quota likely exhausted: {exc.message[:200]}",
                        retryable=False,
                    ) from exc
                if attempt > self.retry.max_retries:
                    raise
                self._sleep(delay)
                backoff = delay
                continue
            self.rate.update(response.rate_limit_headers, self._clock())
            if self.budget is not None:
                self.budget.record(response.usage)
            if on_attempt:
                on_attempt(
                    AttemptRecord(
                        attempt=attempt,
                        ok=True,
                        latency_ms=response.latency_ms,
                        waited_s=waited,
                        response=response,
                    )
                )
            return response

    def _wait_for_window(self, estimated_tokens: int) -> float:
        wait = self.rate.wait_seconds(estimated_tokens, self._clock())
        if wait <= 0:
            return 0.0
        if wait > self.max_rate_wait_s:
            raise LLMError(
                LLMErrorKind.RATE_LIMIT,
                f"rate-limit window resets in {wait:.0f}s (> {self.max_rate_wait_s:.0f}s); "
                "quota likely exhausted",
                retryable=False,
            )
        self._sleep(wait)
        return wait
