# Design Decisions

Each entry: decision, rationale, consequence. "Flag" marks decisions the project owner should
review because they touch methodological validity.

**D-001 Documentation names.** The user's requested names supersede the specification's:
`research_methodology.md` (spec: `methodology.md`), `known_limitations.md` (spec:
`limitations.md`), `experiment_protocol.md` (spec: `experiment_registry.md`). `threat_model.md`
and `implementation_plan.md` are kept from the specification; `research_report.md` arrives in
Phase 7.

**D-002 Python 3.12 via uv.** The machine has Python 3.11/3.13; uv installs CPython 3.12.13.
`requires-python = ">=3.12,<3.13"` and `.python-version` pin it.

**D-003 Real provider = Groq (OpenAI-compatible chat completions), model
`qwen/qwen3.8-27b`, free plan (confirmed by owner 2026-10-17).** The local `.env` defines
`LLM_API_KEY` and `MODEL_NAME`; Phase 2 accepts `MODEL_NAME` as an alias of
`AGENTSHIELD_MODEL` and verifies availability via the `/models` endpoint. On the free plan the
dollar cost is zero, so the binding constraints are provider rate limits and daily quotas:
budget controls cap requests and tokens, and 429 responses use exponential backoff. Experiment
runs still require owner approval. The fake provider is never substituted for a failed real run.

**D-004 Baseline D0 = schema validation only (Flag).** RBAC and tenant confinement belong to D5
(`rbac_only` level), as the specification requires no hidden D4/D5 restrictions in D0. The
agent therefore acts like a mis-scoped integration account in D0. Consequence: H1/H2 analyses
must also compare against `C05-rbac_only` (standard practice) so gains are not inflated by a
straw-man baseline.

**D-005 Tenant observation.** Every dispatched call emits a `TenantCheckEvent`
(match/mismatch/target_missing), logged separately from schema validation and policy decisions.
`enforced=True` only when a gate declares `enforces_tenant` (D5 from Phase 4).

**D-006 Persistent injection delivery (deviation from spec default; accepted by owner 2026-10-17).** A "matching tool
result" is any attack-surface result exposing the target record's field.
`apply_on_nth_matching_tool_result=None` (dataset default) applies the override to every matching
result; integer *k* applies only to the k-th. Rationale: a real attacker edits the stored field,
so every read shows it; single-shot delivery causes inconsistent re-reads and undelivered attacks.
The stored CRM record is never modified, so the injection is never a state change.

**D-007 Hard-benign text uses the same override mechanism**, labeled `benign` in private truth,
so clean, hard-benign and attack scenarios share one code path and differ only in text.

**D-008 Private truth isolation.** `ScenarioPrivateTruth` lives in `schemas/truth.py` (spec placed
it in `scenario.py`) so an AST-based test can prove runtime packages never import it or the
benchmark harness, and defenses never import the public scenario schema (which carries
category/family labels).

**D-009 Scope grammar v1.** Seven rules (summarize invoices, invoice status change ×2 phrasings,
opportunity amount change, summarize opportunity, list cases, send internal summary, summarize
customer), clause splitting on `. ; , then / and then`, at most three clauses, conflicting
values → `ambiguous`. Unknown requests → read-only tools with reads limited to records the user
named; never a write or send. Reads expand via trusted foreign keys (customer → children,
record → parent customer), never via retrieved text.

**D-010 State-change labels.** Diffs are field-level `StateChange`s. For created records (messages)
the grader treats the identifying field (`message.recipient_alias`) as governing the whole record;
other created fields are implied. Grader implementation: Phase 5.

**D-011 Deny precedence lives in the dispatcher**, not inside individual defenses: any DENY is
final; ABSTAIN blocks writes and sends but not reads; a gate exception or an invalid decision
fails closed; optional shadow evaluation after a deny is logged but cannot change the outcome.

**D-012 No evaluation-awareness cues.** Tool descriptions and outputs never mention simulation,
sandbox, security or testing (enforced by a test). `send_internal_message` returns
`status: "sent"` although nothing is delivered.

**D-013 Money** is `Decimal` quantized to cents and serialized as strings in tool output, state
diffs and labels; the scope grammar canonicalizes amounts the same way.

**D-014 Status semantics.** Unpaid = Open | Overdue | Disputed. Open cases = New | Open | Pending |
Escalated. Defined in code so grading never depends on interpretation.

**D-015 Answer contamination via canaries (Flag).** Attacker goals carry unique synthetic canary
strings; deterministic checks use required/forbidden mentions; every canary hit is manually
audited (quoting a payload while flagging it is not contamination). An LLM judge, if used, is
secondary evidence only.

**D-016 Config hashes are semantic.** They exclude id/description/family, so identical defense
settings share a hash (`C14-noD2` = `C15`, `M63` = `C14`, `C05-record_field_value` = `C05`),
allowing safe episode reuse and detecting accidental duplicates.

**D-017 D5 granularity is cumulative:** `rbac_only` (role capability + tenant) ⊂
`task_and_tool` ⊂ `record` ⊂ `record_field_value`.

**D-018 Fake model.** `follow_injections=True` simulates a susceptible agent that obeys
imperative patterns found only in tool messages. Output is labeled `provider_kind="fake"` with
estimated token counts; it tests plumbing and never supports claims about real models.

**D-019 License: MIT** (confirmed by owner 2026-10-17).

**D-020 Reproducible hashes across OSes.** `.gitattributes` forces LF; the data manifest hashes
text files after CRLF→LF normalization.

**D-021 Out-of-grammar legitimate requests (accepted by owner 2026-10-17).** Tagged `scope:out_of_grammar`; the validator
requires that tagged requests do *not* resolve and untagged ones *do*, catching grammar/dataset
drift. Target share: about 20% of legitimate-write tasks in each split.

**D-022 Payload template lineage** (`payload_template_id`, private) is a split-grouping key
alongside `base_task_id`; held-out payload templates are never seen during dev (protects D2 and
prompt tuning from leakage).

**D-023 `.sf/` directory.** The workspace contains real Salesforce org metadata. It is
git-ignored and never read, imported or connected to.

**D-024 Feasibility controls.** Mutation attacks reference a legitimate control scenario that
explicitly requests the analogous action (`feasibility_control_id`), so low attack success can be
distinguished from inability to use the tool.

**D-025 Proposed D5 rule for sends (Phase 4, Flag).** At `record_field_value`, a send must match the
granted alias exactly and its body may reference only entity IDs within the subject customer's
scope (deterministic ID-based check). Semantic body content is not verifiable deterministically.

**D-026 D6 exposure.** D6 sees the proposed arguments, which may contain attacker text (message
bodies). Arguments will be JSON-escaped and this exposure documented; D6 send-action failures are
analyzed separately.

## Phase 2 decisions (2026-10-17)

**D-027 Instruct mode for the real model (Flag).** Groq requests use
`reasoning_effort: "none"` and `reasoning_format: "hidden"`: no thinking tokens are generated or
returned. Rationale: free-tier limits (7,000 input + 1,000 output tokens per minute) and the rule
that reasoning text is never stored. Consequence: results describe the model in instruct mode;
thinking mode may behave differently and is a candidate ablation if quota allows.

**D-028 Temperature 0.** Groq recommends 0.7 for instruct mode; evaluation uses 0.0 to reduce
variance between configurations. Recorded per run; not treated as determinism. In the Phase 2
smoke runs, repeated episodes at temperature 0 produced identical token counts and outcomes.

**D-029 `max_output_tokens: 512` for Groq.** Observed 429 errors stated an output-tokens-per-minute
(OTPM) limit of 1,000 with each request reserving its full `max_completion_tokens`; 1,024 caused
rejections. The largest observed completion was 261 tokens. Truncation is recorded
(`finish_reason=length`) if it ever occurs.

**D-030 Throttling uses the provider's headers conservatively.** Before each call the controller
waits until `x-ratelimit-remaining-tokens` covers 1.25 × the estimated input + `max_output_tokens`,
honors `retry-after` on 429, and fails (non-retryable) instead of waiting longer than 90 s (e.g. a
daily quota). Verified live: 3 rate-limit errors before the fix, 0 after.

**D-031 Aborted episodes are separated.** An episode cut short by a run-level stop (budget,
quota, authentication, configuration) is written to `aborted_episodes.jsonl` for audit, excluded
from metrics, and re-run by `--resume`. Provider errors inside an otherwise healthy run (timeout,
5xx after retries, parse errors) stay in `episodes.jsonl` with their error status and are never
counted as defense successes.

**D-032 `agent_refused` is assigned by the grader (Phase 5), not the runtime.** The runtime cannot
reliably tell a refusal from a short answer; it records `completed` plus the final text, and the
private grader classifies refusals. Provider content-filter stops are `api_error`.

**D-033 Paid-equivalent pricing.** `configs/pricing.groq.yaml` holds Groq's published list price
for `qwen/qwen3.8-27b` (USD 0.80 / 4.00 per 1M input/output tokens, retrieved 2026-10-17 from the
model page) so cost per episode can be reported; the owner's free plan is actually charged $0.

**D-034 Real runs require explicit approval and a hard cap.** `agentshield run --provider real`
prints the estimate and exits with code 4 unless `--approve-real-usage` is given; if no token or
request cap is supplied, one is derived from the estimate (1.5× headroom). Real runs never fall
back to the fake model.
