# Architecture

Status reflects Phase 2. Components marked *(Phase n)* are designed but not yet implemented.

## Package layout

| Module | Responsibility |
|---|---|
| `schemas/common.py` | `StrictModel` (frozen, `extra="forbid"`), ID formats, `EntityType` |
| `schemas/domain.py` | Principal, Customer, Invoice, Opportunity, SupportCase, InternalMessage, enums |
| `schemas/scenario.py` | **Public** `ScenarioPublic`, `InjectionSpec`, `ATTACK_SURFACES` |
| `schemas/truth.py` | **Private** `ScenarioPrivateTruth`, `AttackerGoal`, `StateChangePattern` |
| `schemas/events.py` | `StateChange`, `ToolCallProposal`, trace events, append-only `EventLog` |
| `schemas/llm.py` | Provider-neutral messages, tool calls, usage, `GenerationConfig` |
| `schemas/experiment.py` | `DefenseConfig` (+ semantic hash, bitmask), `EpisodeResult`, `EpisodeStatus` |
| `crm/fixtures.py` | Fixture contract with integrity checks; deterministic `crm_fixture_v1` generator |
| `crm/store.py` | Per-episode in-memory store, immutable snapshots, field-level `diff_states` |
| `crm/tools.py` | Eight typed tools: argument models, model-facing JSON schemas, handlers |
| `crm/dispatcher.py` | The only path from proposal to CRM: schema → tenant observation → gates → atomic execution |
| `auth/principals.py` | Role → general capability table; principal directory |
| `auth/scope_resolver.py` | Trusted deterministic request grammar → `TaskScope` |
| `llm/protocol.py` | `LLMClient` protocol, normalized `LLMError` |
| `llm/fake.py` | Deterministic scripted client (unit tests) |
| `llm/fake_agent.py` | Rule-based offline agent for end-to-end fake runs (never evidence) |
| `llm/settings.py` | Model config + environment → resolved settings (key as `SecretStr`) |
| `llm/openai_compatible.py` | Real client (official `openai` SDK → Groq), reasoning stripping, error mapping |
| `llm/resilience.py` | Retries/backoff, header-driven rate limiting, hard token/request/USD budget |
| `llm/prompts.py` | Versioned base system prompt (`base-v1`) |
| `llm/provider.py` | Client factory (real never degrades to fake) |
| `agent/runtime.py` | The agent loop: model ↔ dispatcher, observation pipeline, traces |
| `agent/observation.py` | Payload transformers (injection/D2 hooks) and serializer (D3 hook) |
| `defenses/registry.py` | 16 primary configs, 64 bitmask configs, leave-one-out, D5 granularity, oracle diagnostics |
| `benchmark/loader.py`, `truth_store.py` | Public loader (runtime-safe) / private truth loader (harness-only) |
| `benchmark/validation.py` | Dataset validator |
| `benchmark/manifest.py` | Content-hash manifest |
| `benchmark/runner.py` | Episode orchestration (fresh store per episode, resume, abort handling) |
| `benchmark/artifacts.py` | `episodes.jsonl`, aborted episodes, transcripts, run manifest |
| `benchmark/estimate.py` | Pre-run usage estimate (offline dry run) |
| `cli.py` | `agentshield` CLI |
| *(Phase 3)* `injection/`, `defenses/d1–d3` | Injector, security prompt, inspector, provenance |
| *(Phase 4)* `defenses/d4–d6`, `auth/policy.py` | Allowlist, policy gateway, verifier |
| *(Phase 5)* `benchmark/{grader,metrics,statistics}.py` | Private scoring, metrics, uncertainty |

## Dispatcher pipeline (implemented)

1. `ProposalEvent` — the proposal is logged before anything else (attempts are never lost).
2. Tool-call limit (default 16) — harness limit identical across configs.
3. Unknown tool / unparseable / schema-invalid arguments → `SchemaValidationEvent(ok=False)`.
4. `TenantCheckEvent` — observation; enforcement only by D5.
5. Gates in order (D4, D5, D6 from Phase 4) under the store lock: deny-precedence, ABSTAIN blocks
   writes/sends, exceptions fail closed, optional shadow evaluation.
6. Handler executes against the in-memory store → `ExecutionEvent` with field-level changes.
7. The structured payload returns to the runtime, where (Phase 3) injection, D2 and D3 transform
   a *copy* before it reaches the model; `ToolResultEvent` records exactly what the model saw.

## Agent loop (implemented, Phase 2)

1. Log the trusted scope (never shown to the model); build `[system, user]` messages and the
   visible tool schemas.
2. Each turn: the `CallController` checks the budget, waits for the rate-limit window, calls the
   model, retries transient errors and logs every attempt as a `ModelCallEvent`.
3. Tool calls go one by one through the dispatcher; the payload copy passes the transformers and
   serializer; a `ToolResultEvent` records exactly what the model saw; one tool message answers
   each provider call id.
4. Stop on a final answer (`completed`), provider error (`timeout`/`api_error`/`parse_error`),
   budget/quota/auth stop (`infrastructure_error`, run aborted), step or tool-call limit
   (`max_steps`) or wall-clock timeout.
5. Snapshot the final state and compute the diff against the initial snapshot.

## Information flow guarantees

- Gates receive an `ActionRequest` containing only the call, the principal and trusted store
  lookups; they never see scenario labels, private truth or tool-output text.
- The scope resolver is a pure function of the verbatim request string.
- `tests/unit/test_import_boundaries.py` statically forbids runtime → harness/truth imports.
- Each episode gets a fresh `CRMStore` built from the immutable fixture; tests verify isolation.
