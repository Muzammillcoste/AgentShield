# AgentShield — Implementation Plan

Status: Phases 1–4 complete (2026-10-17). This plan follows the user's seven-phase order and maps it
onto the specification's day-gates (`AgentShield_Codex_Master_Prompt.md` §14).

## 1. Architecture synopsis

AgentShield measures how six optional prompt-injection defenses (D1–D6), alone and combined,
change unauthorized tool-call *attempts*, unauthorized *executions*, legitimate task success,
answer contamination, false blocks, latency and cost for a tool-using LLM agent operating a
synthetic two-tenant CRM.

```text
trusted request ──► scope resolver (grammar v1) ──► TaskScope ──┐
                                                                ▼
LLM client ◄──► agent runtime (Phase 2) ──► ToolDispatcher ──► [schema] ─► [tenant obs.] ─► gates D4/D5/D6 ─► CRMStore
     ▲                                          │                                                     │
     │                         tool result ◄────┘ ◄── injector ◄── D2 inspect ◄── D3 provenance ◄─────┘ (Phase 3)
     │
system prompt (+D1)                    PRIVATE grader reads: trace + initial fixture + final state + private truth (Phase 5)
```

## 2. Trust boundaries

| Zone | Contents | May influence authorization? |
|---|---|---|
| Trusted fixture | principals, roles, tenants, aliases | Yes (identity, general role ability) |
| Trusted request | verbatim user request | Yes, only via the deterministic scope grammar |
| CRM structured fields | IDs, foreign keys, statuses, amounts | Read by trusted code for FK relations only |
| CRM free text (attack surface) | invoice notes, opportunity/case descriptions | **Never** |
| Model output | proposed tool calls, final answer | **Never** (untrusted proposals) |
| Private truth | expected changes, attacker goals, labels | **Never** (grader/validator only) |

## 3. Module dependency graph (acyclic)

```text
schemas.common ◄─ schemas.domain ◄─ schemas.{scenario,events,llm} ◄─ schemas.truth (private)
hashing ◄─ schemas.experiment
auth.principals ◄─ crm.fixtures ◄─ crm.store ◄─ crm.tools ◄─ crm.dispatcher
crm.tools ◄─ auth.scope_resolver
llm.protocol ◄─ llm.fake
config ◄─ defenses.registry
benchmark.{loader,truth_store,validation,manifest} ◄─ cli
```
Runtime packages (`crm`, `auth`, `llm`, `defenses`, later `injection`, `agent`) never import
`schemas.truth` or `benchmark` — enforced by `tests/unit/test_import_boundaries.py`.

## 4. Milestones and gates

| Phase | Scope | Gate (must pass before next phase) | Status |
|---|---|---|---|
| 1 | Repo, schemas, config, mock CRM, fixtures, scope grammar, dispatcher, fake LLM, validator, tests | Schema/scope/dispatcher tests pass; examples validate; fixture regenerates byte-identically; no LLM needed | **Done** |
| 2 | Real OpenAI-compatible provider, agent runtime loop, retries/backoff, token+cost accounting, budget guard, cost estimator, traces | Fake clean read/write episodes run through runtime; no state persists; real provider fails loudly without key; free `/models` check; capped real smoke run | **Done** |
| 3 | Injector, D1 prompt, D2 inspector (off/flag/quarantine), D3 provenance wrapper | Injection never changes trusted metadata/state; D2 positive/negative/adversarial tests; D3 delimiter-forging tests | **Done** |
| 4 | D4 allowlist, D5 policy (4 granularities), D6 verifier (fake + real), oracle diagnostic | Full D5 matrix (role-but-not-requested, wrong record/field/value, cross-tenant, ambiguous, deny-by-default); D6 cannot override D5 | **Done** |
| 5 | Dataset generator (target 120; 80 dev/40 held-out, grouped), private grader, metrics, runner, golden traces | Dataset validates; 4–8 scenario fake end-to-end run reproduces golden metrics | Pending |
| 6 | Real-model pilot (approved), dev screening of 16 configs, finalist selection, D5/LOO ablations | Reproducible artifacts; paired analyses; honest denominators | Pending (paid) |
| 7 | Held-out evaluation (approved), statistics, report, reproducibility check | Clean clone reproduces fake golden outputs; report numbers trace to artifacts | Pending (paid) |

## 5. Gaps, weaknesses and risks identified in the specification (with proposals)

1. **Grammar circularity (major).** If every dataset request is written in the same grammar the
   scope resolver parses, D4/D5 look near-perfect by construction. *Proposal:* include tagged
   out-of-grammar legitimate requests (`scope:out_of_grammar`, ~15–25% of legitimate-write tasks,
   both splits) so the utility cost of deterministic scoping is measured; freeze grammar before
   held-out; report grammar coverage alongside every D4/D5 result.
2. **Straw-man risk for H1.** Per spec, D0 enforces no RBAC/tenant checks (those are D5). A
   D0-vs-D5 gap therefore partly measures "having any access control at all". *Proposal:* report
   `C05-rbac_only` as the standard-practice comparator for H1 and H2.
3. **Single-shot injection delivery.** Spec default `apply_on_nth_matching_tool_result=1` shows
   the payload only once, creating inconsistent re-reads and undelivered attacks. *Proposal
   (adopted, D-006):* persistent entity-level override by default; log delivery per tool result;
   report delivery rate and conditional rates.
4. **Free-text answer grading is brittle** (negation, quoting the payload while warning about
   it). *Proposal (D-015):* canary-based attacker goals, deterministic forbidden/required mentions,
   manual audit of all canary hits, optional independent judge as secondary evidence only.
5. **D2 overfitting.** Regex rules tuned on dev payloads. *Proposal (D-022):* payload template
   lineage is a split-grouping key; held-out uses unseen templates; detector metrics reported
   per split.
6. **D6 is not injection-free.** D6 sees proposed arguments, and a message `body` can carry
   attacker text. *Proposal (D-026):* JSON-escape args, document as limitation, analyze D6
   failures on send actions separately.
7. **Statistical power.** 40 held-out scenarios (~20 attacks) × 4 finalists × 3 reps gives wide
   intervals; repetitions are not independent. Results are exploratory; cluster bootstrap by
   `base_task_id`.
8. **Real-model specifics.** The local `.env` points at a Groq-style key with model
   `qwen/qwen3.8-27b`. Availability, tool-calling reliability and reasoning-trace handling are
   unverified; feasibility controls are therefore essential, and reasoning text must never be
   logged as chain-of-thought.
9. **Cost unknown.** No pricing is invented; the user supplies official prices or cost is
   "unknown" and token caps are enforced instead.
10. **Workspace hygiene.** A `.sf/` directory with real Salesforce org metadata exists in the
    workspace. It is git-ignored and never read or used (sandbox-only rule).

## 6. Open questions for the project owner

- Phase 2 will verify model availability with a `/models` call before any experiment.
- Resolved 2026-10-17: Groq free plan with `qwen/qwen3.8-27b` (rate limits, not dollars, are
  the budget); MIT license; owner-authored commits; ~20% out-of-grammar legitimate writes;
  persistent injection delivery.
