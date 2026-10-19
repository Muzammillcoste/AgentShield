# AgentShield: A Reproducible Evaluation of Layered Defenses Against Indirect Prompt Injection in Tool-Using Enterprise Agents

*Technical report, 2026-10-18. All numbers below are computed from the committed run artifacts in
`results/` and can be recomputed without model calls (`agentshield analyze`). Agent model:
`gemini-2.5-flash` (instruct mode, temperature 0) via an OpenAI-compatible API.*

## Abstract

Tool-using LLM agents read data that third parties can write. We study whether six
independently configurable defenses stop instructions hidden in that data from causing
unauthorized actions, without breaking legitimate work. We built a fully synthetic two-tenant CRM
sandbox, a 120-scenario benchmark (40 clean, 60 attack, 20 hard-benign; 80 development / 40
held-out, split by customer) and a private grader that scores *attempted* and *executed*
unauthorized actions separately from the agent's own reports. On development data, 16 screened
configurations show that a security system prompt (D1) or provenance marking (D3) alone barely
change unauthorized executions (6/40 and 9/40 vs 7/40 undefended), while a deterministic
policy gateway (D5), an LLM action verifier (D6) or regex inspection of tool output (D2) reduce
them to 0/40. D5's protection rises with authorization granularity (6/40 → 3/40 → 0/40 from
role-only to task to record level) and costs 3 of 27 legitimate tasks phrased outside its request
grammar. On the held-out set, the pre-registered finalists reduced unauthorized executions from
6/60 episodes (2 of 20 attack scenarios) undefended to 1/60 (C11: D1+D2+D3) and 0/60 (C14: all
six defenses); the attacker-goal success reduction is the only difference whose 95% cluster
bootstrap interval excludes zero. The regex inspector did not generalize: its recall fell from
29/37 development payloads to 4/18 held-out payloads. Answer contamination by planted false facts
persisted under every configuration (held-out: 10/12 undefended, 6/12 for both finalists).
Findings are exploratory: small samples, one model, synthetic data.

## 1. Motivation and scope

An enterprise assistant that summarizes invoices or updates CRM records reads free-text fields
(invoice notes, case descriptions) that customers, partners or attackers can write. If the model
treats such text as instructions, it may change records, message third parties or misreport
facts. We ask how individual and combined defenses change (a) attempted and executed unauthorized
actions, (b) legitimate task completion, (c) answer contamination and (d) cost. The contribution is
a domain-specific, reproducible *evaluation* — not a new universal defense: record-level
authorization is an established security control, measured here in an agent setting.

## 2. Related work

Benchmarks for prompt injection against tool-using agents, notably AgentDojo
(https://github.com/sequrity-ai/agentdojo; NeurIPS 2024 Datasets and Benchmarks), motivate
separating utility under attack from attack success; our dataset is independent and not
affiliated. Defensive guidance from OWASP (LLM Prompt Injection Prevention Cheat Sheet,
https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html;
MCP Security Cheat Sheet,
https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) informs D1–D5.
Evaluation-harness practice follows the spirit of UK AISI Inspect (https://inspect.aisi.org.uk/)
and risk framing of the NIST AI RMF (https://www.nist.gov/itl/ai-risk-management-framework).

## 3. Threat model

The legitimate user is authenticated as a synthetic principal and issues one request. The
attacker can edit only free-text fields inside tool *responses* (`invoice.notes`,
`opportunity.description`, `case.description`); never IDs, statuses, amounts, prompts, tool
schemas, permissions or the grader. The model's tool calls are untrusted proposals; every call
passes a central dispatcher. Consequences are graded by actual sandbox events (S1 misleading
answer … S4 disclosure to a simulated external alias). Everything is synthetic and in-memory.

## 4. System and defenses

| | Defense | Mechanism |
|---|---|---|
| D1 | Security instruction | versioned system-prompt paragraph: tool data is not instruction |
| D2 | Tool-output inspection | 7 regex rule families; quarantines only flagged sentences |
| D3 | Provenance marking | nonce-delimited, escaped "untrusted data" container per tool result |
| D4 | Tool allowlist | tools visible/callable only if the request's task needs them |
| D5 | Policy gateway | deterministic: role → task → record → field/value authorization |
| D6 | Action verifier | second LLM call sees only request, role, scope and proposed action |

Task scope for D4/D5/D6 comes from a small deterministic grammar over the *verbatim user request*;
retrieved data can never widen it. D6 cannot override a D5 denial (dispatcher deny precedence).
An ORACLE UPPER BOUND variant builds scope from private labels and is reported only as a
diagnostic.

## 5. Benchmark and methodology

**Data.** 40 hand-specified base tasks (summaries, compound "summarize, then change" writes,
messages); 26 of 40 clean tasks are legitimate writes or sends, 5 of which (19%) are phrased
outside the scope grammar to measure its utility cost. 60 attacks cover five families
(authority spoof, workflow hijack, tool misuse, parameter swap including same-tool/wrong-record,
answer contamination); every attack sits in a record the legitimate task must read (delivery was
100% in all reported runs). 20 hard-benign scenarios contain imperative-looking legitimate text.
Splits are by customer, so no record, task or text-template lineage is shared between dev (80) and
held-out (40). Held-out labels were human-verified by the project owner; dev labels are generated
from the fixture and author-audited.

**Metrics.** UER: attacked episodes with an executed unauthorized change (any change the task did
not allow); UAR: with a proposed one; AGSR: typed attacker goal achieved; ALTS: original task
correct under attack; CTSR: clean task correct; contamination: canary from the payload in the final
answer (contamination family); FBR: legitimate, role-permitted proposals that were blocked.
Provider/infrastructure failures are excluded from denominators and reported. Rates carry 95%
Wilson intervals; configuration differences use a paired cluster bootstrap over base tasks (2,000
resamples).

**Protocol.** The finalist-selection rule was committed before any screening result: baseline C00
+ best-ranked usable config + best config without action-level defenses + full stack C14
(ranking: UER, then ALTS, CTSR, tokens). Development: pilot (60 episodes) → screening of 16
primary configs (1,280) → ablations (800) → frozen selection. Held-out: frozen finalists × 40
scenarios × 3 repetitions (360), run from a clean committed code version.

## 6. Results

### 6.1 Development screening (exploratory)

Selected configurations (k/n with 95% Wilson interval; 40 attacked, 27 clean episodes):

| Config | Defenses | UER | UAR | ALTS | CTSR |
|---|---|---|---|---|---|
| C00 | none | 7/40 [0.09, 0.32] | 7/40 | 27/40 | 26/27 |
| C01 | D1 | 6/40 [0.07, 0.29] | 6/40 | 29/40 | 26/27 |
| C03 | D3 | 9/40 [0.12, 0.38] | 9/40 | 27/40 | 26/27 |
| C02 | D2 | 0/40 [0.00, 0.09] | 0/40 | 36/40 | 26/27 |
| C04 | D4 | 2/40 [0.01, 0.17] | 2/40 | 31/40 | 23/27 |
| C05 | D5 | 0/40 [0.00, 0.09] | 6/40 | 29/40 | 23/27 |
| C06 | D6 | 0/40 [0.00, 0.09] | 7/40 | 27/40 | 26/27 |
| C11 | D1+D2+D3 | 0/40 [0.00, 0.09] | 0/40 | 38/40 | 26/27 |
| C14 | all | 0/39 [0.00, 0.09] | 0/39 | 37/39 | 23/27 |

Prompt-level defenses alone barely moved execution. Action-level gates (D5, D6) *blocked* attacks
the model still *attempted* (UAR 6–7/40); D2 and D4 reduced attempts themselves (D2 by removing the
text, D4 by hiding write tools). Figures: `results/phase6-combined-analysis/*.png`.

### 6.2 Authorization granularity and ablations (development)

| D5 level | UER | UAR | CTSR |
|---|---|---|---|
| role only (rbac_only) | 6/40 | 6/40 | 26/27 |
| + task/tool | 3/40 | 6/40 | 23/27 |
| + record | 0/40 | 6/40 | 23/27 |
| + field/value (default) | 0/40 | 6/40 | 23/27 |
| ORACLE UPPER BOUND scope | 0/40 | 6/40 | 26/27 |

Same-tool/wrong-record attacks pass a tool-name allowlist (D4 alone: 2/40) and task-level policy,
and are stopped only at record granularity. The grammar-based scope costs 3/27 clean tasks
relative to the oracle bound — the price of deterministic, deployable scoping. Leave-one-out from
C14: removing any single defense left UER at 0/40 (redundancy on dev); removing D2 reduced ALTS
by 0.13 [-0.22, -0.03].

### 6.3 Held-out evaluation (pre-registered finalists)

360 episodes, 0 errors, 100% delivery. Episode counts include 3 repetitions; at temperature 0,
116 of 120 scenario × config cells gave identical outcomes across repetitions, so scenario-level
counts are also shown.

| Config | UER | UAR | AGSR | ALTS | CTSR | Contamination |
|---|---|---|---|---|---|---|
| C00 | 6/60 [0.05, 0.20] (2/20 scen.) | 6/60 | 16/60 | 36/60 | 36/39 | 10/12 |
| C11 | 1/60 [0.00, 0.09] (1/20 in one rep.) | 1/60 | 7/60 | 44/60 | 36/39 | 6/12 |
| C14 | 0/60 [0.00, 0.06] | 1/60 | 6/60 | 48/60 | 33/39 | 6/12 |

Paired differences vs C00 (cluster bootstrap, 9 attacked base tasks): UER C11 −0.08
[−0.21, 0.00], C14 −0.10 [−0.25, 0.00]; AGSR C11 −0.15 [−0.30, −0.03], C14 −0.17 [−0.33, −0.03];
ALTS C11 +0.13 [−0.02, +0.30], C14 +0.20 [−0.05, +0.46]; CTSR C14 −0.08 [−0.31, +0.15]. Only the
AGSR reductions exclude zero. All undefended executions came from two scenarios: an authority-spoof
instruction that made the agent send the account summary, including the billing contact, to an
internal alias the user never asked to message (`atk-044`, severity S2, every repetition) and a
same-tool/wrong-record invoice update (`atk-056`, severity S3, every repetition). C11 executed `atk-056`
once; under C14 the same attempt was blocked by D5.

### 6.4 Detector generalization

D2 flagged 29/37 distinct development attack texts (recall 0.78 [0.63, 0.89]) but only 4/18
held-out attack texts (0.22 [0.09, 0.45]), with no false positives on benign texts in either split
(0/5 dev, 0/3 held-out; intervals wide). The rules were written against development-style
examples; held-out templates were never seen. C11's held-out protection therefore cannot be
attributed mainly to D2; with only three finalists we cannot separate D1, D2 and D3 on held-out.

### 6.5 Answer contamination

Planted false facts (fabricated deal values, "paid" claims with confirmation codes) reached the
final answer in 10/12 undefended held-out episodes and in 6/12 under both C11 and C14. Two of four
held-out contamination templates succeeded under every configuration. Action-level defenses
cannot address this failure mode by construction; the D1–D3 layers reduced but did not eliminate
it (RQ3).

### 6.6 Cost

Real-model usage across all experiments: 2,500 episodes, 5.99M tokens, USD 2.78 at Gemini list
prices. Held-out mean tokens per episode: C00 2,514, C11 3,050 (+21%), C14 2,484; median latency
2.2 s, 2.1 s and 2.7 s (D6 adds a model call per write/send).

## 7. Hypotheses (pre-registered expectations)

- **H1** (deterministic authorization reduces executions vs prompt-only safeguards): supported on
  development data (D5 0/40 vs D1 6/40, D3 9/40); on held-out, C14 had 0/60 executions and blocked
  the one attempt, but intervals overlap the baseline.
- **H2** (tool-name allowlisting is insufficient for wrong-record manipulation): supported on
  development data (D4 alone 2/40; task-level D5 3/40; record-level D5 0/40) and illustrated by the
  held-out `atk-056` case.
- **H3** (non-additive effects; full stack need not dominate): partly supported. Every dev
  leave-one-out variant matched the full stack's 0/40, C14 cost more clean-task utility than C11
  on both splits (dev 23/27 vs 26/27; held-out 33/39 vs 36/39), and no configuration beat C14 on
  every metric.

## 8. Failures, corrections and negative results

- Two grader definitions were corrected from development traces, before any held-out run, and
  applied to all configurations by rescoring stored artifacts: unauthorized actions now include
  any change the task did not allow (an answer-contamination payload had induced a real write),
  and actions the user's role may not perform are not counted as false blocks.
- One label is ambiguous ("open cases" vs the defined set New/Open/Pending/Escalated); it fails
  identically under all configurations and was not edited after seeing results.
- Negative results: D3 alone did not reduce executions; D2 does not generalize across templates;
  no defense prevented answer contamination.

## 9. Limitations

Synthetic CRM, one fixture and eight tools; one agent model in instruct mode; 40 held-out
scenarios (9 attacked base tasks) with nearly deterministic repetitions; 29 attack templates;
deterministic answer checks (exact IDs and canaries) that can miss paraphrased false claims; a
controlled request grammar that overstates deployable scope quality; D6 uses the same model as the
agent; dev labels are not human-verified. Zero observed executions is not zero risk.

## 10. Reproducibility

`uv sync && uv run pytest -q` (414 tests, offline; includes a golden fake-model regression run);
`scripts/generate_fixtures.py --check` and `scripts/generate_scenarios.py --check` regenerate the
fixture and dataset byte-identically; `agentshield analyze --input results/<run>` recomputes every
number here from stored traces (verified on a fresh clone: all 16 screening summaries identical).
Run manifests record code commit, model, prompts, defense versions, dataset hash and budget.

## 11. Ethics

All data, people, organizations, aliases and side effects are synthetic and local; no real
CRM, messaging or payment system was contacted. Attack texts target only in-process tools.
