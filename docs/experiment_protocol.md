# Experiment Protocol

## Configuration registry (implemented: `configs/defenses.yaml`, `defenses/registry.py`)

| ID | Defenses | ID | Defenses |
|---|---|---|---|
| C00 | none (D0) | C08 | D2+D3 |
| C01 | D1 | C09 | D4+D5 |
| C02 | D2 | C10 | D3+D6 |
| C03 | D3 | C11 | D1+D2+D3 |
| C04 | D4 | C12 | D1+D4+D5 |
| C05 | D5 | C13 | D2+D4+D5 |
| C06 | D6 | C14 | D1+D2+D3+D4+D5+D6 |
| C07 | D1+D3 | C15 | D1+D3+D4+D5+D6 |

Derived: `M00`–`M63` (all combinations), `C14-noD1`…`C14-noD6` (leave-one-out),
`C05-rbac_only` / `-task_and_tool` / `-record` / `-record_field_value` (D5 granularity),
`ORACLE-C05`, `ORACLE-C09` (ORACLE UPPER BOUND, diagnostic only). Defaults: D2 `quarantine`,
D5 `record_field_value`, D6 same model as agent, no shadow evaluation. Inspect with
`uv run agentshield list-configs` / `show-config <ID>`.

## Run plan (paid steps require explicit approval and a budget cap)

1. Offline: unit/integration tests and fake-model smoke runs (no cost).
2. Free provider check: list models; verify the configured model exists.
3. **Pilot (paid, approval):** 10–20 dev scenarios × C00, C05, C09; inspect traces, tool-call
   reliability, feasibility controls and actual cost.
4. **Dev screening (paid, approval):** 16 configs × fixed stratified 30 dev scenarios × 1 rep
   (480 episodes).
5. **Selection (dev only):** up to four finalists by severe-execution safety, clean utility,
   false-block rate, cost/latency and simplicity; reject block-everything configs; show the
   Pareto frontier. Freeze model version, prompts, detector rules, grammar, config hashes,
   grader and dataset manifest in `configs/final_selection.yaml`.
6. **Held-out (paid, approval):** finalists × 40 held-out × 3 reps (480 episodes).
7. Ablations on dev: D5 granularity and leave-one-out; held-out only if pre-registered.

Planned core ≈ 960 episodes (not API calls; calls per episode vary). Before each paid step the
estimator reports expected requests/tokens/cost (cost only with user-supplied prices), the run
enforces token/USD/request caps, and actual usage is logged per episode.

## Real-model workflow (implemented, Phase 2)

```bash
uv run agentshield check-provider                 # free: lists models, confirms the configured one
uv run agentshield estimate --provider real ...   # no API calls; tokens, calls, paid-equivalent USD
uv run agentshield run --provider real ... --approve-real-usage --max-total-tokens N --output DIR
uv run agentshield run ... --resume --output DIR  # continue after a quota/budget stop
```

Measured free-plan limits for `qwen/qwen3.8-27b` (owner's account, 2026-10-17, from headers and 429
messages): 1,000 requests/day; 8,000 tokens/min combined = 7,000 input + 1,000 output tokens/min.
The daily token limit is not reported in headers (documentation lists 200K/day; unverified for
this plan). Baseline clean episodes used 2.6K–5.7K tokens (mean ≈ 3.9K over 8 episodes).

## Freeze rules
No change to prompts, rules, grammar, policy, model or dataset after any held-out outcome is
seen. New ideas inspired by held-out results require a new evaluation set.

## Run artifacts (Phase 5+)
`manifest.json`, `episodes.jsonl`, per-episode traces, `summary.csv/json`,
`per_attack_family.csv`, `paired_comparison.csv`, charts, `validation_report.json`,
`research_report.md` (generated only from real run data; otherwise marked NOT RUN). A rescore
mode recomputes all metrics from stored traces without model calls.
