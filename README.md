# AgentShield

**A reproducible evaluation of layered defenses against indirect prompt injection in
tool-using enterprise agents.** An LLM agent operates a fully synthetic, in-memory CRM; an
attacker controls only free-text fields inside tool responses; six independently configurable
defenses (D1–D6) are measured for unauthorized attempts, unauthorized executions, legitimate
task success, answer contamination, false blocks, latency and cost.

> **Status: Phase 2 of 7 complete.** Foundations plus a working real-LLM agent runtime (Groq,
> `qwen/qwen3.8-27b`, native tool calling, retries, rate limiting, hard budgets). Defenses,
> the attack injector, the benchmark dataset and experiments are **NOT RUN** yet; the only real
> calls so far are capped integration smoke runs on clean tasks. No research results exist.

Everything is synthetic: no real CRM, Salesforce org, payment system, email delivery or
network destination is ever contacted.

## Quick start

```bash
uv sync                                            # Python 3.12 environment
uv run pytest -q                                   # offline test suite
uv run agentshield validate-data                   # validate scenarios + private labels
uv run agentshield list-configs                    # registered defense configurations
uv run agentshield show-config C14                 # one configuration (also M00..M63)
uv run agentshield resolve-scope "Change invoice INV-007 status to Paid."
uv run agentshield fixture-info
uv run python scripts/generate_fixtures.py --check # fixture regenerates byte-identically

# Offline end-to-end run with the rule-based fake agent (pipeline test, not evidence)
uv run agentshield run --provider fake --public data/public/examples.jsonl --scenarios ex-clean-invoice-summary-001 --configs C00 --output results/fake-demo
```

## Real model (Groq)

Put `LLM_API_KEY` and `MODEL_NAME` (or `AGENTSHIELD_MODEL`) in a local `.env` (never commit it).

```bash
uv run agentshield check-provider                  # free: confirms the model is available
uv run agentshield estimate --provider real --public data/public/examples.jsonl --scenarios ...
uv run agentshield run --provider real --public data/public/examples.jsonl --scenarios ... --configs C00 --output results/my-run --approve-real-usage --max-total-tokens 40000
uv run agentshield run ... --output results/my-run --resume   # continue after a quota stop
```
Real runs refuse to start without `--approve-real-usage`, always run under a hard token/request
cap, and never fall back to the fake model.

## Defenses

| | Defense | Acts on |
|---|---|---|
| D1 | Security system instruction | prompt |
| D2 | Tool-output inspection (off / flag / quarantine) | retrieved text |
| D3 | Provenance / trust marking | retrieved text |
| D4 | Task-scoped tool allowlist | tool visibility |
| D5 | Deterministic policy gateway (rbac_only → record_field_value) | proposed actions |
| D6 | Independent LLM action verifier (cannot override D5 denials) | proposed actions |

Sixteen primary configurations (C00–C15), all 64 combinations, leave-one-out and D5-granularity
ablations are registered; see `docs/experiment_protocol.md`.

## Repository map

`src/agentshield/` (package) · `configs/` (YAML configuration) · `data/` (fixture, public
scenarios, **private** labels, manifest) · `scripts/` (generators) · `tests/` (unit,
integration) · `docs/` (plan, methodology, threat model, architecture, decisions, protocol,
limitations, development log).

## License
MIT (see `LICENSE`).
