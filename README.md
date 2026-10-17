# AgentShield

**A reproducible evaluation of layered defenses against indirect prompt injection in
tool-using enterprise agents.** An LLM agent operates a fully synthetic, in-memory CRM; an
attacker controls only free-text fields inside tool responses; six independently configurable
defenses (D1–D6) are measured for unauthorized attempts, unauthorized executions, legitimate
task success, answer contamination, false blocks, latency and cost.

> **Status: Phase 1 of 7 complete.** Foundations (schemas, synthetic CRM, central dispatcher,
> trusted scope grammar, fake model, defense registry, dataset validator) are implemented and
> tested. The real-model runtime, defenses, benchmark dataset and experiments are **NOT RUN**
> yet. No research results exist at this stage.

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
```

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

## Real models

Real providers arrive in Phase 2 via an OpenAI-compatible adapter. Configure credentials only in
a local `.env` (see `.env.example`); never commit keys. Paid experiments run only after explicit
approval, with token/cost estimates and hard budget caps. The fake model is for testing only and
is never presented as research evidence.

## License
MIT (see `LICENSE`).
