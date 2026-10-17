# Development Log

## 2026-10-17 — Phase 1: foundations (complete, awaiting review)

### Completed
- Repository scaffold: `pyproject.toml` (uv, Python 3.12.13, hatchling), `.python-version`,
  `.gitattributes` (LF), `.gitignore` extended (kept existing `.sf`, `.env` entries),
  `.env.example`, `configs/*.yaml`, `LICENSE` (MIT placeholder), CI workflow.
- Schemas: domain, public scenario + attack surface, private truth, trace events, LLM contracts,
  defense config with semantic hash/bitmask, episode result/status.
- Synthetic CRM: deterministic `crm_fixture_v1` generator (2 tenants, 8 principals in 5 roles,
  8 aliases incl. 2 external bridges, 20 customers, 79 invoices, 30 opportunities, 41 cases),
  per-episode store with snapshots and field-level diffs, eight typed tools, central dispatcher
  with gate hooks, deny precedence, fail-closed gates and tenant observation.
- Trusted scope resolver (grammar v1) with read-only fallback.
- Fake LLM client (scripted steps, malformed args, refusal, failures, injection follower).
- Defense registry: 16 primary, 64 bitmask, 6 leave-one-out, 4 D5 granularity, 2 oracle configs.
- Dataset tooling: public/private loaders, validator, manifest; 11 example scenario pairs.
- CLI: `list-configs`, `show-config`, `fixture-info`, `resolve-scope`, `validate-data`,
  `build-manifest`.
- Docs: implementation plan, decisions (D-001…D-026), threat model, architecture, methodology,
  experiment protocol, limitations.

### Verification (actual results)
- `uv run pytest -q` → 211 passed.
- Mutation check: disabling deny precedence and widening the unresolved-scope fallback made
  12 tests fail; restored code → 211 passed.
- `uv run ruff check` / `ruff format --check` → clean; `uv run mypy` (strict) → no issues
  (30 source files).
- `uv run python scripts/generate_fixtures.py --check` → identical, hash `c2c04f1f7a79…`.
- `uv run agentshield validate-data --strict-manifest` → VALID (11/11, 0 errors, 0 warnings,
  11 unverified labels).

### Owner decisions (2026-10-17)
- Real provider confirmed: Groq, `qwen/qwen3.8-27b`, free plan (D-003). Cost $0; rate limits
  and daily quotas are the constraint.
- Commits allowed; the owner is the sole author (no co-author or tool attribution).

### Pending / blocked
- Phase 2 (real provider, agent runtime, rate-limit/token budget) awaits the owner's go-ahead.
- No real-model call has been made.
- Still open: injection-delivery default (D-006), license (D-019), out-of-grammar share (D-021).

### Reproduce
```bash
uv sync
uv run pytest -q
uv run python scripts/generate_fixtures.py --check
uv run python scripts/build_example_scenarios.py   # rewrites examples deterministically
uv run agentshield validate-data --strict-manifest
uv run agentshield list-configs
```
