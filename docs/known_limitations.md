# Known Limitations

Living list; updated each phase.

1. **Controlled grammar.** Task scope comes from a small regex grammar over the request. It is a
   laboratory approximation, not natural-language authorization; D4/D5 results depend on it and
   overstate what deployable scope derivation achieves on unconstrained requests.
2. **Synthetic CRM.** One fixture, two tenants, eight tools, 170 records. Not representative of
   real CRM scale, schemas or permission models; no claims about Salesforce or any product.
3. **Baseline without access control.** D0 performs schema validation only (by design); RBAC
   and tenant confinement are part of D5. Comparisons against `C05-rbac_only` are needed for a
   fair reading of H1/H2.
4. **Regex inspection (D2).** Deterministic patterns cannot detect paraphrased, multilingual or
   encoded attacks reliably; detector metrics are reported separately.
5. **D6 exposure.** The verifier sees proposed arguments, which may contain attacker text.
6. **Answer grading.** Deterministic canary/mention checks can misfire when the agent quotes a
   payload while warning about it; hits are manually audited.
7. **Small held-out set.** ~40 scenarios; intervals are wide and findings exploratory.
8. **Single model (initially).** Results may not transfer to other models; a second model is a
   stretch goal and is never pooled with the first.
9. **Non-determinism.** Temperature 0 and seeds do not guarantee identical real-model outputs;
   repetitions are recorded, and provider-side model updates are a threat to reproducibility.
10. **Labels not yet human-verified.** All Phase-1 example labels are author-written
    (`label_verified=false`).
11. **Fake model.** Its "susceptibility" is a regex simulation used to test plumbing; it says
    nothing about real LLM behavior.
12. **Instruct mode only.** The real model runs without thinking tokens (D-027); conclusions do
    not automatically transfer to its thinking mode.
13. **Free-tier throughput.** Groq free-plan limits (7K input / 1K output tokens per minute,
    1K requests/day, daily token cap unverified) make the full ~960-episode plan slow; run
    scope may need reduction or a paid tier, decided before Phase 6 and reported honestly.
14. **Rough estimates.** Pre-run token estimates use characters/4 and an offline call path;
    in Phase 2 they over-estimated actual usage by 8–18%. Recorded usage is always the
    provider's count.
15. **D2 rules are dev-derived.** They detect all 5 development attack payloads and none of the
    35 benign fixture texts, which is optimistic by construction; held-out detection is the
    meaningful number. Paraphrased, multilingual and encoded payloads are missed (tested).
16. **D3 cannot be validated with the fake agent.** Provenance marking only matters to a model
    that reads it; its effect is measurable only in real-model runs.
