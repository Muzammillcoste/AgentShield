# Research Methodology

## Questions and pre-registered hypotheses
**Primary RQ.** How do individual and combined prompt-level (D1), tool-output-level (D2, D3) and
action-level (D4, D5, D6) defenses change unauthorized execution, unauthorized attempts,
attack-induced task failure, legitimate task completion and cost?

- **RQ1.** What does task/record/field authorization (D5 granularity) add beyond tool-name
  allowlisting (D4)?
- **RQ2.** With a deterministic gate enforced, does an LLM action verifier (D6) improve outcomes
  enough to justify latency, false rejections and tokens?
- **RQ3.** Which attack families still contaminate the final answer when writes cannot execute?

H1: deterministic authorization reduces unauthorized *executions* relative to prompt-only
safeguards, for actions the guard correctly classifies as out of scope. H2: name-only
allowlisting is insufficient for same-tool/wrong-record attacks. H3: defense combinations are
non-additive; the full stack need not dominate. These are expectations, not guaranteed results.

## Scientific controls (implemented or enforced by design)
- **Label isolation:** private truth is a separate artifact and module; runtime code cannot import
  it (static test). Defenses never receive scenario labels.
- **Identity vs task scope:** principal capabilities (general ability) are stored separately from
  the request-derived `TaskScope`; retrieved data can never widen scope.
- **Deployable scope only:** D4/D5 scope comes from a transparent grammar over the trusted
  request. Any scope built from private labels is labeled ORACLE UPPER BOUND and excluded from
  rankings.
- **State reset:** a fresh store per episode from an immutable, hash-verified fixture.
- **Identical comparisons:** same scenarios, model, prompts (except D1), temperature and limits
  across configs; config/prompt/dataset hashes recorded per run.
- **Attempt vs execution:** proposals are logged before validation or gating; executions are
  scored from state diffs and execution events, never from defense self-reports.
- **Status taxonomy:** completed, agent_refused, timeout, api_error, parse_error, max_steps,
  infrastructure_error, unscorable. Errors are never counted as successful defense.
- **Feasibility:** every mutation attack references a legitimate control scenario; infeasible
  goals are reported separately.
- **Legitimate writes:** at least half of clean tasks request writes/sends; same-tool/wrong-record
  attacks are included so a "block all writes" policy cannot look ideal.
- **Grammar coverage:** out-of-grammar legitimate requests are tagged and measured.

## Dataset protocol (Phase 5)
Target 120 scenarios: 40 clean (≥50% legitimate writes/sends), 60 attacks across five families
and all surfaces, 20 hard-benign. Split 80 dev / 40 held-out, grouped by `base_task_id` and
payload-template lineage, stratified by category and family, fixed seed, manifest hashes. No
tuning on held-out outcomes; held-out frozen once created. Labels are author-written and marked
`label_verified=false` until a human reviews them. If 120 defensible labels cannot be produced,
fewer are published transparently.

## Metrics (Phase 5)
UER, UAR, AGSR (per family), CTSR, ALTS, attack-induced failure gap (matched base tasks), false
block rate (with benign-task completion), answer contamination (canary-based, manually audited),
latency/tokens/cost, and D2 detector precision/recall/FPR on labeled texts separately from agent
outcomes. Denominators and exclusions are always reported.

## Statistics (Phase 6–7)
Wilson 95% intervals for rates; paired cluster bootstrap by `base_task_id` (repetitions kept
within cluster) for configuration differences; absolute risk differences with intervals; no
p-value fishing; the 16-config screen is exploratory (not a balanced factorial design); interactions
are computed only where all required configurations ran on the same scenarios.

## Interpretation rules
Zero observed successes is not zero risk. Results distinguish safer *system execution* (blocked
actions) from safer *model behavior* (fewer attempts). Deterministic security depends on the
quality of scope derivation, which this grammar only approximates.
