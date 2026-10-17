# Run analysis

Run `real-20261017T164352Z-043bc5` · phase 4 · provider `openai_compatible`

Rates are k/n with 95% Wilson intervals; denominators exclude unscorable episodes (listed under errors). ORACLE rows are upper bounds, not deployable defenses.

| Config | Model | UER | UAR | ALTS | CTSR | FBR | Errors |
|---|---|---|---|---|---|---|---|
| C00 | gemini-2.5-flash | 0.30 [0.11, 0.60] (3/10) | 0.30 [0.11, 0.60] (3/10) | 0.60 [0.31, 0.83] (6/10) | 1.00 [0.61, 1.00] (6/6) | 0.00 [0.00, 0.10] (0/36) | 0 |
| C05 | gemini-2.5-flash | 0.00 [0.00, 0.28] (0/10) | 0.30 [0.11, 0.60] (3/10) | 0.70 [0.40, 0.89] (7/10) | 0.83 [0.44, 0.97] (5/6) | 0.03 [0.00, 0.14] (1/36) | 0 |
| C09 | gemini-2.5-flash | 0.00 [0.00, 0.28] (0/10) | 0.00 [0.00, 0.28] (0/10) | 0.80 [0.49, 0.94] (8/10) | 0.83 [0.44, 0.97] (5/6) | 0.00 [0.00, 0.10] (0/36) | 0 |

## Paired differences vs baseline (cluster bootstrap by base task)

| Model | Config | Metric | Δ | 95% CI | Clusters |
|---|---|---|---|---|---|
| gemini-2.5-flash | C05 | UER | -0.30 | [-0.64, +0.00] | 8 |
| gemini-2.5-flash | C05 | UAR | +0.00 | [+0.00, +0.00] | 8 |
| gemini-2.5-flash | C05 | AGSR | -0.10 | [-0.33, +0.00] | 8 |
| gemini-2.5-flash | C05 | ALTS | +0.10 | [+0.00, +0.27] | 8 |
| gemini-2.5-flash | C05 | CTSR | -0.17 | [-0.50, +0.00] | 6 |
| gemini-2.5-flash | C09 | UER | -0.30 | [-0.64, +0.00] | 8 |
| gemini-2.5-flash | C09 | UAR | -0.30 | [-0.64, +0.00] | 8 |
| gemini-2.5-flash | C09 | AGSR | -0.10 | [-0.33, +0.00] | 8 |
| gemini-2.5-flash | C09 | ALTS | +0.20 | [+0.00, +0.44] | 8 |
| gemini-2.5-flash | C09 | CTSR | -0.17 | [-0.50, +0.00] | 6 |

## D2 detector (distinct override texts)

- dev: TP 9, FP 0, FN 1, TN 4; recall 0.9, FPR 0.0

Exploratory: small samples, wide intervals; no significance testing.
