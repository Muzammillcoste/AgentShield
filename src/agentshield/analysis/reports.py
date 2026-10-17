"""Rescore a run from its stored artifacts (no model calls) and write the analysis bundle:
grades.csv, summary.csv/json, per_attack_family.csv, paired_comparison.csv, detector.json,
figures and a short report.md. Fake-model runs are labeled NOT RESEARCH EVIDENCE."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pandas as pd

from agentshield.analysis import plots
from agentshield.benchmark.artifacts import load_episodes
from agentshield.benchmark.grader import EpisodeGrade, grade_episode
from agentshield.benchmark.metrics import group, paired_comparisons, per_family, summarize
from agentshield.benchmark.statistics import wilson
from agentshield.crm.fixtures import CRMFixture
from agentshield.defenses.d2_inspector import D2_RULESET_VERSION, inspect_text
from agentshield.schemas.scenario import ScenarioPublic
from agentshield.schemas.truth import OverrideLabel, ScenarioPrivateTruth


def grade_run(
    run_dir: Path,
    scenarios: Mapping[str, ScenarioPublic],
    truths: Mapping[str, ScenarioPrivateTruth],
    fixture: CRMFixture,
) -> list[EpisodeGrade]:
    grades = []
    for episode in load_episodes(run_dir / "episodes.jsonl"):
        sid = episode.scenario_id
        grades.append(grade_episode(episode, scenarios[sid], truths[sid], fixture))
    return grades


def detector_metrics(
    scenarios: Sequence[ScenarioPublic], truths: Mapping[str, ScenarioPrivateTruth]
) -> dict[str, Any]:
    """D2 precision/recall/FPR on individually labeled override texts, per split."""
    out: dict[str, Any] = {"ruleset": D2_RULESET_VERSION}
    for split in sorted({s.split.value for s in scenarios}):
        tp = fp = fn = tn = 0
        seen: set[str] = set()
        for s in scenarios:
            truth = truths.get(s.scenario_id)
            if s.split.value != split or s.injection is None or truth is None:
                continue
            text = s.injection.replacement_text
            if text in seen:  # count each distinct text once
                continue
            seen.add(text)
            flagged = inspect_text(text).flagged
            malicious = truth.override_label is OverrideLabel.MALICIOUS
            tp += flagged and malicious
            fp += flagged and not malicious
            fn += (not flagged) and malicious
            tn += (not flagged) and not malicious
        recall, r_lo, r_hi = wilson(tp, tp + fn)
        fpr, f_lo, f_hi = wilson(fp, fp + tn)
        precision = tp / (tp + fp) if tp + fp else None
        out[split] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "recall_ci": [r_lo, r_hi],
            "fpr": fpr,
            "fpr_ci": [f_lo, f_hi],
        }
    return out


def _label(config_id: str, model_id: str, multi_model: bool) -> str:
    label = config_id if not config_id.startswith("ORACLE") else f"{config_id} (ORACLE)"
    return f"{label} [{model_id}]" if multi_model else label


def write_bundle(
    grades: Sequence[EpisodeGrade],
    output: Path,
    *,
    detector: dict[str, Any] | None = None,
    baseline: str = "C00",
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([g.model_dump() for g in grades]).to_csv(output / "grades.csv", index=False)
    models = {g.model_id for g in grades}
    rows = []
    for (config, model), items in sorted(group(grades, "config_id", "model_id").items()):
        row = {
            "config_id": config,
            "model_id": model,
            "label": _label(config, model, len(models) > 1),
            "oracle_upper_bound": config.startswith("ORACLE"),
        }
        row |= summarize(items)
        rows.append(row)
    flat = [{k: (json.dumps(v) if isinstance(v, dict) else v) for k, v in r.items()} for r in rows]
    pd.DataFrame(flat).to_csv(output / "summary.csv", index=False)
    (output / "summary.json").write_text(
        json.dumps(rows, indent=2, default=str) + "\n", encoding="utf-8"
    )
    families = per_family(grades)
    pd.DataFrame(families).to_csv(output / "per_attack_family.csv", index=False)
    configs = sorted({g.config_id for g in grades})
    paired = paired_comparisons(grades, baseline, configs)
    pd.DataFrame(paired).to_csv(output / "paired_comparison.csv", index=False)
    if detector is not None:
        (output / "detector.json").write_text(
            json.dumps(detector, indent=2) + "\n", encoding="utf-8"
        )

    figures = [
        plots.security_utility(rows, output / "security_utility.png"),
        plots.attempts_vs_executions(rows, output / "attempts_vs_executions.png"),
        plots.family_heatmap(families, output / "family_agsr.png"),
        plots.tokens_box(
            {
                r["label"]: [
                    g.input_tokens + g.output_tokens
                    for g in grades
                    if g.config_id == r["config_id"] and g.model_id == r["model_id"]
                ]
                for r in rows
            },
            output / "tokens.png",
        ),
    ]
    fake = any(g.provider_kind == "fake" for g in grades)
    _write_report(output / "report.md", rows, paired, detector, fake, manifest)
    return {"summary": rows, "figures": [str(f) for f in figures if f], "fake": fake}


def _fmt(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if value is None:
        return "n/a"
    low, high = row[key + "_lo"], row[key + "_hi"]
    return f"{value:.2f} [{low:.2f}, {high:.2f}] ({row[key + '_k']}/{row[key + '_n']})"


def _write_report(
    path: Path,
    rows: Sequence[dict[str, Any]],
    paired: Sequence[dict[str, Any]],
    detector: dict[str, Any] | None,
    fake: bool,
    manifest: dict[str, Any] | None,
) -> None:
    lines = ["# Run analysis", ""]
    if fake:
        lines += [
            "> **FAKE MODEL OUTPUT — NOT RESEARCH EVIDENCE.** "
            "This analysis tests the pipeline only.",
            "",
        ]
    if manifest:
        lines += [
            f"Run `{manifest.get('run_id')}` · phase {manifest.get('phase')} · "
            f"provider `{manifest.get('provider_kind')}`",
            "",
        ]
    lines += [
        "Rates are k/n with 95% Wilson intervals; denominators exclude unscorable episodes "
        "(listed under errors). ORACLE rows are upper bounds, not deployable defenses.",
        "",
        "| Config | Model | UER | UAR | ALTS | CTSR | FBR | Errors |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['label']} | {r['model_id']} | {_fmt(r, 'UER')} | {_fmt(r, 'UAR')} | "
            f"{_fmt(r, 'ALTS')} | {_fmt(r, 'CTSR')} | {_fmt(r, 'FBR')} | {r['unscorable']} |"
        )
    if paired:
        lines += [
            "",
            "## Paired differences vs baseline (cluster bootstrap by base task)",
            "",
            "| Model | Config | Metric | Δ | 95% CI | Clusters |",
            "|---|---|---|---|---|---|",
        ]
        for p in paired:
            if p["difference"] is None:
                continue
            lines.append(
                f"| {p['model_id']} | {p['config_id']} | {p['metric']} | {p['difference']:+.2f} | "
                f"[{p['ci_low']:+.2f}, {p['ci_high']:+.2f}] | {p['clusters']} |"
            )
    if detector:
        lines += ["", "## D2 detector (distinct override texts)", ""]
        for split, d in detector.items():
            if isinstance(d, dict):
                lines.append(
                    f"- {split}: TP {d['tp']}, FP {d['fp']}, FN {d['fn']}, TN {d['tn']}; "
                    f"recall {d['recall']}, FPR {d['fpr']}"
                )
    lines += ["", "Exploratory: small samples, wide intervals; no significance testing."]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
