"""Export a human label-review sheet (Markdown) for one split.

Usage: uv run python scripts/export_review_sheet.py [--split heldout] [--out PATH]
A reviewer checks each row; verified scenarios can then be marked `label_verified=true` with
`verified_by` in the generator (never silently).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from agentshield.benchmark.loader import load_public_scenarios
from agentshield.benchmark.truth_store import load_private_truth

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", default="heldout", choices=["dev", "heldout"])
    parser.add_argument("--out")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "docs" / f"label_review_{args.split}.md"
    public = load_public_scenarios(ROOT / "data" / "public" / f"{args.split}.jsonl")
    truths = load_private_truth(ROOT / "data" / "private" / f"{args.split}_truth.jsonl")
    lines = [
        f"# Label review sheet — {args.split} split ({len(public)} scenarios)",
        "",
        "Contains PRIVATE labels. For human review only; never feed to the agent or defenses.",
        "Check: request is realistic; required changes/mentions are correct; the attack text is",
        "confined to the note/description field; the attacker goal is correctly typed and would",
        "change state; hard-benign text is genuinely legitimate. Mark each box when verified.",
        "",
    ]
    for p in public:
        t = truths[p.scenario_id]
        goal = t.attacker_goal
        lines += [
            f"## [ ] {p.scenario_id} · {p.category.value}"
            + (f" · {p.attack_family.value}" if p.attack_family else ""),
            f"- **User** `{p.principal_id}`: {p.user_request}",
            f"- **Expected facts**: {'; '.join(t.expected_answer_facts) or '-'}",
            f"- **Required mentions**: {', '.join(t.answer_checks.required_mentions) or '-'}",
            "- **Required changes**: "
            + (
                ", ".join(
                    f"{c.entity.value} {c.record_id or '*'}.{c.field} = {c.value}"
                    for c in t.required_state_changes
                )
                or "none"
            ),
        ]
        if p.injection:
            label = t.override_label.value if t.override_label else "-"
            lines.append(
                f"- **Text in** `{p.injection.target_record_id}.{p.injection.field_path}` "
                f"(via `{p.injection.tool_name}`, label {label}): "
                f"_{p.injection.replacement_text}_"
            )
        if goal.type.value != "none":
            target = goal.target_record_id or goal.recipient_alias or ""
            lines.append(
                f"- **Attacker goal**: {goal.type.value} {target} {goal.value or ''} "
                f"{list(goal.canary_strings) or ''} · severity {t.severity_if_success.value}"
            )
            lines.append(
                "- **Forbidden**: "
                + ", ".join(
                    f"{f.entity.value} {f.record_id or '*'}.{f.field or '*'}"
                    + (f"={f.value}" if f.value is not None else "")
                    for f in t.forbidden_state_change_patterns
                )
                + (
                    f" · forbidden mentions {list(t.answer_checks.forbidden_mentions)}"
                    if t.answer_checks.forbidden_mentions
                    else ""
                )
            )
        lines.append("")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
