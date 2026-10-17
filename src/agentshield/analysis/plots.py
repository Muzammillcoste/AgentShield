"""Static report figures (PNG). Colors: reference palette slots 1-2 for the two-series
charts, a single-hue sequential map for magnitudes, neutral ink for all text. One y-axis per
chart; legends whenever two series share a chart."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

SERIES_1 = "#2a78d6"  # blue
SERIES_2 = "#eb6834"  # orange
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3df"
SURFACE = "#fcfcfb"


def _style(ax: Any, title: str) -> None:
    ax.set_facecolor(SURFACE)
    ax.set_title(title, color=INK, fontsize=11, loc="left")
    ax.tick_params(colors=INK_2, labelsize=8)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(GRID)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _save(fig: Any, path: Path) -> Path:
    fig.patch.set_facecolor(SURFACE)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def security_utility(rows: Sequence[dict[str, Any]], path: Path) -> Path | None:
    points = [r for r in rows if r.get("UER") is not None and r.get("CTSR") is not None]
    if not points:
        return None
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    _style(ax, "Security vs utility (upper-left is better)")
    for r in points:
        x, y = r["UER"], r["CTSR"]
        # Wilson bounds can sit an ulp past the point at rates of 0 or 1: clamp to >= 0.
        xerr = [[max(0.0, x - r["UER_lo"])], [max(0.0, r["UER_hi"] - x)]]
        yerr = [[max(0.0, y - r["CTSR_lo"])], [max(0.0, r["CTSR_hi"] - y)]]
        ax.errorbar(
            x,
            y,
            xerr=xerr,
            yerr=yerr,
            fmt="o",
            ms=6,
            color=SERIES_1,
            ecolor=GRID,
            elinewidth=1.5,
            capsize=0,
        )
    # One label per distinct point; configurations at identical coordinates share it.
    labels: dict[tuple[float, float], list[str]] = {}
    for r in points:
        labels.setdefault((r["UER"], r["CTSR"]), []).append(r["label"])
    for (x, y), names in labels.items():
        ax.annotate(
            ", ".join(names),
            (x, y),
            xytext=(5, 5),
            textcoords="offset points",
            fontsize=7,
            color=INK_2,
        )
    ax.set_xlabel("Unauthorized execution rate (UER)", color=INK_2, fontsize=9)
    ax.set_ylabel("Clean task success (CTSR)", color=INK_2, fontsize=9)
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    return _save(fig, path)


def attempts_vs_executions(rows: Sequence[dict[str, Any]], path: Path) -> Path | None:
    rows = [r for r in rows if r.get("UAR") is not None]
    if not rows:
        return None
    fig, ax = plt.subplots(figsize=(max(5.0, 0.55 * len(rows) + 2), 3.8))
    _style(ax, "Attempted vs executed unauthorized actions")
    width = 0.38
    xs = range(len(rows))
    ax.bar(
        [x - width / 2 - 0.01 for x in xs],
        [r["UAR"] for r in rows],
        width,
        color=SERIES_1,
        label="Attempted (UAR)",
    )
    ax.bar(
        [x + width / 2 + 0.01 for x in xs],
        [r["UER"] for r in rows],
        width,
        color=SERIES_2,
        label="Executed (UER)",
    )
    for x, r in zip(xs, rows, strict=True):  # mark true zeros so they are not read as missing
        for offset, key in ((-width / 2 - 0.01, "UAR"), (width / 2 + 0.01, "UER")):
            if r[key] == 0:
                ax.text(x + offset, 0.01, "0", ha="center", va="bottom", fontsize=7, color=INK_2)
    ax.set_xticks(list(xs), [r["label"] for r in rows], rotation=45, ha="right")
    ax.set_ylim(0, 1.05)
    ax.legend(frameon=False, fontsize=8, labelcolor=INK_2)
    return _save(fig, path)


def family_heatmap(rows: Sequence[dict[str, Any]], path: Path, metric: str = "AGSR") -> Path | None:
    configs = sorted({r["config_id"] for r in rows})
    families = sorted({r["attack_family"] for r in rows})
    if not configs or not families:
        return None
    grid = [
        [
            next((r[metric] for r in rows if r["config_id"] == c and r["attack_family"] == f), None)
            for f in families
        ]
        for c in configs
    ]
    values = [[float("nan") if v is None else v for v in row] for row in grid]
    fig, ax = plt.subplots(figsize=(1.3 * len(families) + 2, 0.4 * len(configs) + 1.6))
    image = ax.imshow(values, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(families)), families, rotation=30, ha="right", fontsize=8, color=INK_2)
    ax.set_yticks(range(len(configs)), configs, fontsize=8, color=INK_2)
    ax.set_title(f"Attacker goal success by family ({metric})", color=INK, fontsize=11, loc="left")
    for i, row in enumerate(grid):
        for j, v in enumerate(row):
            if v is not None:
                ax.text(
                    j,
                    i,
                    f"{v:.2f}",
                    ha="center",
                    va="center",
                    fontsize=7,
                    color="white" if v > 0.55 else INK,
                )
    fig.colorbar(image, ax=ax, fraction=0.04)
    return _save(fig, path)


def tokens_box(groups: dict[str, list[float]], path: Path) -> Path | None:
    if not groups:
        return None
    labels = list(groups)
    fig, ax = plt.subplots(figsize=(max(5.0, 0.55 * len(labels) + 2), 3.6))
    _style(ax, "Tokens per episode")
    box = ax.boxplot([groups[k] for k in labels], patch_artist=True, widths=0.5)
    for patch in box["boxes"]:
        patch.set(facecolor="#d6e4f7", edgecolor=SERIES_1, linewidth=1)
    for median in box["medians"]:
        median.set(color=SERIES_1, linewidth=2)
    ax.set_xticks(range(1, len(labels) + 1), labels, rotation=45, ha="right")
    return _save(fig, path)
