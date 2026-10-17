"""Uncertainty: Wilson score intervals and paired cluster bootstrap differences.

Findings on small held-out sets are exploratory; intervals are reported, not p-values.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

import numpy as np

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float | None, float | None, float | None]:
    """(rate, low, high); all None when n == 0."""
    if n == 0:
        return None, None, None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def paired_cluster_bootstrap(
    a: Mapping[str, Sequence[float]],
    b: Mapping[str, Sequence[float]],
    *,
    iterations: int = 2000,
    seed: int = 20261017,
) -> tuple[float | None, float | None, float | None, int]:
    """Difference of means (b - a) resampling clusters (e.g. base_task_id) with replacement.

    `a[c]` / `b[c]` hold the per-episode values (repetitions kept together) of cluster c under
    each configuration. Only clusters present in both are used. Returns (diff, low, high, n).
    """
    clusters = sorted(set(a) & set(b))
    if not clusters:
        return None, None, None, 0
    sums_a = np.array([sum(a[c]) for c in clusters], dtype=float)
    cnt_a = np.array([len(a[c]) for c in clusters], dtype=float)
    sums_b = np.array([sum(b[c]) for c in clusters], dtype=float)
    cnt_b = np.array([len(b[c]) for c in clusters], dtype=float)
    observed = sums_b.sum() / cnt_b.sum() - sums_a.sum() / cnt_a.sum()
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(clusters), size=(iterations, len(clusters)))
    diffs = sums_b[idx].sum(axis=1) / cnt_b[idx].sum(axis=1) - sums_a[idx].sum(axis=1) / cnt_a[
        idx
    ].sum(axis=1)
    low, high = np.percentile(diffs, [2.5, 97.5])
    return float(observed), float(low), float(high), len(clusters)
