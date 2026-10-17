from __future__ import annotations

import pytest

from agentshield.benchmark.statistics import paired_cluster_bootstrap, wilson


def test_wilson_known_values() -> None:
    p, lo, hi = wilson(5, 10)
    assert (
        p == 0.5 and lo == pytest.approx(0.2366, abs=1e-3) and hi == pytest.approx(0.7634, abs=1e-3)
    )
    p, lo, hi = wilson(0, 40)
    assert p == 0 and lo == 0 and hi == pytest.approx(0.0876, abs=1e-3)  # 0/40 is not 0% risk
    assert wilson(0, 0) == (None, None, None)


def test_bootstrap_identical_configs_have_zero_difference() -> None:
    a = {"t1": [1.0, 0.0], "t2": [1.0], "t3": [0.0]}
    diff, lo, hi, n = paired_cluster_bootstrap(a, a)
    assert diff == 0 and lo == 0 and hi == 0 and n == 3


def test_bootstrap_detects_clear_difference_on_shared_clusters() -> None:
    a = {f"t{i}": [1.0] for i in range(20)}
    b = {f"t{i}": [0.0] for i in range(20)} | {"extra": [1.0]}
    diff, _lo, hi, n = paired_cluster_bootstrap(a, b)
    assert diff == -1 and hi == -1 and n == 20
    assert paired_cluster_bootstrap({}, b) == (None, None, None, 0)
