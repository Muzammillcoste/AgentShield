"""Static guard: runtime code can never reach private ground truth or harness labels.

Runtime packages (CRM, auth, LLM, defenses and — from later phases — injection and agent)
must not import the private truth schema, the private truth loader, or the benchmark
harness. Defenses additionally must not import the public scenario schema, which carries
category/attack-family labels that the orchestrator may see but defenses must not.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.conftest import ROOT

SRC = ROOT / "src" / "agentshield"
RUNTIME_PACKAGES = ("crm", "auth", "llm", "defenses", "injection", "agent")
FORBIDDEN_FOR_RUNTIME = ("agentshield.schemas.truth", "agentshield.benchmark")
FORBIDDEN_FOR_DEFENSES = ("agentshield.schemas.scenario",)
# The agent loop and model clients never see scenario objects (labels stay in the harness).
LABEL_FREE_PACKAGES = ("defenses", "agent", "llm")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def _modules(package: str) -> list[Path]:
    directory = SRC / package
    return sorted(directory.rglob("*.py")) if directory.exists() else []


def _violations(paths: list[Path], forbidden: tuple[str, ...]) -> list[str]:
    bad = []
    for path in paths:
        for name in _imports(path):
            if any(name == f or name.startswith(f + ".") for f in forbidden):
                bad.append(f"{path.relative_to(ROOT)} imports {name}")
    return bad


@pytest.mark.parametrize("package", RUNTIME_PACKAGES)
def test_runtime_never_imports_private_truth_or_harness(package: str) -> None:
    assert _violations(_modules(package), FORBIDDEN_FOR_RUNTIME) == []


@pytest.mark.parametrize("package", LABEL_FREE_PACKAGES)
def test_label_free_packages_never_import_scenarios(package: str) -> None:
    assert _violations(_modules(package), FORBIDDEN_FOR_DEFENSES) == []


def test_only_harness_modules_import_private_truth() -> None:
    allowed = {
        "truth_store.py",
        "validation.py",
        "grader.py",
        "metrics.py",
        "statistics.py",
        "selection.py",
        "reports.py",
        "plots.py",
        "truth.py",
        "oracle.py",
        "dataset_builder.py",
    }
    importers = [
        p.relative_to(ROOT).as_posix()
        for p in SRC.rglob("*.py")
        if any(n.startswith("agentshield.schemas.truth") for n in _imports(p))
    ]
    assert importers, "sanity: the validator must import the truth schema"
    assert all(Path(p).name in allowed for p in importers), importers


def test_schemas_package_does_not_reexport_truth() -> None:
    assert (
        "truth"
        not in (SRC / "schemas" / "__init__.py").read_text(encoding="utf-8").split("`truth.py`")[0]
    )
    assert _imports(SRC / "schemas" / "__init__.py") == set()
