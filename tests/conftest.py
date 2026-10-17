from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.auth.principals import PrincipalDirectory
from agentshield.crm.fixtures import CRMFixture, load_fixture
from agentshield.crm.store import CRMStore
from agentshield.schemas.domain import Principal

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "data" / "fixtures" / "crm_fixture_v1.json"
EXAMPLES_PUBLIC = ROOT / "data" / "public" / "examples.jsonl"
EXAMPLES_PRIVATE = ROOT / "data" / "private" / "examples_truth.jsonl"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def fixture() -> CRMFixture:
    return load_fixture(FIXTURE_PATH)


@pytest.fixture(scope="session")
def principals(fixture: CRMFixture) -> PrincipalDirectory:
    return PrincipalDirectory(fixture.principals)


@pytest.fixture
def store(fixture: CRMFixture) -> CRMStore:
    """A fresh store per test: state never leaks between tests (or episodes)."""
    return CRMStore.from_fixture(fixture)


@pytest.fixture
def manager(principals: PrincipalDirectory) -> Principal:
    return principals.get("sales_manager_t1")
