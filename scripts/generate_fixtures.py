"""Regenerate data/fixtures/crm_fixture_v1.json deterministically.

Usage: uv run python scripts/generate_fixtures.py [--check]
--check exits non-zero if the committed fixture differs from a fresh regeneration.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from agentshield.crm.fixtures import build_fixture_v1, dump_fixture, load_fixture

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "crm_fixture_v1.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify instead of writing")
    args = parser.parse_args()
    fixture = build_fixture_v1()
    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            fresh = Path(tmp) / "fixture.json"
            dump_fixture(fixture, fresh)
            same = fresh.read_bytes() == FIXTURE_PATH.read_bytes().replace(b"\r\n", b"\n")
        committed_hash = load_fixture(FIXTURE_PATH).fixture_hash()
        print(f"fresh={fixture.fixture_hash()} committed={committed_hash} identical={same}")
        return 0 if same else 1
    dump_fixture(fixture, FIXTURE_PATH)
    print(f"wrote {FIXTURE_PATH} hash={fixture.fixture_hash()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
