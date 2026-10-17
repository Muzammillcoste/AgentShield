"""Generate the benchmark dataset (public scenarios + private truth) deterministically.

Usage: uv run python scripts/generate_scenarios.py [--check]
Writes data/public/{dev,heldout}.jsonl and data/private/{dev,heldout}_truth.jsonl.
--check exits non-zero if regeneration differs from the files on disk (frozen data guard).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from agentshield.benchmark.dataset_builder import build_dataset
from agentshield.benchmark.loader import write_jsonl
from agentshield.crm.fixtures import load_fixture

ROOT = Path(__file__).resolve().parents[1]


def write_all(out: Path) -> None:
    pairs = build_dataset(load_fixture(ROOT / "data" / "fixtures" / "crm_fixture_v1.json"))
    for split in ("dev", "heldout"):
        selected = [(p, t) for p, t in pairs if p.split == split]
        write_jsonl(out / "public" / f"{split}.jsonl", (p for p, _ in selected))
        write_jsonl(out / "private" / f"{split}_truth.jsonl", (t for _, t in selected))
        print(f"{split}: {len(selected)} scenarios")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not args.check:
        write_all(ROOT / "data")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        write_all(Path(tmp))
        names = [
            "public/dev.jsonl",
            "public/heldout.jsonl",
            "private/dev_truth.jsonl",
            "private/heldout_truth.jsonl",
        ]
        same = all(
            (Path(tmp) / n).read_bytes() == (ROOT / "data" / n).read_bytes().replace(b"\r\n", b"\n")
            for n in names
        )
    print("identical" if same else "DIFFERS")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
