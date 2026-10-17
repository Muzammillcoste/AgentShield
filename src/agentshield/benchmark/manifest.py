"""Dataset manifest: content hashes for every data file, used to detect drift/tampering.

Text files are hashed after normalizing CRLF to LF so a Windows checkout with automatic
line-ending conversion produces the same hashes as Linux CI (see also .gitattributes).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agentshield import __version__
from agentshield.auth.scope_resolver import GRAMMAR_VERSION
from agentshield.crm.fixtures import CRMFixture
from agentshield.schemas.common import SCHEMA_VERSION, StrictModel

MANIFEST_NAME = "manifest.json"
_TEXT_SUFFIXES = {".json", ".jsonl", ".yaml", ".yml", ".md", ".txt", ".csv"}


class DataManifest(StrictModel):
    schema_version: str = SCHEMA_VERSION
    agentshield_version: str = __version__
    grammar_version: str = GRAMMAR_VERSION
    fixture_id: str
    fixture_hash: str
    files: dict[str, str]
    frozen_splits: tuple[str, ...] = ()


def content_hash(path: Path) -> str:
    data = path.read_bytes()
    if path.suffix.lower() in _TEXT_SUFFIXES:
        data = data.replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def _data_files(data_dir: Path) -> list[Path]:
    return sorted(p for p in data_dir.rglob("*") if p.is_file() and p.name != MANIFEST_NAME)


def build_data_manifest(
    data_dir: Path, fixture: CRMFixture, frozen_splits: tuple[str, ...] = ()
) -> DataManifest:
    files = {p.relative_to(data_dir).as_posix(): content_hash(p) for p in _data_files(data_dir)}
    return DataManifest(
        fixture_id=fixture.fixture_id,
        fixture_hash=fixture.fixture_hash(),
        files=files,
        frozen_splits=frozen_splits,
    )


def write_manifest(manifest: DataManifest, path: Path) -> None:
    text = json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def load_manifest(path: Path) -> DataManifest:
    return DataManifest.model_validate_json(path.read_text(encoding="utf-8"))


def verify_manifest(manifest: DataManifest, data_dir: Path) -> list[str]:
    """Human-readable mismatches between the manifest and files on disk (empty = OK)."""
    problems = []
    current = {p.relative_to(data_dir).as_posix(): content_hash(p) for p in _data_files(data_dir)}
    for name, digest in sorted(manifest.files.items()):
        if name not in current:
            problems.append(f"missing file: {name}")
        elif current[name] != digest:
            problems.append(f"hash mismatch: {name}")
    for name in sorted(set(current) - set(manifest.files)):
        problems.append(f"file not in manifest: {name}")
    return problems
