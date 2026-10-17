"""Run artifact writing: episodes.jsonl, per-episode transcripts and a run manifest.

Episodes are appended one line at a time so a crash or budget stop never loses completed
episodes. Nothing written here contains API keys (settings use `public_view()`).
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from agentshield import __version__
from agentshield.agent.runtime import EpisodeTrace
from agentshield.hashing import canonical_json
from agentshield.schemas.experiment import EpisodeResult

_PACKAGES = ("pydantic", "openai", "pyyaml", "python-dotenv")


def environment_info(root: Path | None = None) -> dict[str, Any]:
    packages: dict[str, str | None] = {}
    for name in _PACKAGES:
        try:
            packages[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            packages[name] = None
    info: dict[str, Any] = {
        "agentshield_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "packages": packages,
        "git_commit": None,
        "git_dirty": None,
    }
    if root is not None:
        try:
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
            ).stdout.strip()
            dirty = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            info["git_commit"], info["git_dirty"] = commit, bool(dirty)
        except (OSError, subprocess.CalledProcessError):
            pass
    return info


def episode_key(scenario_id: str, config_id: str, repetition: int) -> str:
    return f"{scenario_id}__{config_id}__r{repetition}"


class RunExistsError(FileExistsError):
    pass


class RunWriter:
    """Writes one run directory.

    - `episodes.jsonl`: completed/scored-eligible episodes (one canonical JSON per line).
    - `aborted_episodes.jsonl`: episodes cut short by a run-level stop (budget, quota, auth);
      kept for audit, excluded from metrics, and re-run by `--resume`.
    - `traces/`: per-episode transcripts; `manifest.json` (+ `manifest.<n>.json` history).
    """

    def __init__(self, output_dir: Path, *, overwrite: bool = False, resume: bool = False) -> None:
        if overwrite and resume:
            raise ValueError("--overwrite and --resume are mutually exclusive")
        self.output_dir = output_dir
        self.episodes_path = output_dir / "episodes.jsonl"
        self.aborted_path = output_dir / "aborted_episodes.jsonl"
        self.traces_dir = output_dir / "traces"
        self.resume = resume
        exists = self.episodes_path.exists() or self.aborted_path.exists()
        if exists and not (overwrite or resume):
            raise RunExistsError(
                f"{output_dir} already holds a run; use --resume, --overwrite or a new --output"
            )
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        if overwrite:
            for path in (self.episodes_path, self.aborted_path, *output_dir.glob("manifest*.json")):
                path.unlink(missing_ok=True)
            for old in self.traces_dir.rglob("*.json"):
                old.unlink()
        self.completed_keys: set[str] = set()
        if resume and self.episodes_path.exists():
            self.completed_keys = {
                episode_key(e.scenario_id, e.config_id, e.repetition)
                for e in load_episodes(self.episodes_path)
            }

    def write_episode(self, key: str, result: EpisodeResult, trace: EpisodeTrace) -> None:
        self._append(self.episodes_path, result)
        self._transcript(self.traces_dir / f"{key}.json", key, trace)

    def write_aborted(self, key: str, result: EpisodeResult, trace: EpisodeTrace) -> None:
        self._append(self.aborted_path, result)
        (self.traces_dir / "aborted").mkdir(exist_ok=True)
        self._transcript(self.traces_dir / "aborted" / f"{key}__{result.run_id}.json", key, trace)

    def write_manifest(self, manifest: dict[str, Any]) -> Path:
        path = self.output_dir / "manifest.json"
        if path.exists() and self.resume:  # keep the history of every invocation
            n = len(list(self.output_dir.glob("manifest.*.json"))) + 1
            path.rename(self.output_dir / f"manifest.{n}.json")
        path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return path

    @staticmethod
    def _append(path: Path, result: EpisodeResult) -> None:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json(result) + "\n")

    @staticmethod
    def _transcript(path: Path, key: str, trace: EpisodeTrace) -> None:
        transcript = {
            "episode": key,
            "status": trace.status.value,
            "errors": list(trace.errors),
            "messages": [m.model_dump(mode="json") for m in trace.messages],
        }
        path.write_text(
            json.dumps(transcript, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )


def load_episodes(path: Path) -> list[EpisodeResult]:
    with path.open(encoding="utf-8") as handle:
        return [EpisodeResult.model_validate_json(line) for line in handle if line.strip()]
