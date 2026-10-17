"""`agentshield` command-line interface.

Exit codes: 0 success, 1 validation failure, 2 usage error (argparse), 3 config/data error.
Only commands that are actually implemented are registered here.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from agentshield import __version__
from agentshield.auth.scope_resolver import resolve_task_scope
from agentshield.benchmark.loader import (
    DatasetFormatError,
    load_public_scenarios,
    private_truth_path_for,
)
from agentshield.benchmark.manifest import (
    build_data_manifest,
    load_manifest,
    verify_manifest,
    write_manifest,
)
from agentshield.benchmark.truth_store import load_private_truth
from agentshield.benchmark.validation import IssueLevel, validate_dataset
from agentshield.config import BaseConfig, ConfigError, find_repo_root, load_base_config
from agentshield.crm.fixtures import load_fixture
from agentshield.defenses.registry import UnknownConfigError, load_registry
from agentshield.schemas.experiment import ConfigFamily

EXIT_OK = 0
EXIT_VALIDATION_FAILED = 1
EXIT_CONFIG_ERROR = 3


class _Context:
    def __init__(self, config_path: str | None) -> None:
        self.root = find_repo_root()
        path = Path(config_path) if config_path else self.root / "configs" / "base.yaml"
        self.config: BaseConfig = load_base_config(path)

    def path(self, relative: str) -> Path:
        candidate = Path(relative)
        return candidate if candidate.is_absolute() else self.root / candidate


def _cmd_list_configs(ctx: _Context, args: argparse.Namespace) -> int:
    registry = load_registry(ctx.path(ctx.config.defenses_registry))
    if args.all_bitmasks:
        configs = registry.all_bitmask_configs()
    else:
        family = ConfigFamily(args.family) if args.family != "all" else None
        configs = registry.configs(family)
    if args.json:
        rows = [
            {"id": c.id, "family": c.family, "defenses": list(c.enabled), "hash": c.config_hash()}
            for c in configs
        ]
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    for c in configs:
        print(f"{c.id:<24} {c.family:<18} {c.label:<40} {c.config_hash()[:12]}")
    return EXIT_OK


def _cmd_show_config(ctx: _Context, args: argparse.Namespace) -> int:
    registry = load_registry(ctx.path(ctx.config.defenses_registry))
    config = registry.get(args.config_id)
    payload = config.model_dump(mode="json")
    payload["d5_granularity"] = config.semantic_payload().get("d5_granularity")
    payload["bitmask"] = config.bitmask
    payload["config_hash"] = config.config_hash()
    payload["is_oracle_upper_bound"] = config.is_oracle
    print(json.dumps(payload, indent=2))
    return EXIT_OK


def _cmd_fixture_info(ctx: _Context, args: argparse.Namespace) -> int:
    fixture = load_fixture(ctx.path(ctx.config.dataset.fixture))
    info = {
        "fixture_id": fixture.fixture_id,
        "fixture_hash": fixture.fixture_hash(),
        "as_of_date": fixture.as_of_date.isoformat(),
        "tenants": len(fixture.tenants),
        "principals": len(fixture.principals),
        "aliases": len(fixture.aliases),
        "customers": len(fixture.customers),
        "invoices": len(fixture.invoices),
        "opportunities": len(fixture.opportunities),
        "cases": len(fixture.cases),
    }
    print(json.dumps(info, indent=2))
    return EXIT_OK


def _cmd_resolve_scope(ctx: _Context, args: argparse.Namespace) -> int:
    scope = resolve_task_scope(args.request)
    payload = scope.model_dump(mode="json")
    payload["scope_hash"] = scope.scope_hash()
    print(json.dumps(payload, indent=2))
    return EXIT_OK


def _cmd_validate_data(ctx: _Context, args: argparse.Namespace) -> int:
    fixture = load_fixture(ctx.path(ctx.config.dataset.fixture))
    public_dir = ctx.path(ctx.config.dataset.public_dir)
    private_dir = ctx.path(ctx.config.dataset.private_dir)
    public_files = (
        [Path(p) for p in args.public] if args.public else sorted(public_dir.glob("*.jsonl"))
    )
    if not public_files:
        print(f"no public scenario files found in {public_dir}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    scenarios, truths = [], {}
    for public_path in public_files:
        scenarios.extend(load_public_scenarios(public_path))
        truth_path = private_truth_path_for(public_path, private_dir)
        if truth_path.exists():
            truths.update(load_private_truth(truth_path))
        else:
            print(f"warning: no private truth file {truth_path}", file=sys.stderr)

    report = validate_dataset(scenarios, truths, fixture)
    manifest_path = ctx.path(ctx.config.dataset.manifest)
    manifest_problems: list[str] = []
    if manifest_path.exists():
        manifest_problems = verify_manifest(load_manifest(manifest_path), manifest_path.parent)

    for issue in report.issues:
        print(f"[{issue.level}] {issue.scenario_id or '-'}: {issue.code}: {issue.message}")
    for problem in manifest_problems:
        print(f"[manifest] {problem}")
    print(
        f"files={len(public_files)} public={report.n_public} private={report.n_private} "
        f"errors={sum(i.level is IssueLevel.ERROR for i in report.issues)} "
        f"warnings={sum(i.level is IssueLevel.WARNING for i in report.issues)} "
        f"unverified_labels={report.unverified_labels} fixture={report.fixture_hash[:12]}"
    )
    print("counts: " + ", ".join(f"{k}={v}" for k, v in report.counts.items()))
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    ok = report.ok and not (manifest_problems and args.strict_manifest)
    print("VALID" if ok else "INVALID")
    return EXIT_OK if ok else EXIT_VALIDATION_FAILED


def _cmd_build_manifest(ctx: _Context, args: argparse.Namespace) -> int:
    fixture = load_fixture(ctx.path(ctx.config.dataset.fixture))
    manifest_path = ctx.path(ctx.config.dataset.manifest)
    manifest = build_data_manifest(manifest_path.parent, fixture, tuple(args.frozen_split))
    write_manifest(manifest, manifest_path)
    print(f"wrote {manifest_path} ({len(manifest.files)} files)")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="AgentShield: layered prompt-injection defense evaluation (synthetic CRM).",
    )
    parser.add_argument("--version", action="version", version=f"agentshield {__version__}")
    parser.add_argument("--config", help="path to base.yaml (default: configs/base.yaml)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list-configs", help="list registered defense configurations")
    p.add_argument("--family", default="all", choices=["all", *[f.value for f in ConfigFamily]])
    p.add_argument("--all-bitmasks", action="store_true", help="list all 64 combinations")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_list_configs)

    p = sub.add_parser("show-config", help="show one configuration (e.g. C14 or M37)")
    p.add_argument("config_id")
    p.set_defaults(func=_cmd_show_config)

    p = sub.add_parser("fixture-info", help="summarize the CRM fixture and its hash")
    p.set_defaults(func=_cmd_fixture_info)

    p = sub.add_parser("resolve-scope", help="show the trusted task scope for a request")
    p.add_argument("request")
    p.set_defaults(func=_cmd_resolve_scope)

    p = sub.add_parser("validate-data", help="validate public scenarios + private truth")
    p.add_argument("--public", nargs="*", help="public JSONL files (default: all in public_dir)")
    p.add_argument("--report", help="write the JSON validation report here")
    p.add_argument(
        "--strict-manifest", action="store_true", help="fail if data/manifest.json is stale"
    )
    p.set_defaults(func=_cmd_validate_data)

    p = sub.add_parser("build-manifest", help="write data/manifest.json with content hashes")
    p.add_argument(
        "--frozen-split",
        action="append",
        default=[],
        choices=["dev", "heldout"],
        help="mark a split as frozen (repeatable)",
    )
    p.set_defaults(func=_cmd_build_manifest)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ctx = _Context(args.config)
        code: int = args.func(ctx, args)
        return code
    except (ConfigError, DatasetFormatError, FileNotFoundError, UnknownConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except ValueError as exc:  # pydantic validation errors in config/data files
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
