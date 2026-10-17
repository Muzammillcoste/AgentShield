"""`agentshield` command-line interface.

Exit codes: 0 success, 1 validation failure / model not found, 2 usage error (argparse),
3 config/data/provider error, 4 real-model usage requires --approve-real-usage,
5 run stopped early (budget, quota, auth or configuration problem).
Only commands that are actually implemented are registered here.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentshield import __version__
from agentshield.auth.principals import PrincipalDirectory
from agentshield.auth.scope_resolver import GRAMMAR_VERSION, resolve_task_scope
from agentshield.benchmark.artifacts import RunExistsError, RunWriter, environment_info
from agentshield.benchmark.estimate import RunEstimate, budget_for_estimate, estimate_run
from agentshield.benchmark.loader import (
    DatasetFormatError,
    load_public_scenarios,
    private_truth_path_for,
)
from agentshield.benchmark.manifest import (
    build_data_manifest,
    content_hash,
    load_manifest,
    verify_manifest,
    write_manifest,
)
from agentshield.benchmark.runner import RunContext, check_supported, new_run_id, run_episodes
from agentshield.benchmark.session import (
    DEFAULT_MODEL_CONFIGS,
    DEFAULT_PRICING,
    dataset_version,
    load_model,
    load_price,
    select_scenarios,
)
from agentshield.benchmark.truth_store import load_private_truth
from agentshield.benchmark.validation import IssueLevel, validate_dataset
from agentshield.config import (
    BaseConfig,
    BudgetLimits,
    ConfigError,
    find_repo_root,
    load_base_config,
)
from agentshield.crm.fixtures import load_fixture
from agentshield.defenses.d1_system_prompt import D1_VERSION, d1_hash
from agentshield.defenses.d2_inspector import D2_RULESET_VERSION
from agentshield.defenses.d3_provenance import D3_VERSION
from agentshield.defenses.registry import UnknownConfigError, load_registry
from agentshield.llm.openai_compatible import OpenAICompatibleClient
from agentshield.llm.prompts import BASE_PROMPT_VERSION, base_template_hash
from agentshield.llm.protocol import LLMError
from agentshield.llm.provider import build_client
from agentshield.llm.resilience import BudgetGuard, CallController, RetryPolicy
from agentshield.schemas.experiment import ConfigFamily, EpisodeResult

EXIT_OK = 0
EXIT_VALIDATION_FAILED = 1
EXIT_CONFIG_ERROR = 3
EXIT_APPROVAL_REQUIRED = 4
EXIT_RUN_ABORTED = 5


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


def _model_config_path(ctx: _Context, args: argparse.Namespace) -> Path:
    if args.model_config:
        return ctx.path(args.model_config)
    return ctx.path(DEFAULT_MODEL_CONFIGS[args.provider])


def _pricing_path(ctx: _Context, args: argparse.Namespace, provider: str) -> Path | None:
    if getattr(args, "pricing", None):
        return ctx.path(args.pricing)
    default = DEFAULT_PRICING.get(provider)
    return ctx.path(default) if default else None


def _cmd_check_provider(ctx: _Context, args: argparse.Namespace) -> int:
    """Free check: list the provider's models and confirm the configured one exists."""
    _, settings = load_model(ctx.root, _model_config_path(ctx, args))
    if settings.provider == "fake":
        print(json.dumps({"provider": "fake", "model_id": settings.model_id, "model_found": True}))
        return EXIT_OK
    client = OpenAICompatibleClient(settings)
    models = client.list_models()
    wanted = {settings.model_id, f"models/{settings.model_id}"}  # Gemini lists "models/<id>"
    match = next((m for m in models if m.get("id") in wanted), None)
    keep = ("id", "owned_by", "active", "context_window", "max_completion_tokens")
    print(
        json.dumps(
            {
                "base_url": settings.base_url,
                "model_id": settings.model_id,
                "model_source": settings.model_source,
                "api_key_env": settings.api_key_env,
                "api_key_present": settings.api_key is not None,
                "models_listed": len(models),
                "model_found": match is not None,
                "model_info": {k: match.get(k) for k in keep if k in match} if match else None,
            },
            indent=2,
        )
    )
    return EXIT_OK if match else EXIT_VALIDATION_FAILED


def _selection(ctx: _Context, args: argparse.Namespace) -> tuple[Path, list[Any], list[Any]]:
    if args.public:
        public_path = ctx.path(args.public)
    else:
        public_path = ctx.path(ctx.config.dataset.public_dir) / f"{args.split}.jsonl"
    scenarios = select_scenarios(public_path, args.scenarios, args.limit)
    configs = load_registry(ctx.path(ctx.config.defenses_registry)).resolve(args.configs)
    return public_path, scenarios, configs


def _print_estimate(estimate: RunEstimate) -> None:
    usd = "n/a" if estimate.paid_equivalent_usd is None else f"${estimate.paid_equivalent_usd:.4f}"
    print(
        f"estimate: episodes={estimate.episodes} model_calls~{estimate.model_calls} "
        f"tokens~{estimate.total_tokens} (in {estimate.input_tokens} / out "
        f"{estimate.output_tokens}; upper bound {estimate.upper_bound_total_tokens}) "
        f"paid-equivalent={usd}"
    )
    if estimate.minutes_at_documented_tpm is not None:
        print(
            f"          ~{estimate.minutes_at_documented_tpm:.1f} min at documented TPM; "
            f"~{estimate.days_at_documented_tpd or 0:.2f} days of documented TPD"
        )


def _estimate_for(
    ctx: _Context, args: argparse.Namespace, scenarios: list[Any], configs: list[Any]
) -> tuple[RunEstimate, Any, Any, Any, str | None]:
    model_config, settings = load_model(ctx.root, _model_config_path(ctx, args))
    provider = "fake" if settings.provider == "fake" else "real"
    price, pricing_version = load_price(_pricing_path(ctx, args, provider), settings.model_id)
    fixture = load_fixture(ctx.path(ctx.config.dataset.fixture))
    estimate = estimate_run(
        scenarios,
        configs,
        args.repeats,
        fixture=fixture,
        principals=PrincipalDirectory(fixture.principals),
        generation=settings.generation,
        limits=ctx.config.runtime,
        price=price,
        documented=model_config.documented_limits,
    )
    return estimate, settings, price, fixture, pricing_version


def _cmd_estimate(ctx: _Context, args: argparse.Namespace) -> int:
    _, scenarios, configs = _selection(ctx, args)
    estimate = _estimate_for(ctx, args, scenarios, configs)[0]
    _print_estimate(estimate)
    if args.json:
        print(estimate.model_dump_json(indent=2))
    return EXIT_OK


def _cmd_run(ctx: _Context, args: argparse.Namespace) -> int:
    public_path, scenarios, configs = _selection(ctx, args)
    check_supported(scenarios, configs)
    estimate, settings, price, fixture, pricing_version = _estimate_for(
        ctx, args, scenarios, configs
    )
    real = settings.provider != "fake"
    _print_estimate(estimate)
    if real and not args.approve_real_usage:
        print(
            "Real-model usage requires explicit approval: review the estimate above and rerun "
            "with --approve-real-usage (optionally with --max-total-tokens/--max-requests)."
        )
        return EXIT_APPROVAL_REQUIRED

    limits = BudgetLimits(
        max_total_tokens=args.max_total_tokens or ctx.config.budget.max_total_tokens,
        max_requests=args.max_requests or ctx.config.budget.max_requests,
        max_usd=args.max_usd if args.max_usd is not None else ctx.config.budget.max_usd,
    )
    if real and limits.max_total_tokens is None and limits.max_requests is None:
        limits = budget_for_estimate(estimate)  # never run a real model without a hard cap
    runtime_limits = ctx.config.runtime
    controller = CallController(
        retry=RetryPolicy(
            max_retries=runtime_limits.max_retries,
            backoff_initial_s=runtime_limits.backoff_initial_s,
            backoff_max_s=runtime_limits.backoff_max_s,
        ),
        budget=BudgetGuard(limits, price),
        max_rate_wait_s=settings.max_rate_limit_wait_s,
    )
    output = ctx.path(args.output)
    writer = RunWriter(output, overwrite=args.overwrite, resume=args.resume)
    run_id = new_run_id("real" if real else "fake")
    run_ctx = RunContext(
        run_id=run_id,
        fixture=fixture,
        principals=PrincipalDirectory(fixture.principals),
        client=build_client(settings, fake_follows_injections=args.fake_susceptible),
        controller=controller,
        generation=settings.generation,
        limits=runtime_limits,
        dataset_version=dataset_version(ctx.path(ctx.config.dataset.manifest), public_path),
    )
    started = datetime.now(UTC)

    def progress(key: str, result: EpisodeResult) -> None:
        print(
            f"  {key}: {result.status.value} calls={result.usage.requests} "
            f"tokens={result.usage.total_tokens} changes={len(result.state_diff)}"
        )

    summary = run_episodes(run_ctx, scenarios, configs, args.repeats, writer, progress)
    budget = controller.budget.snapshot() if controller.budget else None
    manifest = {
        "run_id": run_id,
        "phase": 3,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "provider_kind": settings.provider,
        "research_evidence": real,
        "note": None if real else "FAKE MODEL OUTPUT: pipeline test only, not research evidence",
        "environment": environment_info(ctx.root),
        "model": settings.public_view(),
        "dataset": {
            "public_file": public_path.name,
            "public_sha256": content_hash(public_path),
            "dataset_version": run_ctx.dataset_version,
            "fixture_id": fixture.fixture_id,
            "fixture_hash": fixture.fixture_hash(),
            "scenario_ids": [s.scenario_id for s in scenarios],
        },
        "configs": {c.id: {"hash": c.config_hash(), **c.semantic_payload()} for c in configs},
        "repeats": args.repeats,
        "resumed": args.resume,
        "defense_versions": {
            "d1": D1_VERSION,
            "d1_sha256": d1_hash(),
            "d2": D2_RULESET_VERSION,
            "d3": D3_VERSION,
        },
        "fake_susceptible": args.fake_susceptible,
        "prompts": {
            "base_version": BASE_PROMPT_VERSION,
            "base_template_sha256": base_template_hash(),
        },
        "grammar_version": GRAMMAR_VERSION,
        "runtime_limits": runtime_limits.model_dump(),
        "estimate": estimate.model_dump(),
        "budget": budget.model_dump() if budget else None,
        "pricing_version": pricing_version,
        "rate_limits_observed": controller.rate.snapshot(),
        "summary": summary.model_dump(),
    }
    path = writer.write_manifest(manifest)
    print(
        f"run {run_id}: episodes={summary.episodes} statuses={summary.statuses} "
        f"tokens={summary.usage.total_tokens} requests={summary.usage.requests} "
        f"skipped_completed={summary.skipped}"
    )
    print(f"artifacts: {path.parent}")
    if summary.aborted:
        print(f"STOPPED EARLY: {summary.aborted}", file=sys.stderr)
        return EXIT_RUN_ABORTED
    return EXIT_OK


def _add_selection_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--provider", choices=["fake", "real"], default="fake")
    p.add_argument("--model-config", help="model YAML (overrides --provider default)")
    p.add_argument("--pricing", help="pricing YAML (default for real: configs/pricing.groq.yaml)")
    p.add_argument("--split", choices=["dev", "heldout"], default="dev")
    p.add_argument("--public", help="public scenario JSONL (overrides --split)")
    p.add_argument("--scenarios", help="comma-separated scenario ids")
    p.add_argument("--limit", type=int, help="first N selected scenarios")
    p.add_argument("--configs", default="C00", help="comma-separated config ids")
    p.add_argument("--repeats", type=int, default=1)


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

    p = sub.add_parser("check-provider", help="list provider models; confirm the configured one")
    p.add_argument("--provider", choices=["fake", "real"], default="real")
    p.add_argument("--model-config", help="model YAML (overrides --provider default)")
    p.set_defaults(func=_cmd_check_provider)

    p = sub.add_parser("estimate", help="estimate requests/tokens/cost of a run (no API calls)")
    _add_selection_args(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_estimate)

    p = sub.add_parser("run", help="run episodes and write artifacts")
    _add_selection_args(p)
    p.add_argument("--output", required=True, help="output directory (e.g. results/smoke)")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument(
        "--resume", action="store_true", help="skip completed episodes; re-run aborted ones"
    )
    p.add_argument("--approve-real-usage", action="store_true", help="required for real models")
    p.add_argument("--max-total-tokens", type=int, help="hard token cap for the run")
    p.add_argument("--max-requests", type=int, help="hard request cap for the run")
    p.add_argument("--max-usd", type=float, help="hard paid-equivalent USD cap (needs pricing)")
    p.add_argument(
        "--fake-susceptible",
        action="store_true",
        help="fake agent obeys imperatives in tool output (plumbing tests only)",
    )
    p.set_defaults(func=_cmd_run)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ctx = _Context(args.config)
        code: int = args.func(ctx, args)
        return code
    except LLMError as exc:
        print(f"error: provider {exc.kind.value}: {exc.message}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except (
        ConfigError,
        DatasetFormatError,
        FileNotFoundError,
        UnknownConfigError,
        RunExistsError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except ValueError as exc:  # pydantic validation errors in config/data files
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
