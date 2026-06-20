from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from .adapters import DEFAULT_HTTP_DEMO_URL, AgentConfig, check_http_agent
from .claude_code import ClaudeCodeRemediator
from .config import load_manifest
from .patcher import load_trace_for_attack
from .paths import (
    DEFAULT_AFTER_SUMMARY_PATH,
    DEFAULT_ATTACK_PACK_PATH,
    DEFAULT_BEFORE_SUMMARY_PATH,
    DEFAULT_GUARDRAILS_PATH,
    DEFAULT_MANIFEST_PATH,
    DEFAULT_REPORT_PATH,
    GENERATED_REGRESSIONS_PATH,
    PATCHES_ROOT,
    TRACES_ROOT,
    UNSAFE_GUARDRAILS_PATH,
)
from .report import generate_report
from .runner import RunReport, latest_run_dir, run_suite
from .summary import write_summary


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return run_command(args)
    if args.command == "rerun":
        return run_command(args, rerun=True)
    if args.command == "fix":
        return fix_command(args)
    if args.command == "reset":
        return reset_command(args)
    if args.command == "dashboard":
        return dashboard_command(args)
    if args.command == "doctor":
        return doctor_command(args)
    if args.command == "init":
        return init_command(args)
    if args.command == "latest":
        return latest_command(args)
    if args.command == "report":
        return report_command(args)

    parser.print_help()
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redteamci",
        description="Crash-test a demo AI agent before production.",
    )
    subparsers = parser.add_subparsers(dest="command")

    for command in ["run", "rerun"]:
        sub = subparsers.add_parser(command)
        sub.add_argument("--config", default=str(DEFAULT_MANIFEST_PATH))
        sub.add_argument("--agent")
        sub.add_argument("--agent-url")
        sub.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
        sub.add_argument("--regressions")
        sub.add_argument("--attacks", dest="attack_pack")
        sub.add_argument("--traces-root", default=str(TRACES_ROOT))
        sub.add_argument("--attack", action="append", dest="attacks")
        sub.add_argument("--offline", action="store_true", help="Use only local fixtures.")
        sub.add_argument("--expect-fail", action="store_true")
        sub.add_argument("--expect-pass", action="store_true")
        sub.add_argument("--summary")
        sub.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    fix = subparsers.add_parser("fix")
    fix.add_argument("attack_id")
    fix.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
    fix.add_argument("--traces-root", default=str(TRACES_ROOT))
    fix.add_argument("--run-id")
    fix.add_argument("--claude-code", action="store_true")
    fix.add_argument("--use-fixture", action="store_true")
    fix.add_argument("--apply", action="store_true")
    fix.add_argument("--dry-run", action="store_true")
    fix.add_argument("--json", action="store_true")

    reset = subparsers.add_parser("reset")
    reset.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))

    doctor = subparsers.add_parser("doctor")
    doctor.add_argument("--config", default=str(DEFAULT_MANIFEST_PATH))
    doctor.add_argument("--agent")
    doctor.add_argument("--agent-url")
    doctor.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
    doctor.add_argument("--regressions")
    doctor.add_argument("--attacks", dest="attack_pack")

    init = subparsers.add_parser("init")
    init.add_argument("--config", default=str(DEFAULT_MANIFEST_PATH))
    init.add_argument("--agent", choices=["builtin", "http"], default="builtin")
    init.add_argument("--agent-url", default=DEFAULT_HTTP_DEMO_URL)
    init.add_argument("--force", action="store_true")

    dashboard = subparsers.add_parser("dashboard")
    dashboard.add_argument("streamlit_args", nargs=argparse.REMAINDER)

    latest = subparsers.add_parser("latest")
    latest.add_argument("--traces-root", default=str(TRACES_ROOT))

    report = subparsers.add_parser("report")
    report.add_argument("--before", default=str(DEFAULT_BEFORE_SUMMARY_PATH))
    report.add_argument("--after", default=str(DEFAULT_AFTER_SUMMARY_PATH))
    report.add_argument("--output", default=str(DEFAULT_REPORT_PATH))

    return parser


def run_command(args: argparse.Namespace, rerun: bool = False) -> int:
    mode = "after_patch" if args.expect_pass else "before_patch" if args.expect_fail else "unknown"
    manifest = _load_run_manifest(args.config)
    guardrails_path = _configured_path(
        args.guardrails,
        DEFAULT_GUARDRAILS_PATH,
        manifest,
        "guardrails",
    )
    regressions_path = _configured_path(
        args.regressions,
        GENERATED_REGRESSIONS_PATH,
        manifest,
        "regressions",
    )
    attack_pack_path = _configured_optional_path(args.attack_pack, manifest, "attacks")
    agent_config = _agent_config(args, manifest)
    report = run_suite(
        guardrails_path=guardrails_path,
        traces_root=args.traces_root,
        generated_regressions_path=regressions_path,
        attack_pack_path=attack_pack_path,
        selected_attack_ids=args.attacks,
        agent_config=agent_config,
        mode=mode,
    )
    if args.summary:
        write_summary(report.summary, args.summary)
    if args.json:
        print(json.dumps(report.summary, indent=2))
    else:
        print_run_report(report, rerun=rerun)
    if args.expect_fail:
        return 0 if report.failed else 1
    if args.expect_pass:
        return 0 if not report.failed else 1
    return 1 if report.failed else 0


def fix_command(args: argparse.Namespace) -> int:
    trace = load_trace_for_attack(
        attack_id=args.attack_id,
        traces_root=args.traces_root,
        run_id=args.run_id,
    )
    trace_path = Path(trace["trace_path"])
    apply = False if args.dry_run else (args.apply or not args.dry_run)
    remediator = ClaudeCodeRemediator()
    result = remediator.remediate(
        attack_id=args.attack_id,
        trace_path=trace_path,
        guardrails_path=Path(args.guardrails),
        apply=apply,
        use_fixture=args.use_fixture,
        allow_fixture_fallback=not args.claude_code or args.use_fixture,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "source": result.source,
                    "applied": apply,
                    "success": result.success,
                    "changed_files": result.changed_files,
                    "summary_path": result.summary_path,
                    "regression_test_path": result.regression_test_path,
                    "diff": result.patch_diff,
                    "error": result.error,
                },
                indent=2,
            )
        )
        return 0 if result.success else 1

    print(f"RedTeamCI remediation for {args.attack_id}")
    print(f"Source: {result.source}")
    print(f"Applied: {apply}")
    print(f"Patch summary: {result.summary_path}")
    if result.regression_test_path:
        print(f"Regression test: {result.regression_test_path}")
    print()
    print("Patch:")
    print(result.patch_diff.rstrip() or "No guardrail changes needed.")
    print()
    if result.error:
        print(f"Error: {result.error}")
    else:
        print("Patch diff saved.")
    return 0 if result.success else 1


def reset_command(args: argparse.Namespace) -> int:
    shutil.copyfile(UNSAFE_GUARDRAILS_PATH, Path(args.guardrails))
    _clear_demo_artifacts()
    print(f"Reset {args.guardrails} to unsafe demo guardrails.")
    return 0


def dashboard_command(args: argparse.Namespace) -> int:
    command = [sys.executable, "-m", "streamlit", "run", "redteamci/dashboard.py"]
    command.extend(args.streamlit_args or [])
    return subprocess.call(command)


def doctor_command(args: argparse.Namespace) -> int:
    checks = _doctor_checks(args)
    for ok, message in checks:
        marker = "PASS" if ok else "FAIL"
        print(f"[{marker}] {message}")
    return 0 if all(ok for ok, _ in checks) else 1


def init_command(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if path.exists() and not args.force:
        print(f"{path} already exists. Use --force to overwrite.")
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"agent: {args.agent}",
    ]
    if args.agent == "http":
        lines.append(f"agent_url: {args.agent_url}")
    lines.extend(
        [
            "guardrails: guardrails.yml",
            "regressions: regressions/generated_attacks.json",
            "# attacks: attacks/redteamci_attacks.json",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {path}")
    return 0


def latest_command(args: argparse.Namespace) -> int:
    latest = latest_run_dir(args.traces_root)
    if latest is None:
        print("No RedTeamCI traces found.")
        return 1
    print(latest)
    return 0


def report_command(args: argparse.Namespace) -> int:
    output = generate_report(before_path=args.before, after_path=args.after, output_path=args.output)
    print(f"Wrote {output}")
    return 0


def print_run_report(report: RunReport, *, rerun: bool = False) -> None:
    label = "rerun" if rerun else "run"
    print(f"RedTeamCI {report.run_id} ({label})")
    print(f"Agent: {report.summary.get('integrations', {}).get('agent', 'builtin')}")
    print()
    for result in report.results:
        marker = "PASS" if result.status == "PASS" else "FAIL"
        print(f"[{marker}] {result.id} {result.name}")
        print(f"  {result.summary}")
        if result.source == "generated":
            print("  Source: generated regression")
        print()
    print(f"{len(report.failed)} failed, {len(report.passed)} passed")
    print(f"Trace saved to {report.traces_dir}/")
    if not report.failed:
        print()
        print("AGENT CERTIFIED")


def report_to_json(report: RunReport) -> dict[str, object]:
    return report.summary


def _clear_demo_artifacts() -> None:
    for run_dir in TRACES_ROOT.glob("run_*"):
        if run_dir.is_dir():
            shutil.rmtree(run_dir)
    if PATCHES_ROOT.exists():
        for path in PATCHES_ROOT.iterdir():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
    else:
        PATCHES_ROOT.mkdir(parents=True, exist_ok=True)
    GENERATED_REGRESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if GENERATED_REGRESSIONS_PATH.exists():
        GENERATED_REGRESSIONS_PATH.unlink()
    for path in [DEFAULT_BEFORE_SUMMARY_PATH, DEFAULT_AFTER_SUMMARY_PATH, DEFAULT_REPORT_PATH]:
        if path.exists():
            path.unlink()


def _load_run_manifest(config_path: str | None) -> dict[str, str]:
    if not config_path:
        return {}
    path = Path(config_path)
    if not path.exists():
        return {}
    manifest = load_manifest(path)
    manifest["_base_dir"] = str(path.parent)
    return manifest


def _configured_path(
    explicit: str | None,
    default: Path,
    manifest: dict[str, str],
    key: str,
) -> str:
    if explicit and Path(explicit) != default:
        return explicit
    value = manifest.get(key)
    if not value:
        return str(default)
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str(Path(manifest.get("_base_dir", ".")) / path)


def _configured_optional_path(
    explicit: str | None,
    manifest: dict[str, str],
    key: str,
) -> str | None:
    value = explicit or manifest.get(key)
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str(Path(manifest.get("_base_dir", ".")) / path)


def _agent_config(args: argparse.Namespace, manifest: dict[str, str]) -> AgentConfig:
    selected = (args.agent or manifest.get("agent") or "builtin").strip()
    if selected == "http-demo":
        return AgentConfig(kind="http", url=args.agent_url or DEFAULT_HTTP_DEMO_URL)
    if selected == "http":
        return AgentConfig(kind="http", url=args.agent_url or manifest.get("agent_url"))
    return AgentConfig(kind="builtin")


def _doctor_checks(args: argparse.Namespace) -> list[tuple[bool, str]]:
    manifest_path = Path(args.config)
    manifest = _load_run_manifest(args.config)
    checks: list[tuple[bool, str]] = []
    if manifest_path.exists():
        checks.append((True, f"Manifest found: {manifest_path}"))
    else:
        checks.append((False, f"Manifest not found: {manifest_path}"))

    guardrails_path = Path(
        _configured_path(args.guardrails, DEFAULT_GUARDRAILS_PATH, manifest, "guardrails")
    )
    checks.append(
        (
            guardrails_path.exists(),
            f"Guardrails {'found' if guardrails_path.exists() else 'missing'}: {guardrails_path}",
        )
    )

    regressions_path = Path(
        _configured_path(args.regressions, GENERATED_REGRESSIONS_PATH, manifest, "regressions")
    )
    regressions_parent = regressions_path.parent
    checks.append(
        (
            regressions_path.exists() or regressions_parent.exists(),
            (
                "Regressions path ready"
                if regressions_path.exists() or regressions_parent.exists()
                else "Regressions parent missing"
            )
            + f": {regressions_path}",
        )
    )

    attack_pack_path = _configured_optional_path(args.attack_pack, manifest, "attacks")
    if attack_pack_path:
        path = Path(attack_pack_path)
        checks.append(
            (
                path.exists(),
                f"Attack pack {'found' if path.exists() else 'missing'}: {path}",
            )
        )

    agent_config = _agent_config(args, manifest)
    if agent_config.kind == "builtin":
        checks.append((True, "Agent configured: builtin"))
    elif agent_config.kind == "http":
        ok, message = check_http_agent(agent_config.url or DEFAULT_HTTP_DEMO_URL)
        checks.append((ok, message))
    else:
        checks.append((False, f"Unsupported agent: {agent_config.kind}"))
    return checks


if __name__ == "__main__":
    raise SystemExit(main())
