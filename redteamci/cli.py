from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

from .adapters import DEFAULT_HTTP_DEMO_URL, AgentConfig, check_http_agent
from .claude_code import (
    ClaudeCodeRemediator,
    build_claude_prompt,
    build_claude_proposal_prompt,
    write_claude_prompt_artifact,
)
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
    FIXTURES_ROOT,
    PATCHES_ROOT,
    ROOT,
    TRACES_ROOT,
    UNSAFE_GUARDRAILS_PATH,
)
from .report import generate_report
from .runner import RunReport, latest_run_dir, run_suite
from .summary import write_junit_summary, write_sarif_summary, write_summary


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return run_command(args)
    if args.command == "rerun":
        return run_command(args, rerun=True)
    if args.command == "fix":
        return fix_command(args)
    if args.command == "claude":
        return claude_command(args)
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
        sub.add_argument("--junit")
        sub.add_argument("--sarif")
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
    fix.add_argument("--mode", choices=["proposal", "direct-edit"], default="proposal")
    fix.add_argument("--max-turns", type=int, default=12)
    fix.add_argument("--timeout", type=int, default=300)
    fix.add_argument("--no-fixture-fallback", action="store_true")
    fix.add_argument("--json", action="store_true")

    claude = subparsers.add_parser("claude")
    claude_sub = claude.add_subparsers(dest="claude_command")

    claude_sub.add_parser("status")

    claude_prompt = claude_sub.add_parser("prompt")
    claude_prompt.add_argument("attack_id")
    claude_prompt.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
    claude_prompt.add_argument("--traces-root", default=str(TRACES_ROOT))
    claude_prompt.add_argument("--run-id")
    claude_prompt.add_argument("--mode", choices=["proposal", "direct-edit"], default="proposal")

    claude_remediate = claude_sub.add_parser("remediate")
    claude_remediate.add_argument("attack_id")
    claude_remediate.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
    claude_remediate.add_argument("--traces-root", default=str(TRACES_ROOT))
    claude_remediate.add_argument("--run-id")
    claude_remediate.add_argument("--apply", action="store_true")
    claude_remediate.add_argument("--mode", choices=["proposal", "direct-edit"], default="proposal")
    claude_remediate.add_argument("--max-turns", type=int, default=12)
    claude_remediate.add_argument("--timeout", type=int, default=300)
    claude_remediate.add_argument("--no-fixture-fallback", action="store_true")
    claude_remediate.add_argument("--json", action="store_true")

    reset = subparsers.add_parser("reset")
    reset.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))

    doctor = subparsers.add_parser("doctor")
    doctor.add_argument("--config", default=str(DEFAULT_MANIFEST_PATH))
    doctor.add_argument("--agent")
    doctor.add_argument("--agent-url")
    doctor.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
    doctor.add_argument("--regressions")
    doctor.add_argument("--attacks", dest="attack_pack")
    doctor.add_argument("--dashboard", action="store_true")

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
    if args.junit:
        write_junit_summary(report.summary, args.junit)
    if args.sarif:
        write_sarif_summary(report.summary, args.sarif)
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
        allow_fixture_fallback=not args.no_fixture_fallback,
        max_turns=args.max_turns,
        timeout=args.timeout,
        mode=args.mode,
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
                    "prompt_path": result.prompt_path,
                    "raw_output_path": result.raw_output_path,
                    "proposal_path": result.proposal_path,
                    "validation_error_path": result.validation_error_path,
                    "fixture_fallback_used": result.fixture_fallback_used,
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
    if result.prompt_path:
        print(f"Claude prompt: {result.prompt_path}")
    if result.raw_output_path:
        print(f"Claude raw output: {result.raw_output_path}")
    if result.proposal_path:
        print(f"Claude proposal: {result.proposal_path}")
    if result.validation_error_path:
        print(f"Claude validation errors: {result.validation_error_path}")
    if result.source == "claude_code_proposal":
        print(f"Live Claude proposal applied: {result.success and apply}")
    print(f"Fixture fallback used: {result.fixture_fallback_used}")
    print()
    print("Patch:")
    print(result.patch_diff.rstrip() or "No guardrail changes needed.")
    print()
    if result.error:
        print(f"Error: {result.error}")
    else:
        print("Patch diff saved.")
    return 0 if result.success else 1


def claude_command(args: argparse.Namespace) -> int:
    remediator = ClaudeCodeRemediator()
    if args.claude_command == "status":
        executable = remediator.executable()
        print(f"Claude Code available: {bool(executable)}")
        print(f"Claude Code executable: {executable or '-'}")
        print("Fixture fallback available: True")
        return 0
    if args.claude_command == "prompt":
        trace = load_trace_for_attack(
            attack_id=args.attack_id,
            traces_root=args.traces_root,
            run_id=args.run_id,
        )
        trace_path = Path(trace["trace_path"])
        run_id = str(trace.get("run_id", "run_unknown"))
        if args.mode == "direct-edit":
            summary_path = PATCHES_ROOT / f"{run_id}_{args.attack_id}_claude_direct_edit_summary.json"
            prompt = build_claude_prompt(
                attack_id=args.attack_id,
                trace=trace,
                guardrails_yaml=Path(args.guardrails).read_text(encoding="utf-8"),
                run_id=run_id,
                summary_path=summary_path,
                trace_path=trace_path,
            )
        else:
            prompt = build_claude_proposal_prompt(
                attack_id=args.attack_id,
                trace=trace,
                guardrails_yaml=Path(args.guardrails).read_text(encoding="utf-8"),
                run_id=run_id,
                trace_path=trace_path,
            )
        prompt_path = write_claude_prompt_artifact(
            attack_id=args.attack_id,
            run_id=run_id,
            prompt=prompt,
            mode=args.mode,
        )
        print(f"Wrote Claude prompt: {prompt_path}")
        return 0
    if args.claude_command == "remediate":
        trace = load_trace_for_attack(
            attack_id=args.attack_id,
            traces_root=args.traces_root,
            run_id=args.run_id,
        )
        result = remediator.remediate(
            attack_id=args.attack_id,
            trace_path=Path(trace["trace_path"]),
            guardrails_path=Path(args.guardrails),
            apply=args.apply,
            use_fixture=False,
            allow_fixture_fallback=not args.no_fixture_fallback,
            max_turns=args.max_turns,
            timeout=args.timeout,
            mode=args.mode,
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "source": result.source,
                        "success": result.success,
                        "changed_files": result.changed_files,
                        "summary_path": result.summary_path,
                        "prompt_path": result.prompt_path,
                        "raw_output_path": result.raw_output_path,
                        "proposal_path": result.proposal_path,
                        "validation_error_path": result.validation_error_path,
                        "fixture_fallback_used": result.fixture_fallback_used,
                        "error": result.error,
                    },
                    indent=2,
                )
            )
        else:
            print(f"Source: {result.source}")
            print(f"Success: {result.success}")
            print(f"Changed files: {result.changed_files}")
            print(f"Patch summary: {result.summary_path}")
            if result.prompt_path:
                print(f"Claude prompt: {result.prompt_path}")
            if result.raw_output_path:
                print(f"Claude raw output: {result.raw_output_path}")
            if result.proposal_path:
                print(f"Claude proposal: {result.proposal_path}")
            if result.validation_error_path:
                print(f"Claude validation errors: {result.validation_error_path}")
            if result.source == "claude_code_proposal":
                print(f"Live Claude proposal applied: {result.success and args.apply}")
            print(f"Fixture fallback used: {result.fixture_fallback_used}")
            if result.error:
                print(f"Error: {result.error}")
        return 0 if result.success else 1
    print("Usage: redteamci claude {status,prompt,remediate}")
    return 1


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
        elif result.source != "builtin":
            print(f"  Source: {result.source}")
        if result.assertion_failures:
            print("  Assertion gates failed:")
            for failure in result.assertion_failures:
                print(f"  - {failure}")
        print()
    print(f"{len(report.failed)} failed, {len(report.passed)} passed")
    generated_loaded = int(report.summary.get("generated_regressions_loaded", 0))
    print(f"Generated regression tests loaded: {generated_loaded}")
    if generated_loaded:
        print("Exploit became regression test")
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

    checks.append((True, "Python package importable: redteamci"))

    guardrails_path = Path(
        _configured_path(args.guardrails, DEFAULT_GUARDRAILS_PATH, manifest, "guardrails")
    )
    checks.append(
        (
            guardrails_path.exists(),
            f"Guardrails {'found' if guardrails_path.exists() else 'missing'}: {guardrails_path}",
        )
    )
    checks.append(
        (
            UNSAFE_GUARDRAILS_PATH.exists(),
            (
                "Unsafe guardrails found"
                if UNSAFE_GUARDRAILS_PATH.exists()
                else "Unsafe guardrails missing"
            )
            + f": {UNSAFE_GUARDRAILS_PATH}",
        )
    )
    fixture_path = FIXTURES_ROOT / "claude_pi003_patch.json"
    checks.append(
        (
            fixture_path.exists(),
            f"Fixture patch {'found' if fixture_path.exists() else 'missing'}: {fixture_path}",
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
    workflow_path = ROOT / ".github" / "workflows" / "redteamci.yml"
    checks.append(
        (
            workflow_path.exists(),
            f"GitHub Actions workflow {'found' if workflow_path.exists() else 'missing'}: {workflow_path}",
        )
    )
    streamlit_available = importlib.util.find_spec("streamlit") is not None
    checks.append(
        (
            streamlit_available or not args.dashboard,
            "Streamlit importable"
            if streamlit_available
            else "Streamlit not installed; dashboard check skipped",
        )
    )
    claude_available = shutil.which("claude") is not None or (
        Path.home() / ".local" / "bin" / "claude.exe"
    ).exists()
    checks.append(
        (
            True,
            (
                "Claude CLI available"
                if claude_available
                else "Claude CLI unavailable; fixture fallback available"
            ),
        )
    )
    report_path = DEFAULT_REPORT_PATH
    if report_path.exists():
        checks.append((True, f"Last report found: {report_path}"))

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
