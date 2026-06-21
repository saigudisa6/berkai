from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .adapters import (
    DEFAULT_HTTP_DEMO_URL,
    AgentConfig,
    check_cli_agent_config,
    check_http_agent,
)
from .claude_code import (
    ClaudeCodeRemediator,
    build_claude_prompt,
    build_claude_proposal_prompt,
    write_claude_prompt_artifact,
)
from .config import load_manifest
from .generator import DEFAULT_PLAN_OUTPUT_DIR, write_plan_outputs
from .github_annotations import ANNOTATION_LEVELS, render_github_annotations
from .github_summary import DEFAULT_GITHUB_SUMMARY_PATH, write_github_summary
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
from .summary import load_summary, write_junit_summary, write_sarif_summary, write_summary
from .trace_viewer import format_trace_timeline, load_trace


DEFAULT_GATE_SUMMARY_PATH = Path("before.json")
DEFAULT_GATE_JUNIT_PATH = Path("before.junit.xml")
DEFAULT_GATE_SARIF_PATH = Path("before.sarif")
DEFAULT_GITHUB_GATE_WORKFLOW_PATH = Path(".github") / "workflows" / "redteamci-agent-security.yml"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return run_command(args)
    if args.command == "rerun":
        return run_command(args, rerun=True)
    if args.command == "gate":
        return gate_command(args)
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
    if args.command == "github-summary":
        return github_summary_command(args)
    if args.command == "github-annotations":
        return github_annotations_command(args)
    if args.command == "trace":
        return trace_command(args)
    if args.command == "plan":
        return plan_command(args)
    if args.command == "story":
        return story_command(args)

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

    gate = subparsers.add_parser("gate")
    gate.add_argument("--config", default=str(DEFAULT_MANIFEST_PATH))
    gate.add_argument("--agent")
    gate.add_argument("--agent-url")
    gate.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
    gate.add_argument("--regressions")
    gate.add_argument("--attacks", dest="attack_pack")
    gate.add_argument("--traces-root", default=str(TRACES_ROOT))
    gate.add_argument("--attack", action="append", dest="attacks")
    gate.add_argument("--offline", action="store_true", help="Use only local fixtures.")
    gate.add_argument("--summary", default=str(DEFAULT_GATE_SUMMARY_PATH))
    gate.add_argument("--junit", default=str(DEFAULT_GATE_JUNIT_PATH))
    gate.add_argument("--sarif", default=str(DEFAULT_GATE_SARIF_PATH))
    gate.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    gate.add_argument("--github-annotations", action="store_true")
    gate.add_argument(
        "--annotation-level",
        choices=ANNOTATION_LEVELS,
        default="error",
    )

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
    init.add_argument("--config", default="redteamci.yml")
    init.add_argument("--agent", choices=["builtin", "http"], default="builtin")
    init.add_argument("--agent-url", default=DEFAULT_HTTP_DEMO_URL)
    init.add_argument("--force", action="store_true")
    init.add_argument("--github-workflow", action="store_true")

    dashboard = subparsers.add_parser("dashboard")
    dashboard.add_argument("streamlit_args", nargs=argparse.REMAINDER)

    latest = subparsers.add_parser("latest")
    latest.add_argument("--traces-root", default=str(TRACES_ROOT))

    report = subparsers.add_parser("report")
    report.add_argument("--before", default=str(DEFAULT_BEFORE_SUMMARY_PATH))
    report.add_argument("--after", default=str(DEFAULT_AFTER_SUMMARY_PATH))
    report.add_argument("--output", default=str(DEFAULT_REPORT_PATH))

    github_summary = subparsers.add_parser("github-summary")
    github_summary.add_argument("--before", default=str(DEFAULT_BEFORE_SUMMARY_PATH))
    github_summary.add_argument("--after", default=str(DEFAULT_AFTER_SUMMARY_PATH))
    github_summary.add_argument("--output", default=str(DEFAULT_GITHUB_SUMMARY_PATH))
    github_summary.add_argument("--github-step-summary", action="store_true")

    github_annotations = subparsers.add_parser("github-annotations")
    github_annotations.add_argument("--summary", default=str(DEFAULT_BEFORE_SUMMARY_PATH))
    github_annotations.add_argument(
        "--level",
        choices=ANNOTATION_LEVELS,
        default="error",
    )

    trace = subparsers.add_parser("trace")
    trace.add_argument("attack_id")
    trace.add_argument("--run-id")
    trace.add_argument("--traces-root", default=str(TRACES_ROOT))
    trace.add_argument("--json", action="store_true")

    plan = subparsers.add_parser("plan")
    plan.add_argument("--config", default=str(DEFAULT_MANIFEST_PATH))
    plan.add_argument("--output-dir", default=str(DEFAULT_PLAN_OUTPUT_DIR))
    plan.add_argument("--attack-pack")
    plan.add_argument("--json", action="store_true")

    story = subparsers.add_parser("story")
    story.add_argument("story_name", choices=["support"])
    story.add_argument(
        "--step",
        choices=[
            "prepare",
            "plan",
            "red",
            "trace",
            "remediate",
            "claude-code-remediate",
            "green",
            "state",
            "full",
        ],
        required=True,
    )
    story.add_argument("--phase", choices=["red", "green"], default="red")
    story.add_argument("--attack", default="generated-refund-001")
    story.add_argument("--strict-claude-code", action="store_true")
    story.add_argument("--fixture-fallback", action="store_true")
    story.add_argument("--mode", choices=["proposal", "direct-edit"], default="proposal")
    story.add_argument("--json", action="store_true")
    story.add_argument("--github-annotations", action="store_true")
    story.add_argument(
        "--fail-on-security-failure",
        action="store_true",
        help="Exit nonzero for expected red findings when used as a GitHub check.",
    )

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


def gate_command(args: argparse.Namespace) -> int:
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
        mode="gate",
    )
    write_summary(report.summary, args.summary)
    write_junit_summary(report.summary, args.junit)
    write_sarif_summary(report.summary, args.sarif)
    if args.json:
        print(json.dumps(report.summary, indent=2))
    else:
        print_run_report(report, label="gate")
    if args.github_annotations:
        for annotation in render_github_annotations(
            report.summary,
            level=args.annotation_level,
        ):
            print(annotation)
    return 1 if report.failed else 0


def fix_command(args: argparse.Namespace) -> int:
    trace = load_trace_for_attack(
        attack_id=args.attack_id,
        traces_root=args.traces_root,
        run_id=args.run_id,
    )
    trace_path = Path(trace["trace_path"])
    apply = bool(args.apply and not args.dry_run)
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
                    "diff_path": result.diff_path,
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
                        "diff_path": result.diff_path,
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
    streamlit_args = list(args.streamlit_args or [])
    if streamlit_args[:1] == ["--"]:
        streamlit_args = streamlit_args[1:]
    command.extend(streamlit_args)
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
    workflow_path = Path.cwd() / DEFAULT_GITHUB_GATE_WORKFLOW_PATH
    if args.github_workflow and workflow_path.exists() and not args.force:
        print(f"{workflow_path} already exists. Use --force to overwrite.")
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
    if args.github_workflow:
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(
            _github_gate_workflow(config_path=_workflow_config_path(path)),
            encoding="utf-8",
        )
        print(f"Wrote {workflow_path}")
    return 0


def _github_gate_workflow(*, config_path: str) -> str:
    return f"""name: RedTeamCI Agent Security

on:
  pull_request:
  push:
  workflow_dispatch:

jobs:
  redteamci:
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install RedTeamCI
        run: python -m pip install git+https://github.com/saigudisa6/berkai.git

      - name: Validate RedTeamCI configuration
        run: python -m redteamci.cli doctor --config {config_path}

      - name: Run RedTeamCI security gate
        run: python -m redteamci.cli gate --config {config_path} --github-annotations

      - name: Upload RedTeamCI artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: redteamci-agent-security
          if-no-files-found: ignore
          path: |
            before.json
            before.junit.xml
            before.sarif
            traces/
            regressions/generated_attacks.json
"""


def _workflow_config_path(config_path: Path) -> str:
    if config_path.is_absolute():
        try:
            return config_path.relative_to(Path.cwd()).as_posix()
        except ValueError:
            return config_path.as_posix()
    return config_path.as_posix()


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


def github_summary_command(args: argparse.Namespace) -> int:
    output, appended = write_github_summary(
        before_path=args.before,
        after_path=args.after,
        output_path=args.output,
        github_step_summary=args.github_step_summary,
    )
    print(f"Wrote {output}")
    if args.github_step_summary:
        if appended:
            print(f"Appended GitHub job summary: {appended}")
        else:
            print(
                "GITHUB_STEP_SUMMARY is not set; wrote "
                f"{output} without appending a job summary."
            )
    return 0


def github_annotations_command(args: argparse.Namespace) -> int:
    summary = load_summary(args.summary)
    for annotation in render_github_annotations(summary, level=args.level):
        print(annotation)
    return 0


def trace_command(args: argparse.Namespace) -> int:
    try:
        trace = load_trace(
            args.attack_id,
            traces_root=args.traces_root,
            run_id=args.run_id,
        )
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}")
        return 1

    if args.json:
        print(json.dumps(trace, indent=2))
    else:
        print(format_trace_timeline(trace))
    return 0


def plan_command(args: argparse.Namespace) -> int:
    paths = write_plan_outputs(
        config_path=args.config,
        output_dir=args.output_dir,
        attack_pack_path=args.attack_pack,
    )
    if args.json:
        print(json.dumps({key: str(path) for key, path in paths.items()}, indent=2))
        return 0

    print("RedTeamCI generated attack plan")
    for label, path in paths.items():
        print(f"{label}: {path}")
    return 0


def story_command(args: argparse.Namespace) -> int:
    from .story import (
        apply_support_story_remediation,
        build_support_story_proof,
        generate_support_story_plan,
        load_support_story_state,
        load_support_story_trace,
        prepare_support_story_workspace,
        run_support_story_claude_code_remediation,
        run_full_support_story_local,
        run_support_story_green_local,
        run_support_story_red_local,
        story_artifacts,
    )

    if args.step == "prepare":
        result = prepare_support_story_workspace()
        return _print_story_result(result, args)
    if args.step == "plan":
        result = generate_support_story_plan()
        return _print_story_result(result, args)
    if args.step == "red":
        result = run_support_story_red_local()
        return _print_story_result(result, args, red_step=True)
    if args.step == "trace":
        try:
            trace = load_support_story_trace(args.phase, args.attack)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            return 1
        if args.json:
            print(json.dumps(trace, indent=2))
        else:
            print(format_trace_timeline(trace))
        return 0
    if args.step == "remediate":
        result = apply_support_story_remediation()
        return _print_story_result(result, args)
    if args.step == "claude-code-remediate":
        result = run_support_story_claude_code_remediation(
            strict_claude_code=args.strict_claude_code,
            fixture_fallback=True,
            mode=args.mode,
        )
        return _print_story_result(result, args)
    if args.step == "green":
        result = run_support_story_green_local()
        return _print_story_result(result, args)
    if args.step == "state":
        state = load_support_story_state()
        proof = build_support_story_proof()
        state = {**state, "proof": proof or state.get("proof", {})}
        if args.json:
            print(json.dumps(state, indent=2))
        else:
            _print_story_state(state, story_artifacts())
        return 0 if proof.get("certified") else 1
    if args.step == "full":
        state = run_full_support_story_local()
        if args.json:
            print(json.dumps(state, indent=2))
        else:
            _print_story_state(state.get("state", {}), story_artifacts())
        green = state.get("green", {})
        return 0 if green.get("ok") else 1
    return 1


def _print_story_result(
    result: object,
    args: argparse.Namespace,
    *,
    red_step: bool = False,
) -> int:
    summary_path = getattr(result, "summary_path", None)
    proof = getattr(result, "proof", None)
    details = getattr(result, "details", None)
    if args.json:
        print(
            json.dumps(
                {
                    "step": getattr(result, "step", ""),
                    "ok": bool(getattr(result, "ok", False)),
                    "summary_path": str(summary_path) if summary_path else None,
                    "proof": proof,
                    "details": details,
                },
                indent=2,
            )
        )
    else:
        print(f"Support story step: {getattr(result, 'step', '')}")
        print(f"OK: {bool(getattr(result, 'ok', False))}")
        if summary_path:
            print(f"Summary: {summary_path}")
        if proof:
            _print_support_story_proof(proof)
        if isinstance(details, dict) and details:
            _print_story_details(details)
    if args.github_annotations:
        for annotation in getattr(result, "annotations", None) or []:
            print(annotation)
    if red_step and args.fail_on_security_failure:
        summary = load_summary(summary_path) if summary_path else {}
        return 1 if int(summary.get("failed", 0)) else 0
    return 0 if bool(getattr(result, "ok", False)) else 1


def _print_story_details(details: dict[str, Any]) -> None:
    if details.get("source"):
        print(f"Source: {details.get('source')}")
    print(f"Live Claude proposal applied: {details.get('live_claude_proposal_applied')}")
    print(f"Fixture fallback used: {details.get('fixture_fallback_used')}")
    if details.get("prompt_path"):
        print(f"Claude prompt: {details['prompt_path']}")
    if details.get("raw_output_path"):
        print(f"Claude raw output: {details['raw_output_path']}")
    if details.get("proposal_path"):
        print(f"Claude proposal: {details['proposal_path']}")
    if details.get("validation_error_path"):
        print(f"Claude validation errors: {details['validation_error_path']}")
    if details.get("summary_path"):
        print(f"Patch summary: {details['summary_path']}")
    if details.get("diff_path"):
        print(f"Patch diff: {details['diff_path']}")
    if details.get("regression_test_path"):
        print(f"Regression test: {details['regression_test_path']}")
    if details.get("error"):
        print(f"Error: {details['error']}")


def _print_story_state(state: dict[str, Any], artifacts: dict[str, str]) -> None:
    proof = state.get("proof") if isinstance(state.get("proof"), dict) else {}
    print("RedTeamCI support story")
    for key, value in artifacts.items():
        print(f"{key}: {value}")
    if state.get("red"):
        red = state["red"]
        print(f"red: {red.get('failed', 0)} failed, {red.get('passed', 0)} passed")
    if state.get("green"):
        green = state["green"]
        print(f"green: {green.get('failed', 0)} failed, {green.get('passed', 0)} passed")
    if proof:
        _print_support_story_proof(proof)


def _print_support_story_proof(proof: dict[str, Any]) -> None:
    status = "AGENT CERTIFIED" if proof.get("certified") else "NOT CERTIFIED"
    print(status)
    print(f"red refund executed: {proof.get('red_refund_executed')}")
    print(f"green refund attempted: {proof.get('green_refund_attempted')}")
    print(f"green refund blocked: {proof.get('green_refund_blocked')}")
    print(
        "blocked-before-execution assertion passed: "
        f"{proof.get('green_blocked_before_execution_assertion_passed')}"
    )
    print(f"regression loaded and passed: {proof.get('regression_loaded_and_passed')}")


def print_run_report(
    report: RunReport,
    *,
    rerun: bool = False,
    label: str | None = None,
) -> None:
    label = label or ("rerun" if rerun else "run")
    print(f"RedTeamCI {report.run_id} ({label})")
    print(f"Agent: {report.summary.get('integrations', {}).get('agent', 'builtin')}")
    print()
    for result in report.results:
        marker = "PASS" if result.status == "PASS" else "FAIL"
        print(f"[{marker}] {result.id} {result.name}")
        print(f"  {result.summary}")
        if result.source == "generated":
            print("  Source: generated regression")
        elif result.source == "generated_plan":
            print("  Source: generated attack plan")
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
    if explicit:
        return explicit
    value = manifest.get(key)
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
    if selected == "cli":
        return AgentConfig(
            kind="cli",
            command=_manifest_command(manifest, "agent_command"),
            cwd=_manifest_path(manifest.get("agent_cwd"), manifest),
            timeout=_manifest_int(manifest, "agent_timeout", 10),
            max_stdout_bytes=_manifest_int(manifest, "agent_max_stdout_bytes", 64 * 1024),
            max_stderr_bytes=_manifest_int(manifest, "agent_max_stderr_bytes", 16 * 1024),
        )
    if selected == "repo":
        return AgentConfig(
            kind="repo",
            command=(
                _manifest_command(manifest, "agent_entrypoint")
                or _manifest_command(manifest, "agent_command")
            ),
            cwd=_manifest_path(manifest.get("agent_cwd"), manifest),
            timeout=_manifest_int(manifest, "agent_timeout", 10),
            max_stdout_bytes=_manifest_int(manifest, "agent_max_stdout_bytes", 64 * 1024),
            max_stderr_bytes=_manifest_int(manifest, "agent_max_stderr_bytes", 16 * 1024),
        )
    return AgentConfig(kind="builtin")


def _manifest_command(manifest: dict[str, str], key: str) -> str | list[str] | None:
    raw = manifest.get(key)
    if not raw:
        return None
    stripped = raw.strip()
    if stripped.startswith("["):
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            return raw
        if isinstance(value, list):
            return [str(item) for item in value]
    return raw


def _manifest_path(value: str | None, manifest: dict[str, str]) -> str | None:
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str(Path(manifest.get("_base_dir", ".")) / path)


def _manifest_int(manifest: dict[str, str], key: str, default: int) -> int:
    raw = manifest.get(key)
    if raw is None:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


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
    elif agent_config.kind in {"cli", "repo"}:
        ok, message = check_cli_agent_config(agent_config)
        checks.append((ok, message))
    else:
        checks.append((False, f"Unsupported agent: {agent_config.kind}"))
    return checks


if __name__ == "__main__":
    raise SystemExit(main())
