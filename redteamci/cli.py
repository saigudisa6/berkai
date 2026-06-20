from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from .paths import DEFAULT_GUARDRAILS_PATH, TRACES_ROOT, UNSAFE_GUARDRAILS_PATH
from .patcher import apply_patch_document, generate_patch_document, preview_patch_diff
from .runner import RunReport, latest_run_dir, run_suite


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
    if args.command == "latest":
        return latest_command(args)

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
        sub.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
        sub.add_argument("--traces-root", default=str(TRACES_ROOT))
        sub.add_argument("--attack", action="append", dest="attacks")
        sub.add_argument("--offline", action="store_true", help="Use only local fixtures.")
        sub.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    fix = subparsers.add_parser("fix")
    fix.add_argument("attack_id")
    fix.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))
    fix.add_argument("--traces-root", default=str(TRACES_ROOT))
    fix.add_argument("--run-id")
    fix.add_argument("--use-fixture", action="store_true")
    fix.add_argument("--live", action="store_true")
    fix.add_argument("--dry-run", action="store_true")
    fix.add_argument("--json", action="store_true")

    reset = subparsers.add_parser("reset")
    reset.add_argument("--guardrails", default=str(DEFAULT_GUARDRAILS_PATH))

    dashboard = subparsers.add_parser("dashboard")
    dashboard.add_argument("streamlit_args", nargs=argparse.REMAINDER)

    latest = subparsers.add_parser("latest")
    latest.add_argument("--traces-root", default=str(TRACES_ROOT))

    return parser


def run_command(args: argparse.Namespace, rerun: bool = False) -> int:
    report = run_suite(
        guardrails_path=args.guardrails,
        traces_root=args.traces_root,
        selected_attack_ids=args.attacks,
    )
    if args.json:
        print(json.dumps(report_to_json(report), indent=2))
    else:
        print_run_report(report, rerun=rerun)
    return 1 if report.failed else 0


def fix_command(args: argparse.Namespace) -> int:
    patch_document, source = generate_patch_document(
        attack_id=args.attack_id,
        guardrails_path=args.guardrails,
        traces_root=args.traces_root,
        run_id=args.run_id,
        use_fixture=args.use_fixture,
        live=args.live,
    )
    diff = preview_patch_diff(patch_document, guardrails_path=args.guardrails)

    if not args.dry_run:
        diff = apply_patch_document(patch_document, guardrails_path=args.guardrails)

    if args.json:
        print(
            json.dumps(
                {
                    "source": source,
                    "applied": not args.dry_run,
                    "patch": patch_document,
                    "diff": diff,
                },
                indent=2,
            )
        )
        return 0

    print(f"Claude analyzed latest trace for {args.attack_id}")
    print(f"Source: {source}")
    print()
    print("Failure:")
    print(patch_document.get("failure_analysis", "No failure analysis returned."))
    print()
    print("Patch:")
    print(diff.rstrip() or "No guardrail changes needed.")
    print()
    regression = patch_document.get("regression_test", {})
    if regression:
        print("Regression test:")
        print(f"+ {regression.get('id')}")
    print()
    print("Applied patch." if not args.dry_run else "Dry run only. Patch not applied.")
    return 0


def reset_command(args: argparse.Namespace) -> int:
    shutil.copyfile(UNSAFE_GUARDRAILS_PATH, Path(args.guardrails))
    print(f"Reset {args.guardrails} to unsafe demo guardrails.")
    return 0


def dashboard_command(args: argparse.Namespace) -> int:
    command = [sys.executable, "-m", "streamlit", "run", "redteamci/dashboard.py"]
    command.extend(args.streamlit_args or [])
    return subprocess.call(command)


def latest_command(args: argparse.Namespace) -> int:
    latest = latest_run_dir(args.traces_root)
    if latest is None:
        print("No RedTeamCI traces found.")
        return 1
    print(latest)
    return 0


def print_run_report(report: RunReport, *, rerun: bool = False) -> None:
    label = "rerun" if rerun else "run"
    print(f"RedTeamCI {report.run_id} ({label})")
    print()
    for result in report.results:
        marker = "PASS" if result.status == "PASS" else "FAIL"
        print(f"[{marker}] {result.id} {result.name}")
        print(f"  {result.summary}")
        print()
    print(f"{len(report.failed)} failed, {len(report.passed)} passed")
    print(f"Trace saved to {report.traces_dir}/")
    if not report.failed:
        print()
        print("AGENT CERTIFIED")


def report_to_json(report: RunReport) -> dict[str, object]:
    return {
        "run_id": report.run_id,
        "failed": len(report.failed),
        "passed": len(report.passed),
        "traces_dir": str(report.traces_dir),
        "results": [
            {
                "id": result.id,
                "name": result.name,
                "status": result.status,
                "summary": result.summary,
                "reason": result.reason,
                "trace_path": str(result.trace_path),
            }
            for result in report.results
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
