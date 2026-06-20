from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import streamlit as st

from redteamci.paths import (
    DEFAULT_AFTER_SUMMARY_PATH,
    DEFAULT_BEFORE_SUMMARY_PATH,
    DEFAULT_REPORT_PATH,
    PATCHES_ROOT,
    ROOT,
)
from redteamci.summary import load_summary


st.set_page_config(page_title="RedTeamCI", layout="wide")


def main() -> None:
    st.title("RedTeamCI")
    st.caption("Crash-test your AI agent before production.")

    before = _load_optional_summary(DEFAULT_BEFORE_SUMMARY_PATH)
    after = _load_optional_summary(DEFAULT_AFTER_SUMMARY_PATH)
    _render_top_metrics(before, after)
    _render_actions()

    left, middle, right = st.columns([1.3, 2.2, 2.2])
    selected_attack = _render_attack_suite(left, before, after)
    _render_flight_recorder(middle, selected_attack, before, after)
    _render_patch_panel(right)


def _render_top_metrics(before: dict[str, Any] | None, after: dict[str, Any] | None) -> None:
    cols = st.columns(3)
    total = (after or before or {}).get("total_attacks", 4)
    before_passed = before.get("passed", 0) if before else 0
    after_passed = after.get("passed", 0) if after else 0
    certified = bool(after and after.get("certified"))
    cols[0].metric("Before", f"{before_passed}/{total} secure")
    cols[1].metric("After", f"{after_passed}/{total} secure")
    cols[2].metric("Status", "AGENT CERTIFIED" if certified else "NOT CERTIFIED")


def _render_actions() -> None:
    cols = st.columns(4)
    if cols[0].button("Run Tests", use_container_width=True):
        run_cli(["reset"])
        run_cli(["run", "--expect-fail", "--summary", "before.json"])
    if cols[1].button("Generate Fix", use_container_width=True):
        run_cli(["fix", "pi-003", "--use-fixture", "--apply"])
    if cols[2].button("Apply & Rerun", use_container_width=True):
        run_cli(["fix", "pi-003", "--use-fixture", "--apply"])
        run_cli(["rerun", "--expect-pass", "--summary", "after.json"])
    if cols[3].button("Generate Report", use_container_width=True):
        run_cli(["report", "--before", "before.json", "--after", "after.json"])


def _render_attack_suite(
    column: Any,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> str | None:
    with column:
        st.subheader("Attack Suite")
        attacks = before.get("attacks", []) if before else after.get("attacks", []) if after else []
        if not attacks:
            st.info("Run the suite to populate before/after results.")
            return None
        labels = {}
        ids = []
        for attack in attacks:
            after_attack = _attack_by_id(after, attack["id"]) if after else None
            ids.append(attack["id"])
            labels[attack["id"]] = (
                f'{attack["id"]}  before={attack["status"]}  '
                f'after={(after_attack or {}).get("status", "-")}'
            )
        return st.radio(
            "Attacks",
            ids,
            format_func=lambda value: labels[value],
            label_visibility="collapsed",
        )


def _render_flight_recorder(
    column: Any,
    selected_attack: str | None,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> None:
    with column:
        st.subheader("Flight Recorder")
        if not selected_attack:
            st.info("Select an attack after running the suite.")
            return
        run_choice = st.radio("Run", ["before", "after"], horizontal=True)
        summary = before if run_choice == "before" else after
        attack = _attack_by_id(summary, selected_attack) if summary else None
        if not attack:
            st.info(f"No {run_choice} trace for {selected_attack}.")
            return
        trace = _load_json(Path(attack["trace_path"]))
        if not trace:
            st.warning("Trace file not found.")
            return
        if attack.get("blocked_before_execution"):
            st.success("Blocked before execution")
        for event in trace.get("events", []):
            label = event.get("title", event.get("type", "event"))
            severity = event.get("severity", "info")
            with st.expander(f"{severity.upper()} - {label}", expanded=event.get("type") == "outcome"):
                st.json(event)


def _render_patch_panel(column: Any) -> None:
    with column:
        st.subheader("Claude Code Patch")
        summary, diff = _latest_patch()
        if not summary:
            st.info("Generate a fix to see remediation output.")
            return
        st.caption(f"Remediation source: {summary.get('source', 'unknown')}")
        st.write("Changed files:")
        for path in summary.get("changed_files", []):
            st.write(f"- {path}")
        st.code(diff or "No patch diff found.", language="diff")
        regression_path = summary.get("regression_test_path")
        if regression_path and Path(regression_path).exists():
            st.write("Generated regression test")
            st.json(_load_json(Path(regression_path)))


def run_cli(args: list[str]) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "redteamci.cli", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        st.code(result.stdout)
    if result.stderr:
        st.error(result.stderr)


def _load_optional_summary(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return load_summary(path)


def _attack_by_id(summary: dict[str, Any] | None, attack_id: str) -> dict[str, Any] | None:
    if not summary:
        return None
    for attack in summary.get("attacks", []):
        if attack.get("id") == attack_id:
            return attack
    return None


def _latest_patch() -> tuple[dict[str, Any] | None, str]:
    if not PATCHES_ROOT.exists():
        return None, ""
    summaries = sorted(PATCHES_ROOT.glob("*_summary.json"), key=lambda path: path.stat().st_mtime)
    if not summaries:
        return None, ""
    summary = _load_json(summaries[-1])
    diff_path = Path(str(summary.get("diff_path", "")))
    diff = diff_path.read_text(encoding="utf-8") if diff_path.exists() else ""
    return summary, diff


def _load_json(path: Path) -> dict[str, Any] | list[Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


if __name__ == "__main__":
    main()
