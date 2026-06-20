from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import streamlit as st

from redteamci.paths import ROOT, TRACES_ROOT
from redteamci.patcher import generate_patch_document, preview_patch_diff
from redteamci.runner import latest_run_dir


st.set_page_config(page_title="RedTeamCI", layout="wide")


def main() -> None:
    st.title("RedTeamCI")
    st.caption("Crash-test your AI agent before production.")

    top_left, top_right = st.columns([3, 2])
    with top_left:
        run_clicked = st.button("Run Tests", use_container_width=True)
        rerun_clicked = st.button("Rerun", use_container_width=True)
    with top_right:
        if run_clicked:
            run_cli(["run"])
        if rerun_clicked:
            run_cli(["rerun"])

    summary, traces = load_latest()

    left, middle, right = st.columns([1.2, 2.2, 2.2])

    selected_attack = None
    with left:
        st.subheader("Attack Suite")
        if not summary:
            st.info("No run yet.")
        else:
            options = [item["id"] for item in summary["results"]]
            labels = {
                item["id"]: f'{item["status"]}  {item["id"]}  {item["name"]}'
                for item in summary["results"]
            }
            selected_attack = st.radio(
                "Attacks",
                options,
                format_func=lambda value: labels[value],
                label_visibility="collapsed",
            )

    with middle:
        st.subheader("Flight Recorder")
        if selected_attack and selected_attack in traces:
            trace = traces[selected_attack]
            st.write(f"Status: `{trace['status']}`")
            for event in trace.get("events", []):
                with st.expander(event.get("title", event.get("type", "event"))):
                    st.json(event)
        else:
            st.info("Select an attack after running the suite.")

    with right:
        st.subheader("Claude Patch")
        if selected_attack:
            try:
                patch_doc, source = generate_patch_document(
                    attack_id=selected_attack,
                    use_fixture=True,
                )
                diff = preview_patch_diff(patch_doc)
                st.caption(f"Patch source: {source}")
                st.code(diff or "No patch needed.", language="diff")
                if st.button("Apply Patch", use_container_width=True):
                    run_cli(["fix", selected_attack, "--use-fixture"])
                if st.button("Apply & Rerun", use_container_width=True):
                    run_cli(["fix", selected_attack, "--use-fixture"])
                    run_cli(["rerun"])
            except Exception as exc:
                st.error(str(exc))
        else:
            st.info("Run the suite and select a failed attack.")


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


def load_latest() -> tuple[dict | None, dict[str, dict]]:
    run_dir = latest_run_dir(TRACES_ROOT)
    if run_dir is None:
        return None, {}
    summary_path = run_dir / "summary.json"
    if not summary_path.exists():
        return None, {}
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    traces: dict[str, dict] = {}
    for trace_path in run_dir.glob("*.json"):
        if trace_path.name == "summary.json":
            continue
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        traces[trace["attack_id"]] = trace
    return summary, traces


if __name__ == "__main__":
    main()
