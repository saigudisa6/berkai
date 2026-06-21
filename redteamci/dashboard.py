from __future__ import annotations

import json
import os
import subprocess
import sys
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import quote

try:
    import streamlit as st
except ModuleNotFoundError:  # pragma: no cover - lets helper tests run without Streamlit.
    st = None

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteamci.paths import (
    DEFAULT_AFTER_SUMMARY_PATH,
    DEFAULT_BEFORE_SUMMARY_PATH,
    DEFAULT_REPORT_PATH,
    GENERATED_REGRESSIONS_PATH,
    PATCHES_ROOT,
    ROOT,
)
from redteamci.claude_code import ClaudeCodeRemediator
from redteamci.github_actions import (
    GitHubActionsError,
    configured_branch,
    configured_workflow_file,
    github_available,
    list_artifacts,
    poll_workflow_run,
    trigger_support_story_workflow,
    wait_for_workflow_run,
    workflow_run_url,
)
from redteamci.summary import load_summary


REDTEAMCI_OUTPUT_DIR = ".redteamci"
AGENT_PROFILE_FILE = "agent_profile.json"
CAPABILITY_PROFILE_FILE = "capability_profile.json"
ATTACK_PLAN_FILE = "attack_plan.json"
ATTACK_PLAN_MARKDOWN_FILE = "attack_plan.md"
LEVEL_1_WARNING = (
    "Level 1 trace/report/proposal only; no forced blocking unless the agent uses guarded tools."
)
SUPPORT_STORY_RELATIVE_ROOT = Path(".demo") / "support-story"
SUPPORT_STORY_ATTACKS = [
    "generated-refund-001",
    "generated-email-001",
    "generated-pii-001",
    "regression-generated-refund-001",
]
PRESENTER_ATTACKS = [
    {
        "id": "generated-refund-001",
        "name": "unauthorized refund",
        "focus": True,
    },
    {
        "id": "generated-email-001",
        "name": "external email exfiltration",
        "focus": False,
    },
    {
        "id": "generated-pii-001",
        "name": "PII leakage",
        "focus": False,
    },
]
PRESENTER_CAPABILITIES = ["Refunds", "Email", "Customer Data", "PII"]
DETERMINISTIC_DEMO_PROOF_STEPS = ["prepare", "plan", "red", "remediate", "green"]
PRESENTER_REFUND_AMOUNT = 500


def main() -> None:
    streamlit = _require_streamlit()
    streamlit.set_page_config(page_title="RedTeamCI", layout="wide")

    presenter_tab, developer_tab, artifacts_tab = st.tabs(
        ["Presenter Mode", "Developer Mode", "Artifacts"]
    )
    with presenter_tab:
        _render_presenter_mode()
    with developer_tab:
        st.subheader("Support Story Deep Inspection")
        _render_support_story_mode()
        st.divider()
        st.subheader("General Suite Developer Mode")
        before = _load_optional_summary(DEFAULT_BEFORE_SUMMARY_PATH)
        after = _load_optional_summary(DEFAULT_AFTER_SUMMARY_PATH)
        _render_top_metrics(before, after)
        _render_demo_mode_actions()
        _render_generated_plan_panel(load_generated_plan_panel(ROOT))

        left, middle, right = st.columns([1.3, 2.2, 2.2])
        selected_attack = _render_attack_suite(left, before, after)
        _render_flight_recorder(middle, selected_attack, before, after)
        _render_patch_panel(right)
    with artifacts_tab:
        _render_artifacts_tab(ROOT)


def _require_streamlit() -> Any:
    if st is None:
        raise RuntimeError("Streamlit is required to launch the RedTeamCI dashboard.")
    return st


def _inject_presenter_styles() -> None:
    st.markdown(
        """
        <style>
        .stApp {
          background: #f6f8fb;
          color: #111827;
        }
        .block-container {
          padding-top: 1.6rem;
          padding-bottom: 2.2rem;
          max-width: 1280px;
        }
        .stApp h1,
        .stApp h2,
        .stApp h3,
        .stApp h4,
        .stApp h5,
        .stApp h6,
        div[data-testid="stMarkdownContainer"],
        div[data-testid="stMarkdownContainer"] p,
        div[data-testid="stMarkdownContainer"] li {
          color: #111827;
        }
        div[data-testid="stCaptionContainer"],
        div[data-testid="stCaptionContainer"] p,
        div[data-testid="stCaptionContainer"] span {
          color: #334155 !important;
        }
        div[data-testid="stMetricLabel"],
        div[data-testid="stMetricLabel"] p,
        div[data-testid="stMetricLabel"] span {
          color: #334155 !important;
          font-weight: 700;
        }
        div[data-testid="stMetricValue"],
        div[data-testid="stMetricValue"] div,
        div[data-testid="stMetricValue"] span {
          color: #0f172a !important;
          font-weight: 800;
        }
        div[data-testid="stAlert"] {
          border-radius: 8px;
        }
        div[data-testid="stAlert"],
        div[data-testid="stAlert"] p,
        div[data-testid="stAlert"] span,
        div[data-testid="stAlert"] div {
          color: #111827 !important;
        }
        div[data-testid="stCheckbox"] label,
        div[data-testid="stCheckbox"] p,
        div[data-testid="stCheckbox"] span {
          color: #111827 !important;
        }
        div[data-testid="stButton"] button {
          border-radius: 8px;
          border: 1px solid #cbd5e1;
          background: #ffffff;
          color: #0f172a;
          font-weight: 700;
          min-height: 2.55rem;
          white-space: normal;
          line-height: 1.2;
        }
        div[data-testid="stButton"] button:hover {
          border-color: #2563eb;
          color: #1d4ed8;
        }
        .rt-hero {
          background: #fbfdff;
          border: 1px solid #d8e0ea;
          border-left: 5px solid #2f6fed;
          border-radius: 8px;
          padding: 22px 26px;
          box-shadow: 0 12px 28px rgba(15, 23, 42, 0.06);
          margin-bottom: 12px;
        }
        .rt-eyebrow {
          color: #1d4ed8;
          font-size: 0.78rem;
          font-weight: 800;
          letter-spacing: 0;
          text-transform: uppercase;
          margin-bottom: 6px;
        }
        .rt-title {
          font-size: 3rem;
          line-height: 1;
          font-weight: 800;
          letter-spacing: 0;
          margin: 0;
          color: #111827;
        }
        .rt-headline {
          font-size: 1.1rem;
          color: #334155;
          margin-top: 8px;
          max-width: 940px;
        }
        .rt-script {
          margin-top: 14px;
          color: #475569;
          line-height: 1.5;
          max-width: 980px;
        }
        .rt-status-grid,
        .rt-stepper,
        .rt-card-grid,
        .rt-proof-grid {
          display: grid;
          gap: 10px;
        }
        .rt-status-grid {
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          margin: 12px 0 14px;
        }
        .rt-status-card,
        .rt-proof-tile,
        .rt-attack-card,
        .rt-panel,
        .rt-lane {
          background: #ffffff;
          border: 1px solid #dce3ed;
          border-radius: 8px;
          box-shadow: 0 8px 20px rgba(15, 23, 42, 0.045);
          box-sizing: border-box;
          overflow: hidden;
        }
        .rt-status-card {
          padding: 12px 14px;
          min-height: 76px;
        }
        .rt-label {
          color: #64748b;
          font-size: 0.76rem;
          font-weight: 750;
          letter-spacing: 0;
          text-transform: uppercase;
        }
        .rt-value {
          margin-top: 6px;
          color: #0f172a;
          font-size: 0.98rem;
          font-weight: 800;
          line-height: 1.25;
          overflow-wrap: anywhere;
        }
        .rt-card-good { border-top: 4px solid #0f766e; border-color: #badbd6; }
        .rt-card-bad { border-top: 4px solid #b42318; border-color: #efc7c3; }
        .rt-card-warn { border-top: 4px solid #b45309; border-color: #f1d4a5; }
        .rt-card-muted { border-top: 4px solid #64748b; border-color: #d8e0ea; }
        .rt-alert {
          border-radius: 8px;
          padding: 12px 14px;
          margin: 8px 0 16px;
          font-weight: 650;
        }
        .rt-alert-good {
          background: #edfdf8;
          border: 1px solid #b8e3d9;
          color: #075e55;
        }
        .rt-alert-warn {
          background: #fff8e8;
          border: 1px solid #f1d4a5;
          color: #8a4b0f;
        }
        .rt-alert-muted {
          background: #f1f5f9;
          border: 1px solid #d8e0ea;
          color: #334155;
        }
        .rt-stepper {
          grid-template-columns: repeat(auto-fit, minmax(118px, 1fr));
          margin: 14px 0 16px;
        }
        .rt-step {
          background: #ffffff;
          border: 1px solid #d8e0ea;
          color: #334155;
          border-radius: 8px;
          padding: 9px 10px;
          text-align: center;
          font-size: 0.82rem;
          font-weight: 750;
        }
        .rt-panel {
          padding: 18px;
          margin-bottom: 14px;
          min-height: 100%;
        }
        .rt-panel-title {
          margin: 0 0 4px;
          color: #0f172a;
          font-size: 1.15rem;
          font-weight: 830;
        }
        .rt-panel-subtitle {
          color: #64748b;
          margin-bottom: 12px;
          line-height: 1.4;
        }
        .rt-chip-row {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-top: 12px;
        }
        .rt-chip {
          display: inline-flex;
          align-items: center;
          border-radius: 999px;
          background: #f1f5f9;
          border: 1px solid #d8e0ea;
          color: #1e293b;
          padding: 6px 10px;
          font-size: 0.84rem;
          font-weight: 700;
        }
        .rt-card-grid {
          grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        }
        .rt-attack-card {
          padding: 13px 14px;
        }
        .rt-attack-id {
          color: #0f172a;
          font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          font-weight: 850;
          font-size: 0.88rem;
          overflow-wrap: anywhere;
        }
        .rt-attack-name {
          color: #475569;
          margin-top: 5px;
          min-height: 34px;
          line-height: 1.35;
        }
        .rt-mini-row {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          margin-top: 10px;
        }
        .rt-pill {
          border-radius: 999px;
          padding: 4px 8px;
          font-size: 0.72rem;
          font-weight: 800;
          background: #f1f5f9;
          color: #334155;
          line-height: 1.2;
        }
        .rt-pill-good { background: #ddf7ef; color: #075e55; }
        .rt-pill-bad { background: #fbe4e2; color: #9f1d16; }
        .rt-pill-warn { background: #fff0c7; color: #8a4b0f; }
        .rt-trace-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
          gap: 14px;
        }
        .rt-lane {
          padding: 16px;
        }
        .rt-lane-red { border-top: 4px solid #b42318; }
        .rt-lane-green { border-top: 4px solid #0f766e; }
        .rt-lane-title {
          font-size: 0.82rem;
          font-weight: 850;
          color: #334155;
          margin-bottom: 10px;
          letter-spacing: 0;
        }
        .rt-event {
          border-left: 3px solid #94a3b8;
          padding: 8px 10px;
          margin: 8px 0;
          background: #f8fafc;
          border-radius: 0 6px 6px 0;
          font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          font-size: 0.85rem;
          color: #172033;
          overflow-wrap: anywhere;
        }
        .rt-event-bad { border-left-color: #b42318; background: #fff1f2; }
        .rt-event-good { border-left-color: #0f766e; background: #edfdf8; }
        .rt-outcome {
          margin-top: 10px;
          padding: 9px 10px;
          border-radius: 6px;
          font-weight: 850;
          text-align: center;
        }
        .rt-outcome-good { background: #ddf7ef; color: #075e55; }
        .rt-outcome-bad { background: #fbe4e2; color: #9f1d16; }
        .rt-proof-grid {
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        }
        .rt-proof-tile {
          padding: 11px 12px;
        }
        .rt-proof-tile strong {
          display: block;
          color: #0f172a;
          margin-bottom: 3px;
        }
        .rt-muted {
          color: #64748b;
        }
        @media (max-width: 920px) {
          .block-container {
            padding-left: 1rem;
            padding-right: 1rem;
          }
          .rt-title {
            font-size: 2.35rem;
          }
          .rt-hero,
          .rt-panel {
            padding: 16px;
          }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_top_metrics(before: dict[str, Any] | None, after: dict[str, Any] | None) -> None:
    cols = st.columns(4)
    before_total = (before or {}).get("total_attacks", 4)
    after_total = (after or before or {}).get("total_attacks", before_total)
    before_passed = before.get("passed", 0) if before else 0
    after_passed = after.get("passed", 0) if after else 0
    certified = bool(after and after.get("certified"))
    generated_passed = (after or {}).get("generated_regressions_passed", 0)
    generated_loaded = (after or {}).get("generated_regressions_loaded", 0)
    cols[0].metric("Before", f"{before_passed}/{before_total} secure")
    cols[1].metric("After", f"{after_passed}/{after_total} secure")
    cols[2].metric("Status", "AGENT CERTIFIED" if certified else "NOT CERTIFIED")
    generated_status = "-" if not generated_loaded else "PASS" if generated_passed == generated_loaded else "FAIL"
    cols[3].metric("Generated regression", generated_status)
    agent = (after or before or {}).get("integrations", {}).get("agent", "builtin")
    if generated_loaded:
        st.success("Exploit became regression test")
    st.caption(f"Agent: {agent}")


def _render_demo_mode_actions() -> None:
    st.subheader("Demo Mode")
    _render_actions()


def _render_presenter_mode() -> None:
    _inject_presenter_styles()
    _render_classic_presenter_mode()


def _render_presenter_header(
    state: dict[str, Any],
    readiness: dict[str, Any],
) -> None:
    github_connected = github_available()[0]
    sentry_context = build_sentry_dashboard_context(state)
    st.markdown(
        """
        <div class="rt-hero">
          <div class="rt-eyebrow">Claude Code for AI-agent security gates</div>
          <h1 class="rt-title">RedTeamCI</h1>
          <div class="rt-headline">pytest for AI-agent security</div>
          <div class="rt-script">
            Companies are shipping agents that can issue refunds, send email,
            and touch customer data. Normal CI tests code. RedTeamCI tests
            whether the agent uses its tools safely.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    status_cards = [
        ("Scenario", "Customer Support Agent", "muted"),
        ("Proof", readiness["label"], _readiness_tone(readiness)),
        ("Release gate", "Local proof active", "good"),
        ("GitHub CI", "connected" if github_connected else "not connected", "muted"),
        (
            "Sentry",
            "optional, configured" if sentry_context["configured"] else "optional, not configured",
            "good" if sentry_context["configured"] else "muted",
        ),
    ]
    st.markdown(
        '<div class="rt-status-grid">'
        + "".join(_status_card_html(label, value, tone) for label, value, tone in status_cards)
        + "</div>",
        unsafe_allow_html=True,
    )

    if readiness["status"] == "ready":
        _render_presenter_alert(
            "good",
            "DEMO READY: red exploit, remediation artifact, generated regression, and green proof are complete.",
        )
    elif readiness["status"] == "partial":
        _render_presenter_alert(
            "warn",
            "INCOMPLETE: proof artifacts exist, but the full certification chain is not complete yet.",
        )
    else:
        _render_presenter_alert(
            "muted",
            "NO RUN YET: generate demo proof to create the local certification chain.",
        )


def _render_presenter_actions() -> None:
    cols = st.columns(5)
    if cols[0].button("Load Latest Proof", key="presenter_load", use_container_width=True):
        st.rerun()
    if cols[1].button(
        "Generate Demo Proof",
        key="presenter_generate_demo_proof",
        use_container_width=True,
    ):
        with st.spinner("Generating deterministic demo proof..."):
            run_deterministic_demo_proof()
        st.rerun()
    if cols[2].button("Run Red Gate", key="presenter_run_red", use_container_width=True):
        run_cli(["story", "support", "--step", "red"])
        st.rerun()

    strict_live = st.checkbox("Strict live Claude", key="presenter_strict_live")
    if cols[3].button(
        "Run Live Claude",
        key="presenter_run_live_claude",
        use_container_width=True,
    ):
        args = ["story", "support", "--step", "claude-code-remediate"]
        if strict_live:
            args.append("--strict-claude-code")
        else:
            args.append("--fixture-fallback")
        run_cli(args)
        st.rerun()
    if cols[4].button("Run Green Proof", key="presenter_run_green", use_container_width=True):
        run_cli(["story", "support", "--step", "green"])
        st.rerun()


def deterministic_demo_proof_commands() -> list[list[str]]:
    return [
        ["story", "support", "--step", step]
        for step in DETERMINISTIC_DEMO_PROOF_STEPS
    ]


def run_deterministic_demo_proof() -> None:
    for command in deterministic_demo_proof_commands():
        run_cli(command)


def _render_presenter_stepper() -> None:
    labels = [
        "Agent Profile",
        "Generated Attacks",
        "Red Gate",
        "Trace Replay",
        "Sentry Incident",
        "Claude Remediation",
        "Green Proof",
    ]
    st.markdown(
        '<div class="rt-stepper">'
        + "".join(f'<div class="rt-step">{_html(label)}</div>' for label in labels)
        + "</div>",
        unsafe_allow_html=True,
    )


def _render_agent_profile_panel() -> None:
    chips = "".join(f'<span class="rt-chip">{_html(capability)}</span>' for capability in PRESENTER_CAPABILITIES)
    st.markdown(
        f"""
        <div class="rt-panel">
          <h3 class="rt-panel-title">Agent Profile</h3>
          <div class="rt-panel-subtitle">Support-agent scenario for refund, email, and customer-data tools.</div>
          <div class="rt-label">Agent</div>
          <div class="rt-value">Customer Support Agent</div>
          <div class="rt-chip-row">
            <span class="rt-chip">Level 2 guarded gateway</span>
            {chips}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_generated_attacks_panel(state: dict[str, Any]) -> None:
    red_summary = state.get("red_summary")
    green_summary = state.get("green_summary")
    cards = []
    for attack in PRESENTER_ATTACKS:
        attack_id = attack["id"]
        red_status = _attack_status_label(red_summary, attack_id)
        green_status = _attack_status_label(green_summary, attack_id)
        assertion_count = _attack_assertion_count(state.get("attack_pack", []), attack_id)
        cards.append(
            _attack_card_html(
                attack_id=attack_id,
                name=str(attack["name"]),
                red_status=red_status,
                green_status=green_status,
                assertion_count=assertion_count,
                focus=bool(attack["focus"]),
            )
        )
    st.markdown(
        f"""
        <div class="rt-panel">
          <h3 class="rt-panel-title">Generated Attacks</h3>
          <div class="rt-panel-subtitle">RedTeamCI generates tests from the agent's tool surface.</div>
          <div class="rt-card-grid">{''.join(cards)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    attack_pack = state.get("attack_pack", [])
    if attack_pack:
        with st.expander("Show raw generated attack pack"):
            st.json(attack_pack)


def _render_red_gate_panel(state: dict[str, Any]) -> None:
    red_summary = state.get("red_summary") or {}
    github_status = _github_presenter_status()
    local_gate = _summary_counts(red_summary)
    refund_status = _attack_status_label(red_summary, "generated-refund-001")
    refund_tone = _status_tone(refund_status)
    st.markdown(
        f"""
        <div class="rt-panel">
          <h3 class="rt-panel-title">Red Gate</h3>
          <div class="rt-panel-subtitle">{_html(github_status)}. Release gate: Local proof active.</div>
          <div class="rt-status-card rt-card-{_html(_summary_tone(red_summary, expect_fail=True))}">
            <div class="rt-label">Local red summary</div>
            <div class="rt-value">{_html(local_gate)}</div>
          </div>
          <div style="height:10px"></div>
          <div class="rt-status-card rt-card-{_html(refund_tone)}">
            <div class="rt-label">Structured tool behavior</div>
            <div class="rt-value">generated-refund-001 - {_html(refund_status)}</div>
            <div class="rt-panel-subtitle">CI failed on structured tool behavior, not final text.</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _github_presenter_status() -> str:
    red_state = st.session_state.get("support_story_github_red")
    if isinstance(red_state, dict):
        conclusion = red_state.get("conclusion") or red_state.get("status")
        if conclusion:
            return f"GitHub CI: {conclusion}"
    return "GitHub CI: connected" if github_available()[0] else "GitHub CI: not connected"


def _render_trace_replay_panel(state: dict[str, Any]) -> None:
    red_trace = load_story_trace(ROOT, "red", "generated-refund-001")
    green_trace = load_story_trace(ROOT, "green", "generated-refund-001")
    proof = state.get("proof", {})

    red_lane = _trace_lane_html(
        "RED",
        red_trace,
        terminal_event="tool_call_executed",
        outcome="FAIL" if proof.get("red_refund_executed") else "-",
        tone="bad",
    )
    green_lane = _trace_lane_html(
        "GREEN",
        green_trace,
        terminal_event="tool_call_blocked",
        outcome="PASS" if proof.get("green_refund_blocked") else "-",
        tone="good",
    )
    st.markdown(
        f"""
        <div class="rt-panel">
          <h3 class="rt-panel-title">Trace Replay</h3>
          <div class="rt-panel-subtitle">
            The replayable trace shows the refund tool call before and after remediation.
          </div>
          <div class="rt-trace-grid">{red_lane}{green_lane}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if red_trace:
        with st.expander("Show red trace JSON"):
            st.json(red_trace)
    if green_trace:
        with st.expander("Show green trace JSON"):
            st.json(green_trace)


def _render_trace_lane(
    label: str,
    trace: dict[str, Any] | None,
    *,
    terminal_event: str,
    outcome: str,
) -> None:
    st.write(f"**{label}**")
    attempted = _first_tool_event(trace, "tool_call_attempted", "issue_refund")
    terminal = _first_tool_event(trace, terminal_event, "issue_refund")
    st.code(_trace_event_line(attempted, "tool_call_attempted issue_refund amount=500 approved=false"))
    if terminal_event == "tool_call_blocked":
        fallback = "tool_call_blocked issue_refund"
    else:
        fallback = "tool_call_executed issue_refund"
    st.code(_trace_event_line(terminal, fallback))
    if outcome == "PASS":
        st.success("PASS")
    elif outcome == "FAIL":
        st.error("FAIL")
    else:
        st.caption("-")


def _trace_lane_html(
    label: str,
    trace: dict[str, Any] | None,
    *,
    terminal_event: str,
    outcome: str,
    tone: str,
) -> str:
    attempted = _first_tool_event(trace, "tool_call_attempted", "issue_refund")
    terminal = _first_tool_event(trace, terminal_event, "issue_refund")
    attempted_line = _trace_event_line(
        attempted,
        f"tool_call_attempted issue_refund amount={PRESENTER_REFUND_AMOUNT} approved=false",
    )
    terminal_fallback = (
        "tool_call_blocked issue_refund"
        if terminal_event == "tool_call_blocked"
        else "tool_call_executed issue_refund"
    )
    terminal_line = _trace_event_line(terminal, terminal_fallback)
    outcome_class = "rt-outcome-good" if outcome == "PASS" else "rt-outcome-bad" if outcome == "FAIL" else ""
    event_class = "rt-event-good" if tone == "good" else "rt-event-bad"
    lane_class = "rt-lane-green" if tone == "good" else "rt-lane-red"
    return f"""
      <div class="rt-lane {lane_class}">
        <div class="rt-lane-title">{_html(label)}</div>
        <div class="rt-event">{_html(attempted_line)}</div>
        <div class="rt-event {event_class}">{_html(terminal_line)}</div>
        <div class="rt-outcome {outcome_class}">{_html(outcome)}</div>
      </div>
    """


def _first_tool_event(
    trace: dict[str, Any] | None,
    event_type: str,
    tool: str,
) -> dict[str, Any] | None:
    if not trace:
        return None
    for event in trace.get("events", []):
        if event.get("type") == event_type and event.get("tool") == tool:
            return event
    return None


def _trace_event_line(event: dict[str, Any] | None, fallback: str) -> str:
    if not event:
        return fallback
    event_type = str(event.get("type", "event"))
    tool = str(event.get("tool", "tool"))
    args = event.get("args", {})
    if isinstance(args, dict) and event_type == "tool_call_attempted":
        amount = args.get("amount", PRESENTER_REFUND_AMOUNT)
        approved = str(args.get("approved", False)).lower()
        return f"{event_type} {tool} amount={amount} approved={approved}"
    return f"{event_type} {tool}"


def _render_sentry_incident_panel(state: dict[str, Any]) -> None:
    context = build_sentry_dashboard_context(state)
    configured = bool(context["configured"])
    event_ids = context["event_ids"]
    event_text = ", ".join(event_ids) if event_ids else "No incident event recorded"
    st.markdown(
        f"""
        <div class="rt-panel">
          <h3 class="rt-panel-title">Sentry Incident</h3>
          <div class="rt-panel-subtitle">Sponsor proof without blocking the local release gate.</div>
          <div class="rt-status-card rt-card-{'good' if configured else 'muted'}">
            <div class="rt-label">Sentry</div>
            <div class="rt-value">{'optional, configured' if configured else 'optional, not configured'}</div>
          </div>
          <div style="height:10px"></div>
          <div class="rt-status-card rt-card-{'good' if event_ids else 'muted'}">
            <div class="rt-label">Red incident IDs</div>
            <div class="rt-value">{_html(event_text)}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if context["open_url"]:
        st.link_button("Open in Sentry", context["open_url"])
    with st.expander("Raw Sentry context"):
        st.json(
            {
                "configured": context["configured"],
                "event_ids": context["event_ids"],
                "tags": context["tags"],
                "fingerprint": context["fingerprint"],
                "artifacts": context["artifact_paths"],
            }
        )


def _render_claude_remediation_panel(root: Path, state: dict[str, Any]) -> None:
    remediation = state.get("remediation", {})
    if not isinstance(remediation, dict):
        remediation = {}
    summary_path = _root_path(root, remediation.get("summary_path"))
    summary = _load_json_object(summary_path) if summary_path else {}
    if not summary:
        story_root = root / SUPPORT_STORY_RELATIVE_ROOT
        summary_path = story_root / "patches" / "support_story_summary.json"
        summary = _load_json_object(summary_path) or {}

    diff_path = _root_path(root, summary.get("diff_path") or remediation.get("diff_path"))
    regression_path = _root_path(
        root,
        summary.get("regression_test_path") or remediation.get("regression_test_path"),
    )
    prompt_path = _root_path(root, remediation.get("prompt_path") or summary.get("prompt_path"))
    raw_output_path = _root_path(root, remediation.get("raw_output_path") or summary.get("raw_output_path"))
    proposal_path = _root_path(root, remediation.get("proposal_path") or summary.get("proposal_path"))
    validation_path = _root_path(
        root,
        remediation.get("validation_error_path") or summary.get("validation_error_path"),
    )

    status = _claude_status(summary, state)
    proposal_or_fixture = bool(
        proposal_path and proposal_path.exists()
        or summary.get("fixture")
        or summary.get("source") == "fixture"
    )
    tiles = [
        ("Prompt artifact", bool(prompt_path and prompt_path.exists())),
        ("Proposal / fixture artifact", proposal_or_fixture),
        ("Guardrail diff", bool(diff_path and diff_path.exists())),
        ("Generated regression", bool(regression_path and regression_path.exists())),
    ]
    st.markdown(
        f"""
        <div class="rt-panel">
          <h3 class="rt-panel-title">Claude Remediation</h3>
          <div class="rt-panel-subtitle">{_html(status['message'])}</div>
          <div class="rt-proof-grid">
            {''.join(_proof_tile_html(label, ok) for label, ok in tiles)}
          </div>
          <div style="height:12px"></div>
          <div class="rt-status-card rt-card-{_html(status['tone'])}">
            <div class="rt-label">Guardrail patch</div>
            <div class="rt-value">high-value refunds require approval</div>
          </div>
          <div style="height:10px"></div>
          <div class="rt-status-card rt-card-{'good' if regression_path and regression_path.exists() else 'muted'}">
            <div class="rt-label">Generated regression</div>
            <div class="rt-value">regression-generated-refund-001</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if prompt_path and prompt_path.exists():
        with st.expander("prompt"):
            st.code(prompt_path.read_text(encoding="utf-8"))
    if raw_output_path and raw_output_path.exists():
        with st.expander("raw output"):
            st.json(_load_json(raw_output_path) or {})
    if proposal_path and proposal_path.exists():
        with st.expander("parsed proposal JSON"):
            st.json(_load_json(proposal_path) or {})
    if validation_path and validation_path.exists():
        with st.expander("validation result"):
            st.json(_load_json(validation_path) or {})
    elif summary:
        with st.expander("validation result"):
            st.caption("Validation passed")
    if diff_path and diff_path.exists():
        with st.expander("full diff"):
            st.code(diff_path.read_text(encoding="utf-8"), language="diff")


def _render_claude_status_line(state: dict[str, Any], summary: dict[str, Any]) -> None:
    if summary.get("live_claude_proposal_applied"):
        st.success("Live Claude Code proposal applied")
        return
    if summary.get("fixture_fallback_used") or summary.get("source") == "fixture":
        st.warning("Deterministic fallback used")
        return
    if not state.get("claude_code_available"):
        st.caption("Claude Code unavailable")
        return
    if summary:
        st.error("Claude Code remediation did not apply")
    else:
        st.info("Run Claude remediation to create proof artifacts.")


def _claude_status(summary: dict[str, Any], state: dict[str, Any]) -> dict[str, str]:
    if summary.get("live_claude_proposal_applied"):
        return {"message": "Live Claude Code proposal applied", "tone": "good"}
    if summary.get("fixture_fallback_used") or summary.get("source") == "fixture":
        return {"message": "Deterministic fallback used", "tone": "warn"}
    if not state.get("claude_code_available"):
        return {"message": "Claude Code unavailable", "tone": "muted"}
    if summary:
        return {"message": "Claude Code remediation did not apply", "tone": "bad"}
    return {"message": "Run Claude remediation to create proof artifacts", "tone": "muted"}


def _render_proof_tile(column: Any, label: str, ok: bool) -> None:
    with column:
        if ok:
            st.success(label)
        else:
            st.caption(label)


def _render_presenter_green_proof_panel(
    state: dict[str, Any],
    readiness: dict[str, Any],
) -> None:
    proof = state.get("proof", {})
    green_summary = state.get("green_summary") or {}
    green_status = _summary_counts(green_summary)
    refund_status = _attack_status_label(green_summary, "generated-refund-001")
    regression_status = _attack_status_label(green_summary, "regression-generated-refund-001")
    certified = readiness["status"] == "ready"
    st.markdown(
        f"""
        <div class="rt-panel">
          <h3 class="rt-panel-title">Green Proof</h3>
          <div class="rt-panel-subtitle">The same refund was attempted again, then blocked before execution.</div>
          <div class="rt-status-grid">
            {_status_card_html('Green gate', green_status, _summary_tone(green_summary))}
            {_status_card_html('generated-refund-001', refund_status, _status_tone(refund_status))}
            {_status_card_html('regression-generated-refund-001', regression_status, _status_tone(regression_status))}
            {_status_card_html('Refund attempted', _yes_no(proof.get('green_refund_attempted')), 'good' if proof.get('green_refund_attempted') else 'muted')}
            {_status_card_html('Blocked before execution', _yes_no(proof.get('green_refund_blocked')), 'good' if proof.get('green_refund_blocked') else 'bad')}
          </div>
          <div class="rt-alert {'rt-alert-good' if certified else 'rt-alert-warn'}">
            {'AGENT CERTIFIED' if certified else 'AGENT NOT CERTIFIED'}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    with st.expander("Proof checklist"):
        for label, ok in readiness["checks"].items():
            if ok:
                st.success(label)
            else:
                st.error(label)


def _render_classic_presenter_mode() -> None:
    state = load_support_story_dashboard_state(ROOT)
    readiness = demo_readiness_status(state)

    _render_classic_presenter_header(state, readiness)
    _render_classic_presenter_actions()
    _render_classic_presenter_stepper()

    profile_col, attacks_col, red_col = st.columns([1.1, 1.3, 1.2])
    with profile_col:
        _render_classic_agent_profile_panel()
    with attacks_col:
        _render_classic_generated_attacks_panel(state)
    with red_col:
        _render_classic_red_gate_panel(state)

    _render_classic_trace_replay_panel(state)

    sentry_col, claude_col = st.columns([1.0, 1.6])
    with sentry_col:
        _render_classic_sentry_incident_panel(state)
    with claude_col:
        _render_classic_claude_remediation_panel(ROOT, state)

    _render_classic_green_proof_panel(state, readiness)


def _render_classic_presenter_header(
    state: dict[str, Any],
    readiness: dict[str, Any],
) -> None:
    st.title("RedTeamCI")
    st.subheader("Claude Code for AI-agent security gates")
    st.caption("pytest for AI-agent security")

    github_connected = github_available()[0]
    sentry_context = build_sentry_dashboard_context(state)
    status_cols = st.columns(5)
    status_cols[0].metric("Scenario", "Customer Support Agent")
    status_cols[1].metric("Proof", readiness["label"])
    status_cols[2].metric("Release gate", "Local proof active")
    status_cols[3].metric(
        "GitHub CI",
        "connected" if github_connected else "not connected",
    )
    status_cols[4].metric(
        "Sentry",
        "optional, configured" if sentry_context["configured"] else "optional, not configured",
    )

    if readiness["status"] == "ready":
        st.success("DEMO READY: red exploit, remediation artifact, generated regression, and green proof are complete.")
    elif readiness["status"] == "partial":
        st.warning("INCOMPLETE: proof artifacts exist, but the full certification chain is not complete yet.")
    else:
        st.info("NO RUN YET: generate demo proof to create the local certification chain.")


def _render_classic_presenter_actions() -> None:
    cols = st.columns(5)
    if cols[0].button("Load Latest Proof", key="classic_presenter_load", use_container_width=True):
        st.rerun()
    if cols[1].button(
        "Generate Demo Proof",
        key="classic_presenter_generate_demo_proof",
        use_container_width=True,
    ):
        with st.spinner("Generating deterministic demo proof..."):
            run_deterministic_demo_proof()
        st.rerun()
    if cols[2].button("Run Red Gate", key="classic_presenter_run_red", use_container_width=True):
        run_cli(["story", "support", "--step", "red"])
        st.rerun()

    strict_live = st.checkbox("Strict live Claude", key="classic_presenter_strict_live")
    if cols[3].button(
        "Run Live Claude",
        key="classic_presenter_run_live_claude",
        use_container_width=True,
    ):
        args = ["story", "support", "--step", "claude-code-remediate"]
        if strict_live:
            args.append("--strict-claude-code")
        else:
            args.append("--fixture-fallback")
        run_cli(args)
        st.rerun()
    if cols[4].button("Run Green Proof", key="classic_presenter_run_green", use_container_width=True):
        run_cli(["story", "support", "--step", "green"])
        st.rerun()


def _render_classic_presenter_stepper() -> None:
    labels = [
        "Agent Profile",
        "Generated Attacks",
        "Red Gate",
        "Trace Replay",
        "Sentry Incident",
        "Claude Remediation",
        "Green Proof",
    ]
    cols = st.columns(len(labels))
    for col, label in zip(cols, labels):
        col.caption(label)


def _render_classic_agent_profile_panel() -> None:
    with st.container(border=True):
        st.subheader("Agent Profile")
        st.metric("Agent", "Customer Support Agent")
        st.caption("Onboarding: Level 2 guarded gateway")
        st.write("Capabilities")
        st.write(" ".join(f"`{capability}`" for capability in PRESENTER_CAPABILITIES))


def _render_classic_generated_attacks_panel(state: dict[str, Any]) -> None:
    with st.container(border=True):
        st.subheader("Generated Attacks")
        st.caption("RedTeamCI generates tests from the agent's tool surface.")
        red_summary = state.get("red_summary")
        green_summary = state.get("green_summary")
        for attack in PRESENTER_ATTACKS:
            attack_id = attack["id"]
            red_status = _attack_status_label(red_summary, attack_id)
            green_status = _attack_status_label(green_summary, attack_id)
            assertion_count = _attack_assertion_count(state.get("attack_pack", []), attack_id)
            label = f"{attack_id} - {attack['name']}"
            if attack["focus"]:
                st.write(f"**{label}**")
            else:
                st.write(label)
            st.caption(
                f"source: generated | assertions: {assertion_count or '-'} | "
                f"red: {red_status} | green: {green_status}"
            )
        attack_pack = state.get("attack_pack", [])
        if attack_pack:
            with st.expander("Show raw generated attack pack"):
                st.json(attack_pack)


def _render_classic_red_gate_panel(state: dict[str, Any]) -> None:
    red_summary = state.get("red_summary") or {}
    with st.container(border=True):
        st.subheader("Red Gate")
        st.caption(_github_presenter_status())
        if not github_available()[0]:
            st.caption("Release gate: Local proof active")
        st.metric("Local red gate", _summary_counts(red_summary))
        refund_status = _attack_status_label(red_summary, "generated-refund-001")
        refund_line = f"generated-refund-001 - {refund_status}"
        if refund_status == "FAIL":
            st.error(refund_line)
        elif refund_status == "PASS":
            st.success(refund_line)
        else:
            st.caption(refund_line)
        st.caption("CI failed on structured tool behavior, not final text.")


def _render_classic_trace_replay_panel(state: dict[str, Any]) -> None:
    red_trace = load_story_trace(ROOT, "red", "generated-refund-001")
    green_trace = load_story_trace(ROOT, "green", "generated-refund-001")
    proof = state.get("proof", {})

    with st.container(border=True):
        st.subheader("Trace Replay")
        red_col, green_col = st.columns(2)
        with red_col:
            _render_trace_lane(
                "RED",
                red_trace,
                terminal_event="tool_call_executed",
                outcome="FAIL" if proof.get("red_refund_executed") else "-",
            )
        with green_col:
            _render_trace_lane(
                "GREEN",
                green_trace,
                terminal_event="tool_call_blocked",
                outcome="PASS" if proof.get("green_refund_blocked") else "-",
            )
        if red_trace:
            with st.expander("Show red trace JSON"):
                st.json(red_trace)
        if green_trace:
            with st.expander("Show green trace JSON"):
                st.json(green_trace)


def _render_classic_sentry_incident_panel(state: dict[str, Any]) -> None:
    context = build_sentry_dashboard_context(state)
    with st.container(border=True):
        st.subheader("Sentry Incident")
        if context["configured"]:
            st.success("Sentry: configured")
        else:
            st.caption("Sentry: optional, not configured")
        if context["event_ids"]:
            st.write("Event IDs")
            for event_id in context["event_ids"]:
                st.code(event_id)
        if context["open_url"]:
            st.link_button("Open in Sentry", context["open_url"])
        with st.expander("Raw Sentry context"):
            st.json(
                {
                    "configured": context["configured"],
                    "event_ids": context["event_ids"],
                    "tags": context["tags"],
                    "fingerprint": context["fingerprint"],
                    "artifacts": context["artifact_paths"],
                }
            )


def _render_classic_claude_remediation_panel(root: Path, state: dict[str, Any]) -> None:
    remediation = state.get("remediation", {})
    if not isinstance(remediation, dict):
        remediation = {}
    summary_path = _root_path(root, remediation.get("summary_path"))
    summary = _load_json_object(summary_path) if summary_path else {}
    if not summary:
        story_root = root / SUPPORT_STORY_RELATIVE_ROOT
        summary_path = story_root / "patches" / "support_story_summary.json"
        summary = _load_json_object(summary_path) or {}

    diff_path = _root_path(root, summary.get("diff_path") or remediation.get("diff_path"))
    regression_path = _root_path(
        root,
        summary.get("regression_test_path") or remediation.get("regression_test_path"),
    )
    prompt_path = _root_path(root, remediation.get("prompt_path") or summary.get("prompt_path"))
    raw_output_path = _root_path(root, remediation.get("raw_output_path") or summary.get("raw_output_path"))
    proposal_path = _root_path(root, remediation.get("proposal_path") or summary.get("proposal_path"))
    validation_path = _root_path(
        root,
        remediation.get("validation_error_path") or summary.get("validation_error_path"),
    )

    with st.container(border=True):
        st.subheader("Claude Remediation")
        _render_claude_status_line(state, summary)
        st.caption("Guardrail patch: high-value refunds require approval")
        st.caption("Generated regression: regression-generated-refund-001")

        tile_cols = st.columns(4)
        _render_proof_tile(tile_cols[0], "Prompt artifact", bool(prompt_path and prompt_path.exists()))
        proposal_or_fixture = bool(
            proposal_path and proposal_path.exists()
            or summary.get("fixture")
            or summary.get("source") == "fixture"
        )
        _render_proof_tile(tile_cols[1], "Proposal / fixture artifact", proposal_or_fixture)
        _render_proof_tile(tile_cols[2], "Guardrail diff", bool(diff_path and diff_path.exists()))
        _render_proof_tile(
            tile_cols[3],
            "Generated regression",
            bool(regression_path and regression_path.exists()),
        )

        if prompt_path and prompt_path.exists():
            with st.expander("prompt"):
                st.code(prompt_path.read_text(encoding="utf-8"))
        if raw_output_path and raw_output_path.exists():
            with st.expander("raw output"):
                st.json(_load_json(raw_output_path) or {})
        if proposal_path and proposal_path.exists():
            with st.expander("parsed proposal JSON"):
                st.json(_load_json(proposal_path) or {})
        if validation_path and validation_path.exists():
            with st.expander("validation result"):
                st.json(_load_json(validation_path) or {})
        elif summary:
            with st.expander("validation result"):
                st.caption("Validation passed")
        if diff_path and diff_path.exists():
            with st.expander("full diff"):
                st.code(diff_path.read_text(encoding="utf-8"), language="diff")


def _render_classic_green_proof_panel(
    state: dict[str, Any],
    readiness: dict[str, Any],
) -> None:
    proof = state.get("proof", {})
    green_summary = state.get("green_summary") or {}
    with st.container(border=True):
        st.subheader("Green Proof")
        cols = st.columns(5)
        cols[0].metric("Green gate", _summary_counts(green_summary))
        cols[1].metric(
            "generated-refund-001",
            _attack_status_label(green_summary, "generated-refund-001"),
        )
        cols[2].metric(
            "regression-generated-refund-001",
            _attack_status_label(green_summary, "regression-generated-refund-001"),
        )
        cols[3].metric("Refund attempted", _yes_no(proof.get("green_refund_attempted")))
        cols[4].metric("Blocked before execution", _yes_no(proof.get("green_refund_blocked")))
        if readiness["status"] == "ready":
            st.success("AGENT CERTIFIED")
        else:
            st.warning("AGENT NOT CERTIFIED")
        with st.expander("Proof checklist"):
            for label, ok in readiness["checks"].items():
                if ok:
                    st.success(label)
                else:
                    st.error(label)


def _render_support_story_mode() -> None:
    state = load_support_story_dashboard_state(ROOT)
    proof = state["proof"]
    certified = support_story_certified(proof)

    cols = st.columns(4)
    red = state["red_summary"] or {}
    green = state["green_summary"] or {}
    cols[0].metric("Red rehearsal", _summary_status(red, expected_failure=True))
    cols[1].metric("Green rehearsal", _summary_status(green))
    cols[2].metric("Proof", "AGENT CERTIFIED" if certified else "NOT CERTIFIED")
    cols[3].metric(
        "Regression",
        "PASS" if proof.get("regression_loaded_and_passed") else "-",
    )

    if certified:
        st.success(
            "AGENT CERTIFIED: unsafe refund executed in red, blocked before "
            "execution in green, and locked as a regression."
        )
    elif state["available"]:
        st.warning("Support story artifacts found, but final proof is not certified yet.")
    else:
        st.info("Run the support story to create replayable red/green evidence.")

    first_row = st.columns(4)
    if first_row[0].button("Run Full Local Story", use_container_width=True):
        run_cli(["story", "support", "--step", "full"])
    if first_row[1].button("Load Latest Demo State", use_container_width=True):
        st.rerun()
    if first_row[2].button("Profile Agent", use_container_width=True):
        run_cli(["story", "support", "--step", "prepare"])
    if first_row[3].button("Generate Attack Plan", use_container_width=True):
        run_cli(["story", "support", "--step", "plan"])

    _render_support_story_github_panel()

    second_row = st.columns(4)
    if second_row[0].button("Run Local Red Rehearsal", use_container_width=True):
        run_cli(["story", "support", "--step", "red"])
    if second_row[1].button("Replay Refund Trace", use_container_width=True):
        if not load_story_trace(ROOT, "red", "generated-refund-001"):
            run_cli(["story", "support", "--step", "red"])
        run_cli(
            [
                "story",
                "support",
                "--step",
                "trace",
                "--phase",
                "red",
                "--attack",
                "generated-refund-001",
            ]
        )
    if second_row[2].button("Run Claude Code Remediation", use_container_width=True):
        run_cli(["story", "support", "--step", "claude-code-remediate"])
    if second_row[3].button("Use Deterministic Fallback", use_container_width=True):
        run_cli(["story", "support", "--step", "remediate"])

    third_row = st.columns(4)
    if third_row[0].button("Run Green Proof", use_container_width=True):
        run_cli(["story", "support", "--step", "green"])

    left, middle, right = st.columns([1.1, 1.4, 1.5])
    with left:
        st.subheader("Final Proof")
        _render_proof_rows(proof)
        st.subheader("Observability")
        _render_sentry_observability(state)
        st.subheader("Artifacts")
        if state["artifacts"]:
            for artifact in state["artifacts"]:
                st.caption(f"{artifact['label']}: {artifact['path']}")
        else:
            st.caption("No support-story artifacts yet.")

    with middle:
        st.subheader("Generated Tests")
        _render_support_attack_cards(state["attack_pack"])
        st.subheader("Remediation")
        _render_support_story_remediation(ROOT, state)

    with right:
        st.subheader("Flight Recorder")
        phase = st.radio("Story phase", ["red", "green"], horizontal=True)
        attack_id = st.selectbox("Story attack", SUPPORT_STORY_ATTACKS, index=0)
        trace = load_story_trace(ROOT, phase, attack_id)
        if not trace:
            st.info("Run the selected phase to create this trace.")
        else:
            for event in trace.get("events", []):
                label = event.get("title", event.get("type", "event"))
                severity = event.get("severity", "info")
                with st.expander(f"{severity.upper()} - {label}"):
                    st.json(event)

    st.caption(
        "GitHub status is live CI. Trace replay uses local story artifacts for "
        "demo reliability; artifact download is optional."
    )


def _render_support_story_github_panel() -> None:
    st.subheader("Real GitHub CI")
    available, message = github_available()
    if available:
        st.caption(message)
    else:
        st.warning(message)
        st.caption(
            "Set GITHUB_TOKEN with Actions: write and Contents: read, plus "
            "GITHUB_REPOSITORY=saigudisa6/berkai and optional GITHUB_BRANCH=main."
        )

    cols = st.columns(2)
    if cols[0].button("Run GitHub CI Red", disabled=not available, use_container_width=True):
        _run_github_story_mode("red")
    if cols[1].button("Run GitHub CI Green", disabled=not available, use_container_width=True):
        _run_github_story_mode("green")

    red_state = st.session_state.get("support_story_github_red")
    green_state = st.session_state.get("support_story_github_green")
    _render_github_run_status("red", red_state)
    _render_github_run_status("green", green_state)


def _run_github_story_mode(mode: str) -> None:
    state_key = f"support_story_github_{mode}"
    try:
        with st.spinner(f"Dispatching support-story {mode} workflow..."):
            correlation_id = trigger_support_story_workflow(mode)
            run = wait_for_workflow_run(
                configured_workflow_file(),
                configured_branch(),
                correlation_id,
                timeout_seconds=60,
                interval_seconds=5,
            )
            if run is None:
                st.session_state[state_key] = {
                    "correlation_id": correlation_id,
                    "status": "queued",
                    "conclusion": None,
                    "url": "",
                    "artifacts": [],
                }
                st.warning(f"Workflow dispatched with correlation id {correlation_id}.")
                return
            completed = poll_workflow_run(run.id, timeout_seconds=180, interval_seconds=5)
            artifacts = list_artifacts(completed.id)
            st.session_state[state_key] = {
                "correlation_id": correlation_id,
                "status": completed.status,
                "conclusion": completed.conclusion,
                "url": workflow_run_url(completed),
                "artifacts": [artifact.get("name", "") for artifact in artifacts],
            }
    except GitHubActionsError as exc:
        st.session_state[state_key] = {"error": str(exc)}
        st.error(str(exc))


def _render_github_run_status(label: str, state: dict[str, Any] | None) -> None:
    if not state:
        return
    if state.get("error"):
        st.error(f"GitHub {label}: {state['error']}")
        return
    conclusion = state.get("conclusion") or state.get("status") or "unknown"
    correlation_id = state.get("correlation_id", "-")
    url = state.get("url", "")
    st.write(f"GitHub {label}: {conclusion} ({correlation_id})")
    if url:
        st.link_button(f"Open GitHub {label} run", url)
    artifacts = [artifact for artifact in state.get("artifacts", []) if artifact]
    if artifacts:
        st.caption("Artifacts: " + ", ".join(artifacts))


def _render_support_attack_cards(attack_pack: list[dict[str, Any]]) -> None:
    if not attack_pack:
        st.info("Generate tests to populate the support attack pack.")
        return
    for attack in attack_pack:
        attack_id = str(attack.get("id", ""))
        name = str(attack.get("name", attack_id))
        task = str(attack.get("task", ""))
        with st.expander(f"{attack_id} - {name}", expanded=attack_id == "generated-refund-001"):
            st.caption(task)
            st.json(attack.get("assertions", []))


def _render_support_story_remediation(root: Path, state: dict[str, Any]) -> None:
    story_root = root / SUPPORT_STORY_RELATIVE_ROOT
    remediation = state.get("remediation", {})
    if not isinstance(remediation, dict):
        remediation = {}
    summary_path = _root_path(root, remediation.get("summary_path")) or (
        story_root / "patches" / "support_story_summary.json"
    )
    diff_path = _root_path(root, remediation.get("diff_path")) or (
        story_root / "patches" / "support_story.diff"
    )
    regression_path = _root_path(root, remediation.get("regression_test_path")) or (
        story_root / "regressions" / "generated_attacks.json"
    )
    summary = _load_json_object(summary_path)
    diff = _load_text(diff_path)
    regression = _load_json(regression_path)
    if not summary and not diff and not regression:
        st.info("Run remediation to populate Claude Code artifacts.")
        return

    st.caption(
        "Claude Code available: "
        + ("yes" if state.get("claude_code_available") else "no")
    )
    if summary:
        source = str(summary.get("source", remediation.get("source", "fixture")))
        live = bool(summary.get("live_claude_proposal_applied"))
        fallback = bool(summary.get("fixture_fallback_used"))
        if live:
            st.success("Live Claude Code proposal applied")
        elif fallback or source == "fixture":
            st.warning("Deterministic fixture fallback used")
        else:
            st.error("Claude Code remediation did not apply")
        st.caption(f"Source: {source}")
        st.caption(f"Regression: {summary.get('regression_test', {}).get('id', '-')}")
        changed = summary.get("changed_files", [])
        if isinstance(changed, list) and changed:
            st.caption("Changed files: " + ", ".join(str(item) for item in changed))

    _render_text_artifact("Prompt artifact", root, remediation.get("prompt_path"))
    _render_json_artifact("Raw output artifact", root, remediation.get("raw_output_path"))
    _render_json_artifact("Parsed proposal JSON", root, remediation.get("proposal_path"))
    _render_json_artifact(
        "Validation result",
        root,
        remediation.get("validation_error_path"),
        empty_message="Validation passed",
    )
    if diff:
        with st.expander("Diff", expanded=True):
            st.code(diff, language="diff")
    if regression:
        with st.expander("Generated regression"):
            st.json(regression)


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


def _render_text_artifact(label: str, root: Path, value: Any) -> None:
    path = _root_path(root, value)
    if not path or not path.exists():
        return
    text = _load_text(path)
    if text:
        with st.expander(label):
            st.caption(_display_path(path, root))
            st.code(text)


def _render_json_artifact(
    label: str,
    root: Path,
    value: Any,
    *,
    empty_message: str | None = None,
) -> None:
    path = _root_path(root, value)
    if not path or not path.exists():
        if empty_message:
            st.caption(empty_message)
        return
    data = _load_json(path)
    with st.expander(label):
        st.caption(_display_path(path, root))
        if data is None:
            st.code(_load_text(path) or "")
        else:
            st.json(data)


def _render_artifacts_tab(root: Path) -> None:
    st.subheader("Artifacts")
    support_artifacts = _support_story_artifacts(root)
    evidence_artifacts = collect_evidence_artifacts(root)
    if not support_artifacts and not evidence_artifacts:
        st.info("Run a story or suite to populate artifacts.")
        return
    if support_artifacts:
        st.write("Support story")
        for artifact in support_artifacts:
            st.caption(f"{artifact['label']}: {artifact['path']}")
    if evidence_artifacts:
        st.write("General suite")
        for artifact in evidence_artifacts:
            st.caption(f"{artifact['label']}: {artifact['path']}")


def _render_generated_plan_panel(state: dict[str, Any]) -> None:
    st.subheader("Generated Agent Plan")
    if not state["available"]:
        st.info("No generated plan artifacts found.")
        return

    agent = state["agent"]
    onboarding = state["onboarding"]
    cols = st.columns(3)
    cols[0].metric("Agent", agent["name"])
    cols[1].metric("Onboarding", onboarding["label"])
    cols[2].metric("Attack pack", state["generated_attack_pack"] or "-")

    if onboarding["tone"] == "success":
        st.success(onboarding["message"])
    elif onboarding["tone"] == "warning":
        st.warning(onboarding["message"])
    else:
        st.info(onboarding["message"])

    left, middle, right = st.columns([1.2, 1.3, 1.5])
    with left:
        st.write("Detected capabilities")
        capabilities = state["capabilities"]
        if capabilities:
            for capability in capabilities:
                status = "yes" if capability["enabled"] else "no"
                st.caption(f"{status} - {capability['label']}")
        else:
            st.caption("No capability profile found.")

    with middle:
        st.write("Generated test categories")
        categories = state["categories"]
        if categories:
            st.table(
                [
                    {
                        "category": category["name"],
                        "count": category["count"],
                        "attack_ids": ", ".join(category["attack_ids"]),
                    }
                    for category in categories
                ]
            )
        else:
            st.caption("No generated categories found.")
        st.write("Generated attack IDs")
        st.code("\n".join(state["attack_ids"]) or "No generated attacks found.")

    with right:
        st.write("Plan artifacts")
        for artifact in state["plan_artifacts"]:
            st.caption(f"{artifact['label']}: {artifact['path']}")
        evidence_artifacts = state["evidence_artifacts"]
        if evidence_artifacts:
            st.write("Run evidence")
            for artifact in evidence_artifacts:
                st.caption(f"{artifact['label']}: {artifact['path']}")

    markdown = state.get("attack_plan_markdown")
    if markdown:
        with st.expander("Attack plan markdown"):
            st.markdown(markdown)


def load_generated_plan_panel(root: Path = ROOT) -> dict[str, Any]:
    root = Path(root)
    redteamci_dir = root / REDTEAMCI_OUTPUT_DIR
    paths = {
        "agent_profile": redteamci_dir / AGENT_PROFILE_FILE,
        "capability_profile": redteamci_dir / CAPABILITY_PROFILE_FILE,
        "attack_plan": redteamci_dir / ATTACK_PLAN_FILE,
        "attack_plan_markdown": redteamci_dir / ATTACK_PLAN_MARKDOWN_FILE,
    }
    agent_profile = _load_json_object(paths["agent_profile"])
    capability_profile = _load_json_object(paths["capability_profile"])
    attack_plan = _load_json_object(paths["attack_plan"])
    attack_plan_markdown = _load_text(paths["attack_plan_markdown"])

    capability_map = _capability_map(capability_profile)
    onboarding_level = _onboarding_level(agent_profile, capability_profile, attack_plan)
    uses_guarded_gateway = bool(capability_map.get("uses_guarded_gateway"))
    generated_attack_pack = _generated_attack_pack_path(root, attack_plan)
    generated_attacks = _load_generated_attacks(generated_attack_pack)

    available = any(
        value is not None
        for value in [agent_profile, capability_profile, attack_plan, attack_plan_markdown]
    )
    return {
        "available": available,
        "agent": _agent_summary(agent_profile, capability_profile, attack_plan),
        "onboarding": onboarding_level_notice(onboarding_level, uses_guarded_gateway),
        "capabilities": _capability_rows(capability_map),
        "categories": _category_rows(attack_plan, generated_attacks),
        "attack_ids": _generated_attack_ids(attack_plan, generated_attacks),
        "generated_attack_pack": _display_path(generated_attack_pack, root)
        if generated_attack_pack
        else "",
        "generated_attack_pack_exists": bool(generated_attack_pack and generated_attack_pack.exists()),
        "plan_artifacts": _existing_plan_artifacts(paths, root),
        "evidence_artifacts": collect_evidence_artifacts(root),
        "attack_plan_markdown": attack_plan_markdown,
    }


def load_support_story_dashboard_state(root: Path = ROOT) -> dict[str, Any]:
    root = Path(root)
    story_root = root / SUPPORT_STORY_RELATIVE_ROOT
    remediation_summary_path = story_root / "patches" / "support_story_summary.json"
    generated_regression_path = story_root / "regressions" / "generated_attacks.json"
    red_summary = _load_json_object(story_root / "red" / "summary.json")
    green_summary = _load_json_object(story_root / "green" / "summary.json")
    state = _load_json_object(story_root / "state.json") or {}
    proof = state.get("proof") if isinstance(state.get("proof"), dict) else {}
    remediation = state.get("remediation") if isinstance(state.get("remediation"), dict) else {}
    attack_pack = _load_json(story_root / "plan" / "generated_support_attacks.json")
    if not isinstance(attack_pack, list):
        attack_pack = []
    artifacts = _support_story_artifacts(root)
    red_sentry_event_ids = _sentry_event_ids(red_summary) or _run_sentry_event_ids(
        state,
        "red",
    )
    red_sentry_events = _sentry_events(red_summary) or _run_sentry_events(state, "red")
    green_verification_ids = _sentry_ids(green_summary, "sentry_verification_event_ids") or _run_sentry_ids(
        state,
        "green",
        "sentry_verification_event_ids",
    )
    green_verification_events = _sentry_events_for_key(
        green_summary,
        "sentry_verification_events",
    ) or _run_sentry_events_for_key(state, "green", "sentry_verification_events")
    executable = ClaudeCodeRemediator().executable()
    return {
        "available": story_root.exists(),
        "state": state,
        "proof": proof,
        "red_summary": red_summary,
        "green_summary": green_summary,
        "remediation": remediation,
        "claude_code_available": bool(executable),
        "claude_code_executable": executable or "",
        "red_sentry_event_ids": red_sentry_event_ids,
        "red_sentry_events": red_sentry_events,
        "green_sentry_verification_event_ids": green_verification_ids,
        "green_sentry_verification_events": green_verification_events,
        "attack_pack": attack_pack,
        "artifacts": artifacts,
        "remediation_summary_exists": remediation_summary_path.exists(),
        "generated_regression_exists": generated_regression_path.exists(),
    }


def support_story_certified(proof: dict[str, Any]) -> bool:
    return all(
        [
            proof.get("red_refund_executed"),
            proof.get("green_refund_attempted"),
            proof.get("green_refund_blocked"),
            proof.get("green_blocked_before_execution_assertion_passed"),
            proof.get("regression_loaded_and_passed"),
            int(proof.get("green_failed", 1)) == 0,
        ]
    )


def demo_readiness_status(state: dict[str, Any]) -> dict[str, Any]:
    proof = state.get("proof", {})
    if not isinstance(proof, dict):
        proof = {}
    checks = {
        "red refund executed": bool(proof.get("red_refund_executed")),
        "green refund attempted": bool(proof.get("green_refund_attempted")),
        "green refund blocked": bool(proof.get("green_refund_blocked")),
        "blocked-before-execution assertion passed": bool(
            proof.get("green_blocked_before_execution_assertion_passed")
        ),
        "regression loaded and passed": bool(proof.get("regression_loaded_and_passed")),
        "green failures = 0": _green_failed_zero(proof),
        "remediation summary exists": bool(state.get("remediation_summary_exists")),
        "generated regression exists": bool(state.get("generated_regression_exists")),
    }
    if all(checks.values()):
        return {
            "status": "ready",
            "label": "DEMO READY",
            "ready": True,
            "checks": checks,
        }
    if _has_support_story_evidence(state, checks):
        return {
            "status": "partial",
            "label": "INCOMPLETE",
            "ready": False,
            "checks": checks,
        }
    return {
        "status": "empty",
        "label": "NO RUN YET",
        "ready": False,
        "checks": checks,
    }


def _has_support_story_evidence(
    state: dict[str, Any],
    checks: dict[str, bool],
) -> bool:
    return any(
        [
            state.get("available"),
            state.get("red_summary"),
            state.get("green_summary"),
            state.get("remediation"),
            state.get("attack_pack"),
            any(checks.values()),
        ]
    )


def _green_failed_zero(proof: dict[str, Any]) -> bool:
    value = proof.get("green_failed", 1)
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 0
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip()) == 0
    return False


def onboarding_level_notice(level: int, uses_guarded_gateway: bool = False) -> dict[str, str]:
    if level >= 2 or uses_guarded_gateway:
        return {
            "label": "Level 2 guarded gateway",
            "tone": "success",
            "message": "Level 2 guarded tool gateway; RedTeamCI can prove blocked-before-execution for guarded tools.",
        }
    if level == 1:
        return {
            "label": "Level 1 trace-reporting agent",
            "tone": "warning",
            "message": LEVEL_1_WARNING,
        }
    return {
        "label": "Level 0 output-only agent",
        "tone": "warning",
        "message": "Level 0 output-only agent; RedTeamCI can report output failures but cannot verify tool blocking.",
    }


def collect_evidence_artifacts(root: Path = ROOT) -> list[dict[str, str]]:
    root = Path(root)
    artifacts: list[tuple[str, Path]] = [
        ("Before summary", root / "before.json"),
        ("After summary", root / "after.json"),
        ("Report", root / "redteamci_report.md"),
    ]

    traces_root = root / "traces"
    if traces_root.exists():
        for path in sorted(traces_root.glob("**/*.json")):
            artifacts.append(("Trace", path))

    patches_root = root / "patches"
    if patches_root.exists():
        patch_artifacts = [
            path
            for path in sorted(patches_root.iterdir())
            if path.is_file() and path.suffix in {".diff", ".json", ".md", ".txt"}
        ]
        for path in patch_artifacts[-8:]:
            artifacts.append(("Claude artifact", path))

    return [
        {"label": label, "path": _display_path(path, root)}
        for label, path in artifacts
        if path.exists()
    ]


def _render_sentry_observability(state: dict[str, Any]) -> None:
    context = build_sentry_dashboard_context(state)
    status = "configured" if context["configured"] else "missing"
    st.caption(f"Sentry DSN: {status}")
    if context["environment"]:
        st.caption(f"Environment: {context['environment']}")
    if context["release"]:
        st.caption(f"Release: {context['release']}")

    event_ids = context["event_ids"]
    if not event_ids:
        st.caption(
            "No Sentry events recorded. Set SENTRY_DSN and install integration "
            "dependencies to enable Sentry."
        )
        return

    red_ids = _string_list(state.get("red_sentry_event_ids"))
    verification_ids = _string_list(state.get("green_sentry_verification_event_ids"))
    if red_ids:
        st.caption("Red incident event IDs")
        for event_id in red_ids:
            st.code(event_id)
    if verification_ids:
        st.caption("Remediation verification event IDs")
        for event_id in verification_ids:
            st.code(event_id)
    if not red_ids and not verification_ids:
        for event_id in event_ids:
            st.code(event_id)
    if context["open_url"]:
        st.link_button("Open in Sentry", context["open_url"])

    with st.expander("Sentry proof context", expanded=True):
        st.json(
            {
                "tags": context["tags"],
                "fingerprint": context["fingerprint"],
                "artifacts": context["artifact_paths"],
            }
        )


def build_sentry_dashboard_context(
    state: dict[str, Any],
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    if environ is None:
        environ = dict(os.environ)
    events = state.get("red_sentry_events", [])
    if not isinstance(events, list):
        events = []
    events = [event for event in events if isinstance(event, dict)]
    verification_events = state.get("green_sentry_verification_events", [])
    if not isinstance(verification_events, list):
        verification_events = []
    verification_events = [
        event for event in verification_events if isinstance(event, dict)
    ]
    event_ids = _dedupe(
        [
            *_string_list(state.get("red_sentry_event_ids")),
            *_string_list(state.get("green_sentry_verification_event_ids")),
            *[
                str(event.get("event_id"))
                for event in events
                if event.get("event_id")
            ],
            *[
                str(event.get("event_id"))
                for event in verification_events
                if event.get("event_id")
            ],
        ]
    )
    primary = events[0] if events else {}
    tags = primary.get("tags", {}) if isinstance(primary.get("tags"), dict) else {}
    extra = primary.get("extra", {}) if isinstance(primary.get("extra"), dict) else {}
    fingerprint = (
        primary.get("fingerprint", [])
        if isinstance(primary.get("fingerprint"), list)
        else []
    )
    return {
        "configured": bool(environ.get("SENTRY_DSN")),
        "environment": environ.get("SENTRY_ENVIRONMENT", ""),
        "release": environ.get("SENTRY_RELEASE", ""),
        "event_ids": event_ids,
        "events": events,
        "verification_events": verification_events,
        "tags": tags,
        "fingerprint": fingerprint,
        "artifact_paths": _sentry_artifact_paths(extra),
        "open_url": _sentry_search_url(event_ids, environ),
    }


def _html(value: Any) -> str:
    return escape(str(value), quote=True)


def _readiness_tone(readiness: dict[str, Any]) -> str:
    status = readiness.get("status")
    if status == "ready":
        return "good"
    if status == "partial":
        return "warn"
    return "muted"


def _status_tone(status: str) -> str:
    normalized = str(status).upper()
    if normalized == "PASS":
        return "good"
    if normalized == "FAIL":
        return "bad"
    return "muted"


def _summary_tone(
    summary: dict[str, Any] | None,
    *,
    expect_fail: bool = False,
) -> str:
    if not summary:
        return "muted"
    failed = int(summary.get("failed", 0) or 0)
    passed = int(summary.get("passed", 0) or 0)
    if expect_fail:
        return "bad" if failed else "warn"
    if failed:
        return "bad"
    if passed:
        return "good"
    return "muted"


def _status_card_html(label: str, value: Any, tone: str) -> str:
    tone = tone if tone in {"good", "bad", "warn", "muted"} else "muted"
    return f"""
      <div class="rt-status-card rt-card-{_html(tone)}">
        <div class="rt-label">{_html(label)}</div>
        <div class="rt-value">{_html(value)}</div>
      </div>
    """


def _proof_tile_html(label: str, ok: bool) -> str:
    tone = "good" if ok else "muted"
    state = "ready" if ok else "pending"
    return f"""
      <div class="rt-proof-tile rt-card-{tone}">
        <strong>{_html(label)}</strong>
        <span class="rt-muted">{_html(state)}</span>
      </div>
    """


def _render_presenter_alert(tone: str, message: str) -> None:
    tone = tone if tone in {"good", "warn", "muted"} else "muted"
    st.markdown(
        f'<div class="rt-alert rt-alert-{_html(tone)}">{_html(message)}</div>',
        unsafe_allow_html=True,
    )


def _attack_card_html(
    *,
    attack_id: str,
    name: str,
    red_status: str,
    green_status: str,
    assertion_count: int,
    focus: bool,
) -> str:
    tone = "bad" if red_status == "FAIL" else "good" if green_status == "PASS" else "muted"
    focus_label = '<span class="rt-pill rt-pill-warn">script focus</span>' if focus else ""
    return f"""
      <div class="rt-attack-card rt-card-{_html(tone)}">
        <div class="rt-attack-id">{_html(attack_id)}</div>
        <div class="rt-attack-name">{_html(name)}</div>
        <div class="rt-mini-row">
          <span class="rt-pill">generated</span>
          <span class="rt-pill">assertions: {_html(assertion_count or '-')}</span>
          <span class="rt-pill {_pill_class(red_status)}">red: {_html(red_status)}</span>
          <span class="rt-pill {_pill_class(green_status)}">green: {_html(green_status)}</span>
          {focus_label}
        </div>
      </div>
    """


def _pill_class(status: str) -> str:
    if status == "PASS":
        return "rt-pill-good"
    if status == "FAIL":
        return "rt-pill-bad"
    return ""


def _sentry_event_ids(summary: dict[str, Any] | None) -> list[str]:
    return _sentry_ids(summary, "sentry_event_ids")


def _sentry_ids(summary: dict[str, Any] | None, key: str) -> list[str]:
    if not summary:
        return []
    integrations = summary.get("integrations", {})
    if not isinstance(integrations, dict):
        return []
    event_ids = integrations.get(key, [])
    if not isinstance(event_ids, list):
        return []
    return [str(event_id) for event_id in event_ids if event_id]


def _sentry_events(summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    return _sentry_events_for_key(summary, "sentry_events")


def _sentry_events_for_key(summary: dict[str, Any] | None, key: str) -> list[dict[str, Any]]:
    if not summary:
        return []
    integrations = summary.get("integrations", {})
    if not isinstance(integrations, dict):
        return []
    events = integrations.get(key, [])
    if not isinstance(events, list):
        return []
    return [event for event in events if isinstance(event, dict)]


def _run_sentry_event_ids(state: dict[str, Any], phase: str) -> list[str]:
    return _run_sentry_ids(state, phase, "sentry_event_ids")


def _run_sentry_ids(state: dict[str, Any], phase: str, key: str) -> list[str]:
    run = state.get(phase, {})
    if not isinstance(run, dict):
        return []
    return _string_list(run.get(key))


def _run_sentry_events(state: dict[str, Any], phase: str) -> list[dict[str, Any]]:
    return _run_sentry_events_for_key(state, phase, "sentry_events")


def _run_sentry_events_for_key(
    state: dict[str, Any],
    phase: str,
    key: str,
) -> list[dict[str, Any]]:
    run = state.get(phase, {})
    if not isinstance(run, dict):
        return []
    events = run.get(key, [])
    if not isinstance(events, list):
        return []
    return [event for event in events if isinstance(event, dict)]


def _sentry_artifact_paths(extra: dict[str, Any]) -> dict[str, Any]:
    return {
        "trace_path": extra.get("trace_path", ""),
        "summary_path": extra.get("summary_path", ""),
        "remediation_artifact_paths": extra.get("remediation_artifact_paths", []),
        "regression_artifact_paths": extra.get("regression_artifact_paths", []),
    }


def _sentry_search_url(event_ids: list[str], environ: dict[str, str]) -> str:
    if not event_ids:
        return ""
    base_url = environ.get("SENTRY_BASE_URL", "").rstrip("/")
    organization = environ.get("SENTRY_ORG", "")
    project = environ.get("SENTRY_PROJECT", "")
    if not base_url or not organization or not project:
        return ""
    query = f"event.id:{event_ids[0]}"
    return (
        f"{base_url}/organizations/{quote(organization)}/issues/"
        f"?project={quote(project)}&query={quote(query)}"
    )


def load_story_trace(root: Path, phase: str, attack_id: str) -> dict[str, Any] | None:
    traces_root = Path(root) / SUPPORT_STORY_RELATIVE_ROOT / phase / "traces"
    if not traces_root.exists():
        return None
    run_dirs = sorted(
        [path for path in traces_root.glob("run_*") if path.is_dir()],
        key=lambda path: path.stat().st_mtime,
    )
    if not run_dirs:
        return None
    trace = _load_json(run_dirs[-1] / f"{attack_id}.json")
    return trace if isinstance(trace, dict) else None


def _summary_status(summary: dict[str, Any], *, expected_failure: bool = False) -> str:
    if not summary:
        return "-"
    failed = int(summary.get("failed", 0))
    passed = int(summary.get("passed", 0))
    if expected_failure:
        return f"{failed} findings" if failed else "no findings"
    return "PASS" if failed == 0 and passed else "FAIL"


def _summary_counts(summary: dict[str, Any] | None) -> str:
    if not summary:
        return "-"
    failed = int(summary.get("failed", 0) or 0)
    passed = int(summary.get("passed", 0) or 0)
    return f"{failed} failed, {passed} passed"


def _attack_status_label(summary: dict[str, Any] | None, attack_id: str) -> str:
    attack = _attack_by_id(summary, attack_id)
    if attack and attack.get("status"):
        return str(attack["status"])
    return "-"


def _attack_assertion_count(attack_pack: Any, attack_id: str) -> int:
    if not isinstance(attack_pack, list):
        return 0
    for attack in attack_pack:
        if not isinstance(attack, dict) or attack.get("id") != attack_id:
            continue
        assertions = attack.get("assertions", [])
        return len(assertions) if isinstance(assertions, list) else 0
    return 0


def _yes_no(value: Any) -> str:
    return "yes" if bool(value) else "no"


def _render_proof_rows(proof: dict[str, Any]) -> None:
    rows = [
        ("red refund executed", proof.get("red_refund_executed")),
        ("green refund attempted", proof.get("green_refund_attempted")),
        ("green refund blocked", proof.get("green_refund_blocked")),
        (
            "blocked-before-execution assertion",
            proof.get("green_blocked_before_execution_assertion_passed"),
        ),
        ("regression loaded and passed", proof.get("regression_loaded_and_passed")),
        ("green failures", int(proof.get("green_failed", 1)) == 0),
    ]
    if not proof:
        st.caption("No final proof yet.")
        return
    for label, ok in rows:
        if ok:
            st.success(label)
        else:
            st.error(label)


def _support_story_artifacts(root: Path) -> list[dict[str, str]]:
    story_root = root / SUPPORT_STORY_RELATIVE_ROOT
    artifacts: list[tuple[str, Path]] = [
        ("State", story_root / "state.json"),
        ("Attack plan", story_root / "plan" / "attack_plan.json"),
        ("Attack pack", story_root / "plan" / "generated_support_attacks.json"),
        ("Red summary", story_root / "red" / "summary.json"),
        ("Green summary", story_root / "green" / "summary.json"),
        ("Patch summary", story_root / "patches" / "support_story_summary.json"),
        ("Patch diff", story_root / "patches" / "support_story.diff"),
        ("Claude prompt", story_root / "patches" / "support_story_claude_proposal_prompt.txt"),
        ("Claude raw output", story_root / "patches" / "support_story_claude_proposal_raw.json"),
        ("Claude proposal", story_root / "patches" / "support_story_claude_proposal.json"),
        (
            "Claude validation",
            story_root / "patches" / "support_story_claude_proposal_validation_errors.json",
        ),
        ("Regression", story_root / "regressions" / "generated_attacks.json"),
    ]
    for phase in ["red", "green"]:
        traces = story_root / phase / "traces"
        if traces.exists():
            for path in sorted(traces.glob("run_*/*.json"))[-6:]:
                artifacts.append((f"{phase.title()} trace", path))
    return [
        {"label": label, "path": _display_path(path, root)}
        for label, path in artifacts
        if path.exists()
    ]


def _agent_summary(
    agent_profile: dict[str, Any] | None,
    capability_profile: dict[str, Any] | None,
    attack_plan: dict[str, Any] | None,
) -> dict[str, str]:
    agent = agent_profile.get("agent", {}) if agent_profile else {}
    if not isinstance(agent, dict):
        agent = {}
    agent_id = _first_text(
        agent.get("id"),
        capability_profile.get("agent_id") if capability_profile else None,
        attack_plan.get("agent_id") if attack_plan else None,
        "agent",
    )
    return {
        "id": agent_id,
        "name": _first_text(agent.get("name"), agent_id),
        "adapter_kind": _first_text(
            agent.get("adapter_kind"),
            capability_profile.get("adapter_kind") if capability_profile else None,
            "unknown",
        ),
    }


def _onboarding_level(
    agent_profile: dict[str, Any] | None,
    capability_profile: dict[str, Any] | None,
    attack_plan: dict[str, Any] | None,
) -> int:
    agent = agent_profile.get("agent", {}) if agent_profile else {}
    if not isinstance(agent, dict):
        agent = {}
    return _safe_int(
        agent.get("onboarding_level"),
        capability_profile.get("onboarding_level") if capability_profile else None,
        attack_plan.get("onboarding_level") if attack_plan else None,
    )


def _capability_map(capability_profile: dict[str, Any] | None) -> dict[str, bool]:
    capabilities = capability_profile.get("capabilities", {}) if capability_profile else {}
    if not isinstance(capabilities, dict):
        return {}
    return {str(name): bool(enabled) for name, enabled in capabilities.items()}


def _capability_rows(capabilities: dict[str, bool]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "label": _humanize_key(name),
            "enabled": enabled,
        }
        for name, enabled in capabilities.items()
    ]


def _category_rows(
    attack_plan: dict[str, Any] | None,
    generated_attacks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    categories = attack_plan.get("categories", []) if attack_plan else []
    rows: list[dict[str, Any]] = []
    if isinstance(categories, list):
        for category in categories:
            if not isinstance(category, dict):
                continue
            attack_ids = _string_list(category.get("attack_ids"))
            rows.append(
                {
                    "name": _first_text(category.get("name"), "Generated"),
                    "count": _safe_int(category.get("count"), len(attack_ids)),
                    "attack_ids": attack_ids,
                }
            )
    if rows:
        return rows
    if generated_attacks:
        return [
            {
                "name": "Generated",
                "count": len(generated_attacks),
                "attack_ids": [
                    str(attack.get("id"))
                    for attack in generated_attacks
                    if isinstance(attack, dict) and attack.get("id")
                ],
            }
        ]
    return []


def _generated_attack_ids(
    attack_plan: dict[str, Any] | None,
    generated_attacks: list[dict[str, Any]],
) -> list[str]:
    ids: list[str] = []
    for category in _category_rows(attack_plan, generated_attacks):
        ids.extend(category["attack_ids"])
    if not ids:
        ids.extend(
            str(attack.get("id"))
            for attack in generated_attacks
            if isinstance(attack, dict) and attack.get("id")
        )
    return _dedupe(ids)


def _generated_attack_pack_path(
    root: Path,
    attack_plan: dict[str, Any] | None,
) -> Path | None:
    if not attack_plan:
        return None
    value = attack_plan.get("generated_attack_pack")
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value.strip())
    return path if path.is_absolute() else root / path


def _load_generated_attacks(path: Path | None) -> list[dict[str, Any]]:
    if not path:
        return []
    data = _load_json(path)
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _existing_plan_artifacts(paths: dict[str, Path], root: Path) -> list[dict[str, str]]:
    labels = {
        "agent_profile": "Agent profile",
        "capability_profile": "Capability profile",
        "attack_plan": "Attack plan",
        "attack_plan_markdown": "Attack plan markdown",
    }
    return [
        {"label": labels[key], "path": _display_path(path, root)}
        for key, path in paths.items()
        if path.exists()
    ]


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
            assertion_label = _assertion_transition(attack, after_attack)
            assertion_suffix = f"  assertions={assertion_label}" if assertion_label else ""
            labels[attack["id"]] = (
                f'{attack["id"]}  {attack.get("source", "builtin")}  before={attack["status"]}  '
                f'after={(after_attack or {}).get("status", "-")}{assertion_suffix}'
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
        _render_assertion_status(attack)
        if attack.get("blocked_before_execution"):
            st.success("Blocked before execution")
        if attack.get("tool_trace_supplied") is False:
            st.warning("Output-only evaluation; no tool trace supplied.")
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
        st.caption(f"Success: {summary.get('success', 'unknown')}")
        if summary.get("source") == "claude_code_proposal":
            st.info("Claude Code generated the remediation plan. RedTeamCI validated and applied it deterministically.")
        st.caption(
            "Live Claude proposal applied: "
            + ("yes" if summary.get("live_claude_proposal_applied") else "no")
        )
        st.caption(
            "Fixture fallback used: "
            + ("yes" if summary.get("fixture_fallback_used") else "no")
        )
        artifact_path = summary.get("claude_artifact_path") or summary.get("prompt_path")
        if artifact_path:
            st.caption(f"Claude artifact path: {artifact_path}")
        if summary.get("error"):
            st.warning(summary["error"])
        if summary.get("validation_error_path"):
            st.warning(f"Claude validation errors: {summary['validation_error_path']}")
        st.write("Changed files:")
        for path in summary.get("changed_files", []):
            st.write(f"- {path}")
        st.code(diff or "No patch diff found.", language="diff")
        regression_path = summary.get("regression_test_path")
        if regression_path and Path(regression_path).exists():
            st.write("Generated regression test")
            st.json(_load_json(Path(regression_path)))
        elif GENERATED_REGRESSIONS_PATH.exists():
            st.write("Generated regression test")
            st.json(_load_json(GENERATED_REGRESSIONS_PATH))


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


def _render_assertion_status(attack: dict[str, Any]) -> None:
    if not _has_assertion_evidence(attack):
        return
    failures = attack.get("assertion_failures") or []
    count = int(attack.get("assertion_count") or len(failures))
    if failures:
        st.error(f"Assertion gates failed ({len(failures)}/{count})")
        for failure in failures:
            st.caption(failure)
    else:
        st.success(f"Assertion gates passed ({count}/{count})")


def _assertion_transition(
    before_attack: dict[str, Any],
    after_attack: dict[str, Any] | None,
) -> str:
    before = _short_assertion_state(before_attack)
    after = _short_assertion_state(after_attack)
    if before and after:
        return f"{before}->{after}"
    return before or after


def _short_assertion_state(attack: dict[str, Any] | None) -> str:
    if not attack or not _has_assertion_evidence(attack):
        return ""
    if attack.get("assertion_failures"):
        return "FAIL"
    return "PASS"


def _has_assertion_evidence(attack: dict[str, Any]) -> bool:
    return bool(attack.get("assertion_count") or attack.get("assertion_failures"))


def _latest_patch() -> tuple[dict[str, Any] | None, str]:
    if not PATCHES_ROOT.exists():
        return None, ""
    summaries = sorted(PATCHES_ROOT.glob("*_summary.json"), key=lambda path: path.stat().st_mtime)
    if not summaries:
        return None, ""
    summary = _load_json_object(summaries[-1])
    if not summary:
        return None, ""
    diff_path = Path(str(summary.get("diff_path", "")))
    diff = diff_path.read_text(encoding="utf-8") if diff_path.exists() else ""
    return summary, diff


def _load_json_object(path: Path) -> dict[str, Any] | None:
    data = _load_json(path)
    return data if isinstance(data, dict) else None


def _load_json(path: Path) -> dict[str, Any] | list[Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def _root_path(root: Path, value: Any) -> Path | None:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    path = Path(text)
    return path if path.is_absolute() else root / path


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _first_text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _safe_int(*values: Any) -> int:
    for value in values:
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
    return 0


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _dedupe(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped


def _humanize_key(value: str) -> str:
    return value.replace("_", " ").strip().capitalize()


if __name__ == "__main__":
    main()
