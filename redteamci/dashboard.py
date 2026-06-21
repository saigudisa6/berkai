from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

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
from redteamci.summary import load_summary


REDTEAMCI_OUTPUT_DIR = ".redteamci"
AGENT_PROFILE_FILE = "agent_profile.json"
CAPABILITY_PROFILE_FILE = "capability_profile.json"
ATTACK_PLAN_FILE = "attack_plan.json"
ATTACK_PLAN_MARKDOWN_FILE = "attack_plan.md"
LEVEL_1_WARNING = (
    "Level 1 trace/report/proposal only; no forced blocking unless the agent uses guarded tools."
)


def main() -> None:
    streamlit = _require_streamlit()
    streamlit.set_page_config(page_title="RedTeamCI", layout="wide")
    st.title("RedTeamCI")
    st.caption("Crash-test your AI agent before production.")

    before = _load_optional_summary(DEFAULT_BEFORE_SUMMARY_PATH)
    after = _load_optional_summary(DEFAULT_AFTER_SUMMARY_PATH)
    _render_top_metrics(before, after)
    _render_demo_mode_actions()
    _render_generated_plan_panel(load_generated_plan_panel(ROOT))

    left, middle, right = st.columns([1.3, 2.2, 2.2])
    selected_attack = _render_attack_suite(left, before, after)
    _render_flight_recorder(middle, selected_attack, before, after)
    _render_patch_panel(right)


def _require_streamlit() -> Any:
    if st is None:
        raise RuntimeError("Streamlit is required to launch the RedTeamCI dashboard.")
    return st


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
