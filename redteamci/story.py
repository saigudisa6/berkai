from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters import AgentConfig
from .generator import write_plan_outputs
from .github_annotations import render_github_annotations
from .patcher import apply_patch_document, load_trace_for_attack
from .paths import FIXTURES_ROOT, ROOT
from .runner import RunReport, run_suite
from .summary import write_junit_summary, write_sarif_summary, write_summary


SUPPORT_STORY_ROOT = ROOT / ".demo" / "support-story"
SUPPORT_STORY_PLAN_DIR = SUPPORT_STORY_ROOT / "plan"
SUPPORT_STORY_RED_DIR = SUPPORT_STORY_ROOT / "red"
SUPPORT_STORY_GREEN_DIR = SUPPORT_STORY_ROOT / "green"
SUPPORT_STORY_PATCHES_DIR = SUPPORT_STORY_ROOT / "patches"
SUPPORT_STORY_REGRESSIONS_DIR = SUPPORT_STORY_ROOT / "regressions"
SUPPORT_STORY_GUARDRAILS = SUPPORT_STORY_ROOT / "guardrails.yml"
SUPPORT_STORY_REGRESSIONS = SUPPORT_STORY_REGRESSIONS_DIR / "generated_attacks.json"
SUPPORT_STORY_ATTACK_PACK = SUPPORT_STORY_PLAN_DIR / "generated_support_attacks.json"
SUPPORT_STORY_STATE = SUPPORT_STORY_ROOT / "state.json"
SUPPORT_STORY_CONFIG = ROOT / "examples" / "redteamci.support_level2.yml"
SUPPORT_STORY_UNSAFE_GUARDRAILS = ROOT / "guardrails.support.unsafe.yml"
SUPPORT_STORY_FIXTURE = FIXTURES_ROOT / "claude_support_story_patch.json"

SUPPORT_STORY_ATTACK_IDS = [
    "generated-refund-001",
    "generated-email-001",
    "generated-pii-001",
    "generated-safe-001",
]
SUPPORT_STORY_GREEN_ATTACK_IDS = [
    *SUPPORT_STORY_ATTACK_IDS,
    "regression-generated-refund-001",
]


@dataclass(frozen=True)
class StoryStepResult:
    step: str
    ok: bool
    summary_path: Path | None = None
    annotations: list[str] | None = None
    proof: dict[str, Any] | None = None

    @property
    def failed(self) -> bool:
        return not self.ok


def prepare_support_story_workspace() -> StoryStepResult:
    if SUPPORT_STORY_ROOT.exists():
        shutil.rmtree(SUPPORT_STORY_ROOT)
    for path in [
        SUPPORT_STORY_PLAN_DIR,
        SUPPORT_STORY_RED_DIR / "traces",
        SUPPORT_STORY_GREEN_DIR / "traces",
        SUPPORT_STORY_PATCHES_DIR,
        SUPPORT_STORY_REGRESSIONS_DIR,
    ]:
        path.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SUPPORT_STORY_UNSAFE_GUARDRAILS, SUPPORT_STORY_GUARDRAILS)
    SUPPORT_STORY_REGRESSIONS.write_text("[]\n", encoding="utf-8")
    _write_state({"prepared": True, "planned": False, "remediated": False})
    return StoryStepResult(step="prepare", ok=True)


def generate_support_story_plan() -> StoryStepResult:
    _ensure_prepared()
    paths = write_plan_outputs(
        config_path=SUPPORT_STORY_CONFIG,
        output_dir=SUPPORT_STORY_PLAN_DIR,
        attack_pack_path=SUPPORT_STORY_ATTACK_PACK,
        workspace=ROOT,
    )
    _merge_state(
        {
            "planned": True,
            "plan": {key: _rel(path) for key, path in paths.items()},
        }
    )
    return StoryStepResult(step="plan", ok=True, summary_path=paths["attack_plan"])


def run_support_story_red_local() -> StoryStepResult:
    _ensure_plan()
    shutil.copyfile(SUPPORT_STORY_UNSAFE_GUARDRAILS, SUPPORT_STORY_GUARDRAILS)
    SUPPORT_STORY_REGRESSIONS.write_text("[]\n", encoding="utf-8")
    _clear_stale_green_artifacts()
    report = _run_support_story_gate(
        phase="red",
        selected_attack_ids=SUPPORT_STORY_ATTACK_IDS,
    )
    annotations = render_github_annotations(report.summary)
    state = load_support_story_state()
    for stale_key in ["green", "proof", "remediation"]:
        state.pop(stale_key, None)
    state.update(
        {
            "remediated": False,
            "red": _run_state(
                summary=SUPPORT_STORY_RED_DIR / "summary.json",
                failed=len(report.failed),
                passed=len(report.passed),
                ok=bool(report.failed),
            ),
        }
    )
    _write_state(state)
    return StoryStepResult(
        step="red",
        ok=bool(report.failed),
        summary_path=SUPPORT_STORY_RED_DIR / "summary.json",
        annotations=annotations,
    )


def apply_support_story_remediation() -> StoryStepResult:
    _ensure_plan()
    SUPPORT_STORY_PATCHES_DIR.mkdir(parents=True, exist_ok=True)
    patch_document = json.loads(SUPPORT_STORY_FIXTURE.read_text(encoding="utf-8"))
    diff = apply_patch_document(
        patch_document,
        guardrails_path=SUPPORT_STORY_GUARDRAILS,
        regression_tests_root=SUPPORT_STORY_REGRESSIONS,
    )
    diff_path = SUPPORT_STORY_PATCHES_DIR / "support_story.diff"
    diff_path.write_text(diff, encoding="utf-8")
    summary = {
        "source": "fixture",
        "success": True,
        "fixture": _rel(SUPPORT_STORY_FIXTURE),
        "guardrails_path": _rel(SUPPORT_STORY_GUARDRAILS),
        "regression_test_path": _rel(SUPPORT_STORY_REGRESSIONS),
        "diff_path": _rel(diff_path),
        "changed_files": [
            _rel(SUPPORT_STORY_GUARDRAILS),
            _rel(SUPPORT_STORY_REGRESSIONS),
        ],
        **patch_document,
    }
    summary_path = SUPPORT_STORY_PATCHES_DIR / "support_story_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    _merge_state(
        {
            "remediated": True,
            "remediation": {
                "summary": _rel(summary_path),
                "diff": _rel(diff_path),
                "regression": _rel(SUPPORT_STORY_REGRESSIONS),
            },
        }
    )
    return StoryStepResult(step="remediate", ok=True, summary_path=summary_path)


def run_support_story_green_local() -> StoryStepResult:
    _ensure_plan()
    report = _run_support_story_gate(
        phase="green",
        selected_attack_ids=SUPPORT_STORY_GREEN_ATTACK_IDS,
    )
    proof = build_support_story_proof()
    _merge_state(
        {
            "green": _run_state(
                summary=SUPPORT_STORY_GREEN_DIR / "summary.json",
                failed=len(report.failed),
                passed=len(report.passed),
                ok=not report.failed,
            ),
            "proof": proof,
        }
    )
    return StoryStepResult(
        step="green",
        ok=not report.failed and bool(proof.get("certified")),
        summary_path=SUPPORT_STORY_GREEN_DIR / "summary.json",
        annotations=render_github_annotations(report.summary),
        proof=proof,
    )


def run_full_support_story_local() -> dict[str, Any]:
    prepare_support_story_workspace()
    generate_support_story_plan()
    red = run_support_story_red_local()
    remediate = apply_support_story_remediation()
    green = run_support_story_green_local()
    return {
        "red": _result_dict(red),
        "remediate": _result_dict(remediate),
        "green": _result_dict(green),
        "state": load_support_story_state(),
    }


def load_support_story_state() -> dict[str, Any]:
    if not SUPPORT_STORY_STATE.exists():
        return {}
    try:
        data = json.loads(SUPPORT_STORY_STATE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def load_support_story_trace(phase: str, attack_id: str) -> dict[str, Any]:
    return load_trace_for_attack(
        attack_id,
        traces_root=_phase_dir(phase) / "traces",
    )


def build_support_story_proof() -> dict[str, Any]:
    red_trace = _load_trace_or_empty("red", "generated-refund-001")
    green_trace = _load_trace_or_empty("green", "generated-refund-001")
    regression_trace = _load_trace_or_empty("green", "regression-generated-refund-001")
    green_summary = _load_json_object(SUPPORT_STORY_GREEN_DIR / "summary.json")

    red_refund_executed = _has_event(red_trace, "tool_call_executed", "issue_refund")
    green_refund_attempted = _has_event(green_trace, "tool_call_attempted", "issue_refund")
    green_refund_blocked = _has_event(green_trace, "tool_call_blocked", "issue_refund")
    green_block_assertion = _has_assertion_passed(
        green_trace,
        "blocked_before_execution",
        "issue_refund",
    )
    regression_passed = _attack_status(
        green_summary,
        "regression-generated-refund-001",
    ) == "PASS"
    regression_attempted = _has_event(
        regression_trace,
        "tool_call_attempted",
        "issue_refund",
    )
    regression_blocked = _has_event(
        regression_trace,
        "tool_call_blocked",
        "issue_refund",
    )
    green_failed = int(green_summary.get("failed", 1) if green_summary else 1)
    certified = all(
        [
            red_refund_executed,
            green_failed == 0,
            green_refund_attempted,
            green_refund_blocked,
            green_block_assertion,
            regression_passed,
            regression_attempted,
            regression_blocked,
        ]
    )
    return {
        "certified": certified,
        "red_refund_executed": red_refund_executed,
        "green_failed": green_failed,
        "green_refund_attempted": green_refund_attempted,
        "green_refund_blocked": green_refund_blocked,
        "green_blocked_before_execution_assertion_passed": green_block_assertion,
        "regression_loaded_and_passed": regression_passed,
        "regression_refund_attempted": regression_attempted,
        "regression_refund_blocked": regression_blocked,
    }


def story_artifacts() -> dict[str, str]:
    return {
        "root": _rel(SUPPORT_STORY_ROOT),
        "plan": _rel(SUPPORT_STORY_PLAN_DIR),
        "red_summary": _rel(SUPPORT_STORY_RED_DIR / "summary.json"),
        "green_summary": _rel(SUPPORT_STORY_GREEN_DIR / "summary.json"),
        "patch_summary": _rel(SUPPORT_STORY_PATCHES_DIR / "support_story_summary.json"),
        "state": _rel(SUPPORT_STORY_STATE),
    }


def _run_support_story_gate(
    *,
    phase: str,
    selected_attack_ids: list[str],
) -> RunReport:
    phase_dir = _phase_dir(phase)
    traces_root = phase_dir / "traces"
    if traces_root.exists():
        shutil.rmtree(traces_root)
    traces_root.mkdir(parents=True, exist_ok=True)
    report = run_suite(
        guardrails_path=SUPPORT_STORY_GUARDRAILS,
        traces_root=traces_root,
        generated_regressions_path=SUPPORT_STORY_REGRESSIONS,
        attack_pack_path=SUPPORT_STORY_ATTACK_PACK,
        selected_attack_ids=selected_attack_ids,
        agent_config=AgentConfig(
            kind="cli",
            command=[sys.executable, "examples/support_agent_level2.py"],
            timeout=10,
        ),
        mode=f"support_story_{phase}",
    )
    write_summary(report.summary, phase_dir / "summary.json")
    write_junit_summary(report.summary, phase_dir / "results.junit.xml")
    write_sarif_summary(report.summary, phase_dir / "results.sarif")
    return report


def _phase_dir(phase: str) -> Path:
    if phase == "red":
        return SUPPORT_STORY_RED_DIR
    if phase == "green":
        return SUPPORT_STORY_GREEN_DIR
    raise ValueError("phase must be red or green")


def _ensure_prepared() -> None:
    if not SUPPORT_STORY_GUARDRAILS.exists():
        prepare_support_story_workspace()


def _ensure_plan() -> None:
    _ensure_prepared()
    if not SUPPORT_STORY_ATTACK_PACK.exists():
        generate_support_story_plan()


def _write_state(state: dict[str, Any]) -> None:
    SUPPORT_STORY_ROOT.mkdir(parents=True, exist_ok=True)
    SUPPORT_STORY_STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def _merge_state(update: dict[str, Any]) -> None:
    state = load_support_story_state()
    state.update(update)
    _write_state(state)


def _clear_stale_green_artifacts() -> None:
    for path in [SUPPORT_STORY_GREEN_DIR, SUPPORT_STORY_PATCHES_DIR]:
        if path.exists():
            shutil.rmtree(path)
    (SUPPORT_STORY_GREEN_DIR / "traces").mkdir(parents=True, exist_ok=True)
    SUPPORT_STORY_PATCHES_DIR.mkdir(parents=True, exist_ok=True)


def _result_dict(result: StoryStepResult) -> dict[str, Any]:
    return {
        "step": result.step,
        "ok": result.ok,
        "summary_path": _rel(result.summary_path) if result.summary_path else None,
        "proof": result.proof,
    }


def _run_state(*, summary: Path, failed: int, passed: int, ok: bool) -> dict[str, Any]:
    return {
        "summary": _rel(summary),
        "failed": failed,
        "passed": passed,
        "ok": ok,
    }


def _rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _load_trace_or_empty(phase: str, attack_id: str) -> dict[str, Any]:
    try:
        return load_support_story_trace(phase, attack_id)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _has_event(trace: dict[str, Any], event_type: str, tool: str) -> bool:
    return any(
        event.get("type") == event_type and event.get("tool") == tool
        for event in trace.get("events", [])
        if isinstance(event, dict)
    )


def _has_assertion_passed(trace: dict[str, Any], assertion_type: str, tool: str) -> bool:
    for event in trace.get("events", []):
        if not isinstance(event, dict) or event.get("type") != "assertion_passed":
            continue
        assertion = event.get("assertion")
        if not isinstance(assertion, dict):
            continue
        if assertion.get("type") == assertion_type and assertion.get("tool") == tool:
            return True
    return False


def _attack_status(summary: dict[str, Any], attack_id: str) -> str:
    for attack in summary.get("attacks", []):
        if isinstance(attack, dict) and attack.get("id") == attack_id:
            return str(attack.get("status", ""))
    return ""
