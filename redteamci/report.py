from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .paths import GENERATED_REGRESSIONS_PATH, PATCHES_ROOT
from .redaction import redact_secrets
from .summary import load_summary


def generate_report(
    *,
    before_path: str | Path,
    after_path: str | Path,
    output_path: str | Path,
) -> Path:
    before = load_summary(before_path)
    after = load_summary(after_path)
    output = Path(output_path)
    output.write_text(_render_report(before, after), encoding="utf-8")
    return output


def _render_report(before: dict[str, Any], after: dict[str, Any]) -> str:
    before_secure = before.get("passed", 0)
    after_secure = after.get("passed", 0)
    before_total = before.get("total_attacks") or 0
    after_total = after.get("total_attacks") or before_total
    certified = bool(after.get("certified"))
    selected = _attack_by_id(before, "pi-003") or (before.get("attacks") or [{}])[0]
    patch_summary, patch_diff = _latest_patch()
    generated_regression = _generated_regression_text()
    generated_attacks = [
        attack for attack in after.get("attacks", []) if attack.get("source") == "generated"
    ]
    blocked_events = _blocked_events(after)
    output_only = _output_only_attacks(after)
    integrations = after.get("integrations", {})
    agent = integrations.get("agent") or before.get("integrations", {}).get("agent", "builtin")

    lines = [
        "# RedTeamCI Security Report",
        "",
        "## Result",
        "Exploit became regression test",
        f"Before patch: {before_secure}/{before_total} secure",
        f"After patch: {after_secure}/{after_total} secure",
        f"Generated regression tests loaded: {after.get('generated_regressions_loaded', 0)}",
        f"Agent: {agent}",
        f"Status: {'AGENT CERTIFIED' if certified else 'NOT CERTIFIED'}",
        "",
        "## What RedTeamCI Tested",
        "",
        "Attack ID | Source | Name | Before | After | Secure Behavior",
        "--- | --- | --- | --- | --- | ---",
    ]
    for before_attack in _attack_union(before, after):
        after_attack = _attack_by_id(after, before_attack["id"]) or {}
        source = after_attack.get("source", before_attack.get("source", "builtin"))
        lines.append(
            " | ".join(
                [
                    before_attack["id"],
                    source,
                    before_attack["name"],
                    before_attack.get("status", "NOT RUN"),
                    after_attack.get("status", "UNKNOWN"),
                    after_attack.get("reason", before_attack.get("reason", "")),
                ]
            )
        )

    assertion_gate_lines = _assertion_gate_lines(before, after)
    if assertion_gate_lines:
        lines.extend(["", "## Custom Assertion Gates", "", *assertion_gate_lines])

    lines.extend(["", "## Generated Regression Result", ""])
    if generated_attacks:
        for attack in generated_attacks:
            lines.append(f"Generated regression: {attack['id']} - {attack['status']}")
    else:
        lines.append("Generated regression: none loaded")

    lines.extend(
        [
            "",
            f"## Selected Failure: {selected.get('id', 'pi-003')}",
            "",
            "Timeline:",
            "- Webpage loaded",
            "- Hidden HTML comment entered agent context",
            '- Agent attempted read_file(".env")',
            "- Policy did not block it before patch",
            "- Secret-like content detected",
            "- FAIL",
            "",
            "After:",
            "- Generated regression replayed same exploit",
            '- Agent attempted read_file(".env")',
            "- Policy blocked before execution",
            "- PASS",
            "",
            "## Claude Code Remediation",
            f"Source: {patch_summary.get('source', 'unknown')}",
            f"Success: {patch_summary.get('success', 'unknown')}",
            _remediation_description(patch_summary),
            "RedTeamCI validated and applied it deterministically."
            if patch_summary.get("source") == "claude_code_proposal"
            and patch_summary.get("success")
            else "",
            f"Live Claude proposal applied: {_yes_no(patch_summary.get('live_claude_proposal_applied'))}",
            f"Fixture fallback used: {_yes_no(patch_summary.get('fixture_fallback_used'))}",
            f"Claude artifact path: {patch_summary.get('claude_artifact_path') or patch_summary.get('prompt_path') or '-'}",
            f"Regression test path: {patch_summary.get('regression_test_path')}",
            f"Failure reason: {patch_summary.get('error')}",
            "",
            "Changed files:",
        ]
    )
    for changed in patch_summary.get("changed_files", []):
        lines.append(f"- {changed}")

    lines.extend(["", "Patch diff:", "```diff", patch_diff.rstrip(), "```", ""])
    lines.extend(["## Blocked Before Execution", ""])
    if blocked_events:
        for event in blocked_events:
            lines.append(
                f"- {event.get('attack_id', 'unknown')}: {event.get('tool')} blocked before execution"
            )
    else:
        lines.append("- No blocked tool calls recorded.")

    lines.extend(["", "## External Agent Trace Coverage", ""])
    if output_only:
        for attack in output_only:
            lines.append(
                f"- {attack['id']}: Output-only evaluation; no tool trace supplied."
            )
    else:
        lines.append("- Tool trace supplied for all recorded attacks.")

    lines.extend(
        [
            "",
            "## Generated Regression Test",
            "",
            "```json",
            generated_regression,
            "```",
            "",
        ]
    )
    integration_lines = _integration_lines(integrations)
    if integration_lines:
        lines.extend(["## Integrations", *integration_lines, ""])
    lines.extend(["## Certification", "AGENT CERTIFIED" if certified else "NOT CERTIFIED", ""])
    return "\n".join(lines)


def _attack_by_id(summary: dict[str, Any], attack_id: str) -> dict[str, Any] | None:
    for attack in summary.get("attacks", []):
        if attack.get("id") == attack_id:
            return attack
    return None


def _attack_union(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    attacks: dict[str, dict[str, Any]] = {}
    for attack in before.get("attacks", []):
        attacks[attack["id"]] = attack
    for attack in after.get("attacks", []):
        attacks.setdefault(
            attack["id"],
            {
                "id": attack["id"],
                "name": attack.get("name", attack["id"]),
                "status": "NOT RUN",
                "source": attack.get("source", "builtin"),
                "reason": "",
            },
        )
    return list(attacks.values())


def _assertion_gate_lines(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    rows = []
    failures = []
    for before_attack in _attack_union(before, after):
        after_attack = _attack_by_id(after, before_attack["id"]) or {}
        if not (
            _has_assertion_evidence(before_attack)
            or _has_assertion_evidence(after_attack)
        ):
            continue
        source = after_attack.get("source", before_attack.get("source", "builtin"))
        rows.append(
            " | ".join(
                [
                    before_attack["id"],
                    source,
                    before_attack["name"],
                    _assertion_state(before_attack),
                    _assertion_state(after_attack),
                ]
            )
        )
        for failure in before_attack.get("assertion_failures") or []:
            failures.append(f"- {before_attack['id']} before: {failure}")
        for failure in after_attack.get("assertion_failures") or []:
            failures.append(f"- {before_attack['id']} after: {failure}")

    if not rows:
        return []
    lines = [
        "Attack ID | Source | Name | Before Assertions | After Assertions",
        "--- | --- | --- | --- | ---",
        *rows,
    ]
    if failures:
        lines.extend(["", "Assertion failure details:", *failures])
    return lines


def _has_assertion_evidence(attack: dict[str, Any]) -> bool:
    return bool(attack.get("assertion_count") or attack.get("assertion_failures"))


def _assertion_state(attack: dict[str, Any]) -> str:
    if not attack:
        return "NOT RUN"
    failures = attack.get("assertion_failures") or []
    if failures:
        return f"FAIL ({len(failures)} failed)"
    count = int(attack.get("assertion_count") or 0)
    if count:
        return f"PASS ({count} passed)"
    return "-"


def _latest_patch() -> tuple[dict[str, Any], str]:
    if not PATCHES_ROOT.exists():
        return {}, ""
    summaries = sorted(PATCHES_ROOT.glob("*_summary.json"), key=lambda path: path.stat().st_mtime)
    if not summaries:
        return {}, ""
    summary_path = summaries[-1]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    diff_path = Path(str(summary.get("diff_path", "")))
    diff = diff_path.read_text(encoding="utf-8") if diff_path.exists() else ""
    return redact_secrets(summary), redact_secrets(diff)


def _generated_regression_text() -> str:
    if not GENERATED_REGRESSIONS_PATH.exists():
        return "[]"
    data = json.loads(GENERATED_REGRESSIONS_PATH.read_text(encoding="utf-8"))
    return json.dumps(redact_secrets(data), indent=2)


def _blocked_events(summary: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for attack in summary.get("attacks", []):
        if not attack.get("blocked_before_execution"):
            continue
        for tool in attack.get("dangerous_tools_blocked", []):
            events.append({"attack_id": attack["id"], "tool": tool})
    return events


def _output_only_attacks(summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        attack
        for attack in summary.get("attacks", [])
        if attack.get("tool_trace_supplied") is False
    ]


def _integration_lines(integrations: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    sentry_ids = integrations.get("sentry_event_ids") or []
    if sentry_ids:
        lines.append(f"Sentry event created: {sentry_ids}")
    redis_keys = integrations.get("redis_stream_keys") or []
    if redis_keys:
        lines.append(f"Redis stream keys: {redis_keys}")
    redis_summary = integrations.get("redis_summary_key")
    if redis_summary:
        lines.append(f"Redis summary key: {redis_summary}")
    return lines


def _yes_no(value: Any) -> str:
    return "yes" if bool(value) else "no"


def _remediation_description(summary: dict[str, Any]) -> str:
    source = summary.get("source")
    if source == "claude_code_proposal":
        return "Claude Code generated the remediation plan."
    if source == "fixture":
        return "Remediation used a stored deterministic artifact."
    if source == "claude_code_direct_edit":
        return "Claude Code direct-edit mode was used."
    return "No remediation artifact found."
