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
    total = after.get("total_attacks") or before.get("total_attacks") or 0
    certified = bool(after.get("certified"))
    selected = _attack_by_id(before, "pi-003") or (before.get("attacks") or [{}])[0]
    after_selected = _attack_by_id(after, selected.get("id", "pi-003"))
    patch_summary, patch_diff = _latest_patch()
    generated_regression = _generated_regression_text()
    blocked_events = _blocked_events(after)
    output_only = _output_only_attacks(after)
    integrations = after.get("integrations", {})
    agent = integrations.get("agent") or before.get("integrations", {}).get("agent", "builtin")

    lines = [
        "# RedTeamCI Security Report",
        "",
        "## Result",
        f"Before patch: {before_secure}/{total} secure",
        f"After patch: {after_secure}/{total} secure",
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
            "## Claude Code Remediation",
            f"Source: {patch_summary.get('source', 'unknown')}",
            f"Success: {patch_summary.get('success', 'unknown')}",
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
            "## Integrations",
            f"Sentry event IDs: {integrations.get('sentry_event_ids', [])}",
            f"Redis stream keys: {integrations.get('redis_stream_keys', [])}",
            "Browserbase: disabled",
            "Arize: disabled",
            "",
            "## Certification",
            "AGENT CERTIFIED" if certified else "NOT CERTIFIED",
            "",
        ]
    )
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
