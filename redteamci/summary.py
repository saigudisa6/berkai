from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


def build_run_summary(
    *,
    run_id: str,
    results: list[Any],
    mode: str = "unknown",
    integrations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    total = len(results)
    passed = len([result for result in results if result.status == "PASS"])
    failed = total - passed
    generated = [result for result in results if result.source == "generated"]
    generated_passed = len([result for result in generated if result.status == "PASS"])
    generated_failed = len(generated) - generated_passed
    return {
        "project": "RedTeamCI",
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "total_attacks": total,
        "passed": passed,
        "failed": failed,
        "generated_regressions_loaded": len(generated),
        "generated_regressions_passed": generated_passed,
        "generated_regressions_failed": generated_failed,
        "pass_rate": passed / total if total else 0.0,
        "certified": failed == 0 and total > 0,
        "attacks": [
            {
                "id": result.id,
                "name": result.name,
                "status": result.status,
                "source": result.source,
                "reason": result.reason,
                "trace_path": str(result.trace_path),
                "tool_trace_supplied": result.tool_trace_supplied,
                "blocked_before_execution": result.blocked_before_execution,
                "dangerous_tools_attempted": result.dangerous_tools_attempted,
                "dangerous_tools_blocked": result.dangerous_tools_blocked,
                "assertion_count": result.assertion_count,
                "assertion_failures": result.assertion_failures,
            }
            for result in results
        ],
        "integrations": integrations
        or {
            "sentry_event_ids": [],
            "redis_stream_keys": [],
            "claude_code_patch": None,
        },
    }


def write_summary(summary: dict[str, Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(summary, indent=2), encoding="utf-8")


def load_summary(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_junit_summary(summary: dict[str, Any], path: str | Path) -> None:
    tests = int(summary.get("total_attacks", 0))
    failures = int(summary.get("failed", 0))
    suite = ElementTree.Element(
        "testsuite",
        {
            "name": "RedTeamCI",
            "tests": str(tests),
            "failures": str(failures),
            "errors": "0",
            "skipped": "0",
            "timestamp": str(summary.get("timestamp", "")),
        },
    )

    suite_properties = ElementTree.SubElement(suite, "properties")
    for name, value in [
        ("project", summary.get("project", "RedTeamCI")),
        ("run_id", summary.get("run_id", "")),
        ("mode", summary.get("mode", "")),
        ("certified", summary.get("certified", False)),
    ]:
        ElementTree.SubElement(
            suite_properties,
            "property",
            {"name": name, "value": str(value)},
        )

    for attack in summary.get("attacks", []):
        source = str(attack.get("source") or "unknown")
        attack_id = str(attack.get("id") or "unknown")
        attack_name = str(attack.get("name") or attack_id)
        testcase = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "classname": f"redteamci.{_junit_token(source)}",
                "name": f"{attack_id}: {attack_name}",
                "time": "0",
            },
        )
        properties = ElementTree.SubElement(testcase, "properties")
        for name, value in [
            ("attack_id", attack_id),
            ("source", source),
            ("trace_path", attack.get("trace_path", "")),
            ("blocked_before_execution", attack.get("blocked_before_execution", False)),
            ("assertion_count", attack.get("assertion_count", 0)),
        ]:
            ElementTree.SubElement(
                properties,
                "property",
                {"name": name, "value": str(value)},
            )

        reason = str(attack.get("reason") or "")
        if attack.get("status") == "FAIL":
            failure = ElementTree.SubElement(
                testcase,
                "failure",
                {"message": reason, "type": "RedTeamCIFailure"},
            )
            failure.text = _junit_failure_text(attack)

        system_out = ElementTree.SubElement(testcase, "system-out")
        system_out.text = json.dumps(
            {
                "status": attack.get("status"),
                "source": source,
                "trace_path": attack.get("trace_path"),
                "reason": reason,
                "assertion_failures": attack.get("assertion_failures", []),
                "dangerous_tools_attempted": attack.get("dangerous_tools_attempted", []),
                "dangerous_tools_blocked": attack.get("dangerous_tools_blocked", []),
            },
            indent=2,
        )

    ElementTree.indent(suite, space="  ")
    tree = ElementTree.ElementTree(suite)
    tree.write(path, encoding="utf-8", xml_declaration=True)


def _junit_failure_text(attack: dict[str, Any]) -> str:
    lines = [
        f"Attack: {attack.get('id')} - {attack.get('name')}",
        f"Source: {attack.get('source')}",
        f"Reason: {attack.get('reason')}",
        f"Trace: {attack.get('trace_path')}",
    ]
    assertion_failures = attack.get("assertion_failures") or []
    if assertion_failures:
        lines.append("Assertion failures:")
        lines.extend(f"- {failure}" for failure in assertion_failures)
    return "\n".join(lines)


def _junit_token(value: str) -> str:
    token = "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
    return token or "unknown"
