from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
