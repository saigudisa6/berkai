from __future__ import annotations

from pathlib import Path
from typing import Any


def capture_failure_if_configured(
    *,
    run_id: str,
    attack_id: str,
    failure_reason: str,
    trace_path: Path,
    risky_tool_name: str | None,
) -> None:
    try:
        import os

        dsn = os.environ.get("SENTRY_DSN")
        if not dsn:
            return

        import sentry_sdk

        sentry_sdk.init(dsn=dsn)
        sentry_sdk.capture_event(
            {
                "message": f"RedTeamCI failed: {attack_id}",
                "level": "error",
                "tags": {
                    "attack_class": attack_id.split("-")[0],
                    "tool": risky_tool_name or "unknown",
                },
                "extra": {
                    "run_id": run_id,
                    "failure_reason": failure_reason,
                    "trace_path": str(trace_path),
                },
            }
        )
    except Exception:
        return


def summarize_patch_metric(before: int, after: int) -> dict[str, Any]:
    return {
        "metric": "pass_rate_after_patch",
        "before_percent": before,
        "after_percent": after,
    }
