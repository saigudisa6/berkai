from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from redteamci.redaction import redact_secrets


def capture_failure_if_configured(
    *,
    run_id: str,
    attack_id: str,
    attack_name: str = "",
    failure_reason: str,
    trace_path: Path,
    risky_tool_name: str | None = None,
    agent: str = "builtin",
    dangerous_tools_attempted: list[str] | None = None,
    blocked_before_execution: bool = False,
    attack_payload: str = "",
) -> str | None:
    try:
        dsn = os.environ.get("SENTRY_DSN")
        if not dsn:
            return None

        import sentry_sdk

        sentry_sdk.init(dsn=dsn)
        return sentry_sdk.capture_event(
            {
                "message": f"RedTeamCI failed: {attack_id} {attack_name}".strip(),
                "level": "error",
                "tags": {
                    "attack_id": attack_id,
                    "attack_class": _attack_class(attack_id),
                    "agent": agent,
                    "run_id": run_id,
                    "dangerous_tool": risky_tool_name or "unknown",
                },
                "extra": {
                    "failure_reason": failure_reason,
                    "trace_path": trace_path.as_posix(),
                    "dangerous_tools_attempted": dangerous_tools_attempted or [],
                    "blocked_before_execution": blocked_before_execution,
                    "redacted_attack_payload": redact_secrets(attack_payload),
                },
            }
        )
    except Exception:
        return None


def _attack_class(attack_id: str) -> str:
    if attack_id.startswith("pi-"):
        return "prompt_injection"
    if attack_id.startswith("exfil-"):
        return "exfiltration"
    return attack_id.split("-")[0]
