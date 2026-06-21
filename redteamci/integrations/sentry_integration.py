from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from redteamci.redaction import redact_secrets


def build_failure_event_payload(
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
    summary_path: Path | None = None,
    remediation_artifact_paths: list[str | Path] | None = None,
    regression_artifact_paths: list[str | Path] | None = None,
    scenario: str | None = None,
    run_type: str | None = None,
) -> dict[str, Any]:
    attempted_tools = dangerous_tools_attempted or []
    risky_tool = risky_tool_name or (attempted_tools[0] if attempted_tools else "unknown")
    scenario_value = _scenario_value(scenario, run_type)
    tags = {
        "redteamci": "true",
        "scenario": scenario_value,
        "attack_id": attack_id,
        "attack_class": _attack_class(attack_id),
        "agent": agent,
        "run_id": run_id,
        "dangerous_tool": risky_tool,
        "blocked_before_execution": str(blocked_before_execution).lower(),
    }
    if run_type:
        tags["run_type"] = run_type
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        tags["ci_provider"] = "github_actions"
    github_url = _github_run_url()
    if github_url:
        tags["github_run_url"] = github_url

    extra = {
        "failure_reason": failure_reason,
        "redacted_attack_payload": redact_secrets(attack_payload),
        "dangerous_tools_attempted": attempted_tools,
        "trace_path": _path_value(trace_path),
        "blocked_before_execution": blocked_before_execution,
    }
    if summary_path:
        extra["summary_path"] = _path_value(summary_path)
    if remediation_artifact_paths:
        extra["remediation_artifact_paths"] = [
            _path_value(path) for path in remediation_artifact_paths
        ]
    if regression_artifact_paths:
        extra["regression_artifact_paths"] = [
            _path_value(path) for path in regression_artifact_paths
        ]

    return {
        "message": f"RedTeamCI failed: {attack_id} {attack_name}".strip(),
        "level": "error",
        "tags": tags,
        "fingerprint": ["redteamci", run_type or scenario_value, attack_id, risky_tool],
        "extra": extra,
    }


def build_failure_event_context(*, event_id: str, **payload_kwargs: Any) -> dict[str, Any]:
    payload = build_failure_event_payload(**payload_kwargs)
    return {
        "event_id": event_id,
        "tags": payload["tags"],
        "fingerprint": payload["fingerprint"],
        "extra": payload["extra"],
    }


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
    summary_path: Path | None = None,
    remediation_artifact_paths: list[str | Path] | None = None,
    regression_artifact_paths: list[str | Path] | None = None,
    scenario: str | None = None,
    run_type: str | None = None,
) -> str | None:
    try:
        dsn = os.environ.get("SENTRY_DSN")
        if not dsn:
            return None

        import sentry_sdk

        sentry_sdk.init(
            dsn=dsn,
            environment=os.environ.get("SENTRY_ENVIRONMENT"),
            release=os.environ.get("SENTRY_RELEASE"),
        )
        event_id = sentry_sdk.capture_event(
            build_failure_event_payload(
                run_id=run_id,
                attack_id=attack_id,
                attack_name=attack_name,
                failure_reason=failure_reason,
                trace_path=trace_path,
                risky_tool_name=risky_tool_name,
                agent=agent,
                dangerous_tools_attempted=dangerous_tools_attempted,
                blocked_before_execution=blocked_before_execution,
                attack_payload=attack_payload,
                summary_path=summary_path,
                remediation_artifact_paths=remediation_artifact_paths,
                regression_artifact_paths=regression_artifact_paths,
                scenario=scenario,
                run_type=run_type,
            )
        )
        return str(event_id) if event_id else None
    except Exception:
        return None


def _attack_class(attack_id: str) -> str:
    if attack_id.startswith("pi-"):
        return "prompt_injection"
    if attack_id.startswith("exfil-"):
        return "exfiltration"
    return attack_id.split("-")[0]


def _scenario_value(scenario: str | None, run_type: str | None) -> str:
    if scenario:
        return scenario
    configured = os.environ.get("REDTEAMCI_SCENARIO")
    if configured:
        return configured
    if run_type and run_type.startswith("support_story"):
        return "support-story"
    return "unknown"


def _github_run_url() -> str:
    explicit = os.environ.get("GITHUB_RUN_URL")
    if explicit:
        return explicit
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if not repository or not run_id:
        return ""
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    return f"{server_url}/{repository}/actions/runs/{run_id}"


def _path_value(path: str | Path) -> str:
    return Path(path).as_posix()
