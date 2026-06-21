from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .patcher import load_trace_for_attack
from .redaction import redact_secrets


def load_trace(
    attack_id: str,
    *,
    traces_root: str | Path,
    run_id: str | None = None,
) -> dict[str, Any]:
    return load_trace_for_attack(attack_id, traces_root=traces_root, run_id=run_id)


def format_trace_timeline(trace: dict[str, Any]) -> str:
    safe_trace = redact_secrets(trace)
    lines = [
        f"RedTeamCI trace: {_value(safe_trace.get('attack_id'))} {_value(safe_trace.get('attack_name'))}",
        f"Run: {_value(safe_trace.get('run_id'))}",
        f"Status: {_value(safe_trace.get('status'))}",
        f"Outcome: {_value(safe_trace.get('outcome_reason'))}",
        f"Trace path: {_value(safe_trace.get('trace_path'))}",
    ]

    result_preview = _single_line(safe_trace.get("result_preview"))
    if result_preview:
        lines.append(f"Result preview: {_truncate(result_preview, 160)}")

    events = safe_trace.get("events", [])
    lines.append("Events:")
    if not isinstance(events, list) or not events:
        lines.append("  (none)")
        return "\n".join(lines)

    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            lines.append(f"{index}. - [info] event - {_truncate(_single_line(event), 120)}")
            continue
        lines.append(_format_event(index, event))

    return "\n".join(lines)


def _format_event(index: int, event: dict[str, Any]) -> str:
    timestamp = _value(event.get("timestamp"))
    severity = _value(event.get("severity", "info"))
    event_type = _value(event.get("type"))
    title = _value(event.get("title") or str(event_type).replace("_", " ").title())
    details = _event_details(event)
    suffix = f" | {' '.join(details)}" if details else ""
    return f"{index}. {timestamp} [{severity}] {event_type} - {title}{suffix}"


def _event_details(event: dict[str, Any]) -> list[str]:
    details: list[str] = []
    tool = event.get("tool")
    if tool:
        details.append(f"tool={_safe_atom(tool)}")

    args = event.get("args")
    if not isinstance(args, dict):
        args = {}

    path = args.get("path") or event.get("path")
    if path:
        details.append(f"path={_safe_atom(path)}")

    url = args.get("url") or event.get("url")
    if url:
        url_text = _single_line(url)
        details.append(f"url={_safe_atom(_truncate(url_text, 120))}")
        domain = urlparse(url_text).netloc
        if domain:
            details.append(f"domain={_safe_atom(domain)}")

    assertion = event.get("assertion")
    if isinstance(assertion, dict):
        assertion_type = assertion.get("type")
        if assertion_type:
            details.append(f"assertion={_safe_atom(assertion_type)}")
        assertion_tool = assertion.get("tool")
        if assertion_tool and not tool:
            details.append(f"tool={_safe_atom(assertion_tool)}")
        assertion_path = assertion.get("path")
        if assertion_path and not path:
            details.append(f"path={_safe_atom(assertion_path)}")
        if event.get("type") in {"assertion_passed", "assertion_failed"}:
            result = "passed" if event.get("type") == "assertion_passed" else "failed"
            details.append(f"assertion_result={result}")

    status = event.get("status")
    if status:
        details.append(f"status={_safe_atom(status)}")

    reason = event.get("reason")
    if reason:
        details.append(f"reason={_safe_atom(_truncate(_single_line(reason), 160))}")

    error = event.get("error")
    if error:
        details.append(f"error={_safe_atom(_truncate(_single_line(error), 120))}")

    return details


def _value(value: Any) -> str:
    text = _single_line(value)
    return text if text else "-"


def _single_line(value: Any) -> str:
    if value is None:
        return ""
    safe_value = redact_secrets(value)
    text = str(safe_value)
    return " ".join(text.split())


def _safe_atom(value: Any) -> str:
    text = _single_line(value)
    if not text:
        return "-"
    if any(char.isspace() for char in text):
        return repr(text)
    return text


def _truncate(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return value[: max_length - 3] + "..."
