from __future__ import annotations

from pathlib import Path
from typing import Any

from .paths import ROOT
from .redaction import redact_secrets

ANNOTATION_LEVELS = ("error", "warning", "notice")


def render_github_annotations(
    summary: dict[str, Any],
    *,
    level: str = "error",
) -> list[str]:
    if level not in ANNOTATION_LEVELS:
        raise ValueError(f"level must be one of: {', '.join(ANNOTATION_LEVELS)}")

    redacted = redact_secrets(summary)
    run_id = _text(redacted.get("run_id")) or "<run_id>"
    annotations = []
    for attack in redacted.get("attacks", []):
        if str(attack.get("status") or "").upper() != "FAIL":
            continue
        annotations.append(_annotation_line(attack, run_id=run_id, level=level))
    return annotations


def _annotation_line(attack: dict[str, Any], *, run_id: str, level: str) -> str:
    properties = []
    trace_file = _trace_file(attack.get("trace_path"))
    if trace_file:
        properties.append(("file", trace_file))
    properties.extend(
        [
            ("line", "1"),
            ("title", _title(attack)),
        ]
    )
    property_text = ",".join(
        f"{name}={_escape_property(value)}" for name, value in properties
    )
    message = _message(attack, run_id=run_id)
    return f"::{level} {property_text}::{_escape_data(message)}"


def _title(attack: dict[str, Any]) -> str:
    attack_id = _text(attack.get("id")) or "unknown"
    attack_name = _one_line(attack.get("name")) or attack_id
    label = attack_id if attack_name == attack_id else f"{attack_id} {attack_name}"
    return f"RedTeamCI failed: {label}"


def _message(attack: dict[str, Any], *, run_id: str) -> str:
    attack_id = _text(attack.get("id")) or "unknown"
    lines = [
        f"Reason: {_text(attack.get('reason')) or 'Attack failed'}",
        f"Source: {_one_line(attack.get('source')) or 'unknown'}",
        (
            "Blocked before execution: "
            f"{str(bool(attack.get('blocked_before_execution'))).lower()}"
        ),
        (
            "Dangerous tools attempted: "
            f"{_list_text(attack.get('dangerous_tools_attempted'))}"
        ),
        (
            "Dangerous tools blocked: "
            f"{_list_text(attack.get('dangerous_tools_blocked'))}"
        ),
    ]

    assertion_failures = _list_items(attack.get("assertion_failures"))
    if assertion_failures:
        lines.append("Assertion failures:")
        lines.extend(f"- {failure}" for failure in assertion_failures)

    lines.append(
        "Trace replay: "
        f"python -m redteamci.cli trace {attack_id} --run-id {run_id}"
    )
    return "\n".join(lines)


def _trace_file(trace_path: Any) -> str:
    raw = _text(trace_path).strip()
    if not raw:
        return ""
    try:
        path = Path(raw)
    except (TypeError, ValueError):
        return raw

    if path.is_absolute():
        for base in [ROOT, Path.cwd()]:
            try:
                return path.resolve().relative_to(base.resolve()).as_posix()
            except (OSError, ValueError):
                continue
    return path.as_posix()


def _list_text(value: Any) -> str:
    items = _list_items(value)
    return ", ".join(items) if items else "-"


def _list_items(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in (_one_line(item) for item in value) if item]
    text = _one_line(value)
    return [text] if text else []


def _one_line(value: Any) -> str:
    return " ".join(_text(value).splitlines()).strip()


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(redact_secrets(value))


def _escape_data(value: Any) -> str:
    return _text(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: Any) -> str:
    return _escape_data(value).replace(",", "%2C").replace(":", "%3A")
