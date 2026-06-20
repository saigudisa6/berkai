from __future__ import annotations

import json
from pathlib import Path
from typing import Any


GUARDRAIL_KEYS = [
    "allowed_tools",
    "denied_file_patterns",
    "denied_domains",
    "denied_secret_patterns",
    "require_human_approval",
]

MANIFEST_KEYS = [
    "agent",
    "agent_url",
    "guardrails",
    "regressions",
]


def normalize_guardrails(raw: dict[str, Any] | None) -> dict[str, list[str]]:
    guardrails: dict[str, list[str]] = {}
    raw = raw or {}
    for key in GUARDRAIL_KEYS:
        value = raw.get(key, [])
        if value is None:
            value = []
        if isinstance(value, str):
            value = [value]
        guardrails[key] = [str(item) for item in value]
    return guardrails


def load_guardrails(path: str | Path) -> dict[str, list[str]]:
    """Load the small YAML subset used by RedTeamCI guardrail files."""
    path = Path(path)
    if not path.exists():
        return normalize_guardrails({})

    data: dict[str, list[str]] = {}
    current_key: str | None = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if not raw_line.startswith(" ") and stripped.endswith(":"):
            current_key = stripped[:-1]
            data.setdefault(current_key, [])
            continue

        if current_key and stripped.startswith("- "):
            value = stripped[2:].strip()
            data.setdefault(current_key, []).append(_unquote_scalar(value))

    return normalize_guardrails(data)


def load_manifest(path: str | Path) -> dict[str, str]:
    """Load the tiny scalar YAML subset used by redteamci.yml."""
    path = Path(path)
    if not path.exists():
        return {}

    manifest: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        if key not in MANIFEST_KEYS:
            continue
        manifest[key] = _unquote_scalar(value.strip())
    return manifest


def dump_guardrails(guardrails: dict[str, Any]) -> str:
    normalized = normalize_guardrails(guardrails)
    lines: list[str] = []
    for key in GUARDRAIL_KEYS:
        lines.append(f"{key}:")
        values = normalized.get(key, [])
        if values:
            lines.extend(f"  - {_quote_scalar(value)}" for value in values)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_guardrails(path: str | Path, guardrails: dict[str, Any]) -> None:
    Path(path).write_text(dump_guardrails(guardrails), encoding="utf-8")


def merge_guardrail_patch(
    current: dict[str, Any],
    patch: dict[str, Any],
) -> dict[str, list[str]]:
    merged = normalize_guardrails(current)
    normalized_patch = normalize_guardrails(patch)
    for key in GUARDRAIL_KEYS:
        seen = set(merged[key])
        for value in normalized_patch[key]:
            if value not in seen:
                merged[key].append(value)
                seen.add(value)
    return merged


def _quote_scalar(value: str) -> str:
    return json.dumps(value)


def _unquote_scalar(value: str) -> str:
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value.strip("'\"")
    return value
