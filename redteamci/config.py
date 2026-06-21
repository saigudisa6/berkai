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
    "agent_command",
    "agent_entrypoint",
    "agent_cwd",
    "agent_timeout",
    "agent_max_stdout_bytes",
    "agent_max_stderr_bytes",
    "attacks",
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
    """Load RedTeamCI manifest values needed by existing run commands.

    This keeps the original flat manifest contract while also flattening the
    nested agent shape used by generated plan manifests.
    """
    path = Path(path)
    if not path.exists():
        return {}

    raw = load_manifest_data(path)
    manifest = _flatten_manifest(raw)
    return {key: value for key, value in manifest.items() if key in MANIFEST_KEYS}


def load_manifest_data(path: str | Path) -> dict[str, Any]:
    """Load the small YAML subset used by RedTeamCI manifests."""
    path = Path(path)
    if not path.exists():
        return {}
    raw = _parse_yaml_subset(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def _flatten_manifest(raw: dict[str, Any]) -> dict[str, str]:
    manifest: dict[str, str] = {}

    for key in [
        "agent",
        "agent_url",
        "command",
        "cwd",
        "timeout",
        "attacks",
        "guardrails",
        "regressions",
    ]:
        value = raw.get(key)
        normalized = _manifest_value(value)
        if normalized is not None:
            if key == "command":
                manifest["agent_command"] = normalized
            elif key == "cwd":
                manifest["agent_cwd"] = normalized
            elif key == "timeout":
                manifest["agent_timeout"] = normalized
            else:
                manifest[key] = normalized

    agent = raw.get("agent")
    if isinstance(agent, dict):
        adapter = (
            agent.get("adapter_kind")
            or agent.get("kind")
            or agent.get("type")
            or agent.get("adapter")
        )
        adapter_value = _manifest_value(adapter)
        if adapter_value is not None:
            manifest["agent"] = adapter_value
        endpoint = agent.get("endpoint") or agent.get("url") or agent.get("agent_url")
        endpoint_value = _manifest_value(endpoint)
        if endpoint_value is not None:
            manifest["agent_url"] = endpoint_value
        command_value = _manifest_value(agent.get("command"))
        if command_value is not None:
            manifest["agent_command"] = command_value
        entrypoint_value = _manifest_value(agent.get("entrypoint"))
        if entrypoint_value is not None:
            manifest["agent_entrypoint"] = entrypoint_value
        cwd_value = _manifest_value(
            agent.get("cwd")
            or agent.get("working_dir")
            or agent.get("working_directory")
            or agent.get("path")
            or agent.get("repo_path")
        )
        if cwd_value is not None:
            manifest["agent_cwd"] = cwd_value
        timeout_value = _manifest_value(agent.get("timeout"))
        if timeout_value is not None:
            manifest["agent_timeout"] = timeout_value
        max_stdout_value = _manifest_value(agent.get("max_stdout_bytes"))
        if max_stdout_value is not None:
            manifest["agent_max_stdout_bytes"] = max_stdout_value
        max_stderr_value = _manifest_value(agent.get("max_stderr_bytes"))
        if max_stderr_value is not None:
            manifest["agent_max_stderr_bytes"] = max_stderr_value

    paths = raw.get("paths")
    if isinstance(paths, dict):
        for key in ["attacks", "guardrails", "regressions"]:
            value = paths.get(key)
            normalized = _manifest_value(value)
            if normalized is not None:
                manifest[key] = normalized
    return manifest


def _manifest_value(value: Any) -> str | None:
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return json.dumps(value)
    return None


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


def _parse_yaml_subset(text: str) -> Any:
    lines = _yaml_lines(text)
    if not lines:
        return {}
    value, _ = _parse_yaml_node(lines, 0, lines[0][0])
    return value


def _yaml_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        lines.append((indent, raw_line.strip()))
    return lines


def _parse_yaml_node(
    lines: list[tuple[int, str]],
    index: int,
    indent: int,
) -> tuple[Any, int]:
    if lines[index][1].startswith("- "):
        return _parse_yaml_sequence(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(
    lines: list[tuple[int, str]],
    index: int,
    indent: int,
) -> tuple[dict[str, Any], int]:
    data: dict[str, Any] = {}
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            break
        if content.startswith("- ") or ":" not in content:
            break

        key, raw_value = content.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        index += 1

        if raw_value:
            data[key] = _parse_scalar(raw_value)
            continue

        if index < len(lines) and lines[index][0] > indent:
            data[key], index = _parse_yaml_node(lines, index, lines[index][0])
        else:
            data[key] = {}
    return data, index


def _parse_yaml_sequence(
    lines: list[tuple[int, str]],
    index: int,
    indent: int,
) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent or not content.startswith("- "):
            break

        item_text = content[2:].strip()
        index += 1

        if not item_text:
            if index < len(lines) and lines[index][0] > indent:
                item, index = _parse_yaml_node(lines, index, lines[index][0])
                items.append(item)
            else:
                items.append("")
            continue

        if _looks_like_inline_mapping(item_text):
            key, raw_value = item_text.split(":", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            item: dict[str, Any] = {}
            if raw_value:
                item[key] = _parse_scalar(raw_value)
            elif index < len(lines) and lines[index][0] > indent:
                item[key], index = _parse_yaml_node(lines, index, lines[index][0])
            else:
                item[key] = {}

            if index < len(lines) and lines[index][0] > indent:
                continuation, index = _parse_yaml_mapping(lines, index, lines[index][0])
                item.update(continuation)
            items.append(item)
            continue

        items.append(_parse_scalar(item_text))
    return items, index


def _looks_like_inline_mapping(value: str) -> bool:
    if ":" not in value:
        return False
    prefix, _ = value.split(":", 1)
    return bool(prefix.strip()) and " " not in prefix.strip()


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        return _unquote_scalar(value)
    lowered = value.lower()
    if lowered in {"null", "none"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.startswith("[") and value.endswith("]"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            inner = value[1:-1].strip()
            if not inner:
                return []
            return [_parse_scalar(item.strip()) for item in inner.split(",")]
    if value.lstrip("-").isdigit():
        try:
            return int(value)
        except ValueError:
            pass
    return value
