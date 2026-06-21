from __future__ import annotations

import shlex
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import load_manifest_data


SCHEMA_VERSION = "0.1"


@dataclass(frozen=True)
class AgentDescriptor:
    id: str
    name: str
    adapter_kind: str
    onboarding_level: int
    command: list[str] | None
    endpoint: str | None
    repo_path: str | None
    entrypoint: str | None
    description: str


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    category: str
    description: str


@dataclass(frozen=True)
class AgentProfile:
    schema_version: str
    agent: AgentDescriptor
    tools: list[ToolDescriptor]
    sensitive_resources: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_agent_profile(config_path: str | Path) -> dict[str, Any]:
    path = Path(config_path)
    raw = load_manifest_data(path)
    return build_agent_profile(raw, base_dir=path.parent).to_dict()


def build_agent_profile(
    manifest: dict[str, Any],
    *,
    base_dir: str | Path | None = None,
) -> AgentProfile:
    agent_raw = manifest.get("agent")
    agent_map = agent_raw if isinstance(agent_raw, dict) else {}
    adapter_kind = _normalize_adapter_kind(
        _first_string(
            agent_map.get("adapter_kind"),
            agent_map.get("kind"),
            agent_map.get("type"),
            agent_map.get("adapter"),
            agent_raw if isinstance(agent_raw, str) else None,
        )
        or "builtin"
    )
    agent_id = _slug(
        _first_string(agent_map.get("id"), agent_map.get("name"))
        or f"{adapter_kind}-agent"
    )
    name = _first_string(agent_map.get("name"), agent_map.get("id")) or agent_id
    description = _first_string(
        agent_map.get("description"),
        manifest.get("description"),
    ) or _default_description(adapter_kind)
    onboarding_level = _onboarding_level(agent_map, adapter_kind)
    command = _normalize_command(agent_map.get("command") or manifest.get("command"))
    endpoint = _first_string(
        agent_map.get("endpoint"),
        agent_map.get("url"),
        agent_map.get("agent_url"),
        manifest.get("agent_url"),
    )
    repo_path = _resolve_optional_path(agent_map.get("repo_path"), base_dir)
    entrypoint = _first_string(agent_map.get("entrypoint"))

    tools = _tools(manifest, adapter_kind)
    sensitive_resources = _sensitive_resources(manifest, adapter_kind)

    return AgentProfile(
        schema_version=SCHEMA_VERSION,
        agent=AgentDescriptor(
            id=agent_id,
            name=name,
            adapter_kind=adapter_kind,
            onboarding_level=onboarding_level,
            command=command,
            endpoint=endpoint,
            repo_path=repo_path,
            entrypoint=entrypoint,
            description=description,
        ),
        tools=tools,
        sensitive_resources=sensitive_resources,
    )


def _normalize_adapter_kind(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    if normalized == "http-demo":
        return "http"
    if normalized in {"builtin", "http", "cli", "docker", "repo"}:
        return normalized
    return normalized or "builtin"


def _onboarding_level(agent: dict[str, Any], adapter_kind: str) -> int:
    explicit = agent.get("onboarding_level")
    if isinstance(explicit, int):
        return max(0, min(2, explicit))
    if isinstance(explicit, str) and explicit.strip().isdigit():
        return max(0, min(2, int(explicit.strip())))
    if bool(agent.get("uses_guarded_gateway")) or adapter_kind == "builtin":
        return 2
    if agent.get("trace_reporting") is False:
        return 0
    if adapter_kind in {"http", "cli", "docker", "repo"}:
        return 1
    return 0


def _tools(manifest: dict[str, Any], adapter_kind: str) -> list[ToolDescriptor]:
    raw_tools = manifest.get("tools")
    tools: list[ToolDescriptor] = []
    if isinstance(raw_tools, list):
        for item in raw_tools:
            tool = _tool_from_item(item)
            if tool:
                tools.append(tool)
    elif isinstance(raw_tools, dict):
        for name, item in raw_tools.items():
            tool = _tool_from_item({"name": name, **item} if isinstance(item, dict) else name)
            if tool:
                tools.append(tool)

    if tools:
        return _dedupe_tools(tools)
    if adapter_kind == "builtin":
        return [
            ToolDescriptor(
                name="read_file",
                category="filesystem",
                description="Reads files through the RedTeamCI guarded tool gateway.",
            ),
            ToolDescriptor(
                name="list_files",
                category="filesystem",
                description="Lists files through the RedTeamCI guarded tool gateway.",
            ),
            ToolDescriptor(
                name="visit_url",
                category="browser",
                description="Loads a fixture webpage through the guarded tool gateway.",
            ),
            ToolDescriptor(
                name="http_post",
                category="network",
                description="Posts data through the guarded tool gateway.",
            ),
        ]
    return []


def _tool_from_item(item: Any) -> ToolDescriptor | None:
    if isinstance(item, str):
        name = item.strip()
        if not name:
            return None
        return ToolDescriptor(name=name, category=_category_for_tool(name), description="")
    if not isinstance(item, dict):
        return None
    name = _first_string(item.get("name"))
    if not name:
        return None
    category = _first_string(item.get("category")) or _category_for_tool(name)
    description = _first_string(item.get("description")) or ""
    return ToolDescriptor(name=name, category=category, description=description)


def _dedupe_tools(tools: list[ToolDescriptor]) -> list[ToolDescriptor]:
    deduped: list[ToolDescriptor] = []
    seen: set[str] = set()
    for tool in tools:
        if tool.name in seen:
            continue
        seen.add(tool.name)
        deduped.append(tool)
    return deduped


def _category_for_tool(name: str) -> str:
    lower = name.lower()
    if any(marker in lower for marker in ["read", "file", "list"]):
        return "filesystem"
    if any(marker in lower for marker in ["url", "browser", "web", "http_get"]):
        return "browser"
    if any(marker in lower for marker in ["post", "network", "http"]):
        return "network"
    if "email" in lower:
        return "email"
    if any(marker in lower for marker in ["refund", "payment", "stripe"]):
        return "payment"
    return "tool"


def _sensitive_resources(manifest: dict[str, Any], adapter_kind: str) -> list[str]:
    values = _string_list(manifest.get("sensitive_resources"))
    if not values:
        values = _string_list(manifest.get("secrets"))
    if values:
        return _dedupe_strings(values)
    if adapter_kind == "builtin":
        return [".env", "OPENAI_API_KEY", "DB_PASSWORD", "SECRET_KEY"]
    return []


def _normalize_command(value: Any) -> list[str] | None:
    if isinstance(value, list):
        command = [str(item) for item in value if str(item).strip()]
        return command or None
    if isinstance(value, str) and value.strip():
        return shlex.split(value)
    return None


def _resolve_optional_path(value: Any, base_dir: str | Path | None) -> str | None:
    raw = _first_string(value)
    if not raw:
        return None
    path = Path(raw)
    if path.is_absolute() or base_dir is None:
        return str(path)
    return str(Path(base_dir) / path)


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _first_string(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _slug(value: str) -> str:
    lowered = value.strip().lower()
    chars = [char if char.isalnum() else "-" for char in lowered]
    slug = "-".join(part for part in "".join(chars).split("-") if part)
    return slug or "agent"


def _default_description(adapter_kind: str) -> str:
    if adapter_kind == "builtin":
        return "RedTeamCI built-in Level 2 demo agent using the guarded tool gateway."
    return f"RedTeamCI {adapter_kind} agent."
