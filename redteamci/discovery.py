from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .profile import SCHEMA_VERSION


@dataclass(frozen=True)
class CapabilityProfile:
    schema_version: str
    agent_id: str
    adapter_kind: str
    onboarding_level: int
    capabilities: dict[str, bool]
    risk_areas: list[str]
    evidence: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_capability_profile(agent_profile: dict[str, Any]) -> CapabilityProfile:
    agent = agent_profile.get("agent", {})
    if not isinstance(agent, dict):
        agent = {}
    tools = agent_profile.get("tools", [])
    if not isinstance(tools, list):
        tools = []
    sensitive_resources = agent_profile.get("sensitive_resources", [])
    if not isinstance(sensitive_resources, list):
        sensitive_resources = []

    tool_descriptors = [_normalize_tool(item) for item in tools]
    names_and_categories = " ".join(
        f"{tool['name']} {tool['category']}" for tool in tool_descriptors
    ).lower()
    sensitive_blob = " ".join(str(item) for item in sensitive_resources).lower()

    evidence: list[dict[str, str]] = []
    capabilities = {
        "can_browse_web": _has_any(names_and_categories, ["visit_url", "browser", "web", "url"]),
        "can_read_files": _has_any(names_and_categories, ["read_file", "filesystem", "file"]),
        "can_post_network": _has_any(names_and_categories, ["http_post", "network", "post"]),
        "can_send_email": _has_any(names_and_categories, ["email", "send_mail"]),
        "can_issue_refunds": _has_any(names_and_categories, ["refund", "payment", "stripe"]),
        "handles_sensitive_data": bool(sensitive_resources),
        "handles_secrets": _has_any(
            sensitive_blob,
            ["secret", "token", "api_key", "password", ".env", "key"],
        ),
        "uses_guarded_gateway": int(agent.get("onboarding_level", 0) or 0) == 2,
    }

    for tool in tool_descriptors:
        _add_tool_evidence(tool, capabilities, evidence)
    for resource in sensitive_resources:
        evidence.append(
            {
                "source": "declared_sensitive_resource",
                "value": str(resource),
                "reason": "Manifest declares sensitive data or secret material.",
            }
        )

    risk_areas = _risk_areas(capabilities)
    if not evidence:
        evidence.append(
            {
                "source": "manifest",
                "value": "no declared tools",
                "reason": "No tool schema was declared; generated plan is limited to output-only checks.",
            }
        )

    return CapabilityProfile(
        schema_version=SCHEMA_VERSION,
        agent_id=str(agent.get("id", "agent")),
        adapter_kind=str(agent.get("adapter_kind", "unknown")),
        onboarding_level=int(agent.get("onboarding_level", 0) or 0),
        capabilities=capabilities,
        risk_areas=risk_areas,
        evidence=evidence,
    )


def _normalize_tool(item: Any) -> dict[str, str]:
    if not isinstance(item, dict):
        return {"name": str(item), "category": "tool", "description": ""}
    return {
        "name": str(item.get("name", "")),
        "category": str(item.get("category", "tool")),
        "description": str(item.get("description", "")),
    }


def _add_tool_evidence(
    tool: dict[str, str],
    capabilities: dict[str, bool],
    evidence: list[dict[str, str]],
) -> None:
    value = tool["name"]
    category = tool["category"]
    lower = f"{value} {category}".lower()
    checks = [
        ("can_browse_web", ["visit_url", "browser", "web", "url"], "Matched browsing capability heuristic."),
        ("can_read_files", ["read_file", "filesystem", "file"], "Matched filesystem capability heuristic."),
        ("can_post_network", ["http_post", "network", "post"], "Matched network posting capability heuristic."),
        ("can_send_email", ["email", "send_mail"], "Matched email capability heuristic."),
        ("can_issue_refunds", ["refund", "payment", "stripe"], "Matched refund/payment capability heuristic."),
    ]
    for capability, markers, reason in checks:
        if capabilities.get(capability) and _has_any(lower, markers):
            evidence.append(
                {
                    "source": "declared_tool",
                    "value": value,
                    "reason": reason,
                }
            )
            return


def _risk_areas(capabilities: dict[str, bool]) -> list[str]:
    risks: list[str] = []
    if capabilities["can_browse_web"]:
        risks.append("prompt_injection")
    if capabilities["can_read_files"] or capabilities["handles_secrets"]:
        risks.append("secret_exfiltration")
    if capabilities["can_post_network"]:
        risks.append("network_exfiltration")
    if capabilities["can_issue_refunds"]:
        risks.append("unauthorized_refund")
    if capabilities["can_send_email"]:
        risks.append("email_exfiltration")
    if capabilities["handles_sensitive_data"]:
        risks.append("sensitive_data_leakage")
    if any(capabilities[key] for key in ["can_read_files", "can_post_network", "can_send_email", "can_issue_refunds"]):
        risks.append("tool_abuse")
    return _dedupe(risks) or ["output_safety"]


def _has_any(value: str, markers: list[str]) -> bool:
    return any(marker in value for marker in markers)


def _dedupe(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
