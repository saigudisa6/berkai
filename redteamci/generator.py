from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import load_manifest_data
from .discovery import build_capability_profile
from .profile import SCHEMA_VERSION, build_agent_profile
from .templates import ASSERTION_REGISTRY, generated_attacks_for_capabilities


DEFAULT_PLAN_OUTPUT_DIR = Path(".redteamci")
DEFAULT_GENERATED_ATTACK_PACK = Path("attacks") / "generated_attacks.json"


def write_plan_outputs(
    *,
    config_path: str | Path,
    output_dir: str | Path = DEFAULT_PLAN_OUTPUT_DIR,
    attack_pack_path: str | Path | None = None,
    workspace: str | Path | None = None,
) -> dict[str, Path]:
    workspace_path = Path(workspace) if workspace is not None else Path.cwd()
    config = Path(config_path)
    manifest = load_manifest_data(config)

    agent_profile = build_agent_profile(manifest, base_dir=config.parent).to_dict()
    capability_profile = build_capability_profile(agent_profile).to_dict()
    attacks = generated_attacks_for_capabilities(capability_profile)

    output_root = _resolve_workspace_path(output_dir, workspace_path)
    generated_attack_pack = _resolve_workspace_path(
        attack_pack_path or _manifest_attack_pack(manifest),
        workspace_path,
    )
    attack_plan = build_attack_plan(
        agent_profile=agent_profile,
        capability_profile=capability_profile,
        attacks=attacks,
        generated_attack_pack=_display_path(generated_attack_pack, workspace_path),
    )

    output_root.mkdir(parents=True, exist_ok=True)
    generated_attack_pack.parent.mkdir(parents=True, exist_ok=True)

    agent_profile_path = output_root / "agent_profile.json"
    capability_profile_path = output_root / "capability_profile.json"
    attack_plan_path = output_root / "attack_plan.json"
    attack_plan_markdown_path = output_root / "attack_plan.md"

    _write_json(agent_profile_path, agent_profile)
    _write_json(capability_profile_path, capability_profile)
    _write_json(attack_plan_path, attack_plan)
    attack_plan_markdown_path.write_text(
        render_attack_plan_markdown(
            agent_profile=agent_profile,
            capability_profile=capability_profile,
            attack_plan=attack_plan,
            attacks=attacks,
        ),
        encoding="utf-8",
    )
    _write_json(generated_attack_pack, attacks)

    return {
        "agent_profile": agent_profile_path,
        "capability_profile": capability_profile_path,
        "attack_plan": attack_plan_path,
        "attack_plan_markdown": attack_plan_markdown_path,
        "generated_attack_pack": generated_attack_pack,
    }


def build_attack_plan(
    *,
    agent_profile: dict[str, Any],
    capability_profile: dict[str, Any],
    attacks: list[dict[str, Any]],
    generated_attack_pack: str,
) -> dict[str, Any]:
    agent = agent_profile.get("agent", {})
    if not isinstance(agent, dict):
        agent = {}
    return {
        "schema_version": SCHEMA_VERSION,
        "agent_id": str(agent.get("id", "agent")),
        "onboarding_level": int(agent.get("onboarding_level", 0) or 0),
        "assertion_registry": list(ASSERTION_REGISTRY),
        "risk_areas": list(capability_profile.get("risk_areas", [])),
        "categories": _categories(attacks),
        "generated_attack_pack": generated_attack_pack,
        "honesty": _honesty_block(int(agent.get("onboarding_level", 0) or 0)),
    }


def render_attack_plan_markdown(
    *,
    agent_profile: dict[str, Any],
    capability_profile: dict[str, Any],
    attack_plan: dict[str, Any],
    attacks: list[dict[str, Any]],
) -> str:
    agent = agent_profile.get("agent", {})
    if not isinstance(agent, dict):
        agent = {}
    capabilities = capability_profile.get("capabilities", {})
    if not isinstance(capabilities, dict):
        capabilities = {}

    lines = [
        "# RedTeamCI Generated Attack Plan",
        "",
        f"Agent: {agent.get('name', agent.get('id', 'agent'))}",
        f"Agent ID: {agent.get('id', 'agent')}",
        f"Adapter: {agent.get('adapter_kind', 'unknown')}",
        f"Onboarding level: {agent.get('onboarding_level', 0)}",
        "",
        "Only Level 2 agents can prove blocked-before-execution and deterministic red-to-green prevention. Level 0 agents are output-only. Level 1 agents can provide trace evidence and remediation proposals, but RedTeamCI cannot force blocking unless the agent uses the guarded gateway/SDK.",
        "",
        "## Capability Discovery",
        "",
    ]
    for name, enabled in capabilities.items():
        marker = "yes" if enabled else "no"
        lines.append(f"- {name}: {marker}")

    lines.extend(["", "## Risk Areas", ""])
    for risk in capability_profile.get("risk_areas", []):
        lines.append(f"- {risk}")

    lines.extend(
        [
            "",
            "## Generated Attacks",
            "",
            "| ID | Name | Assertion gates |",
            "| --- | --- | --- |",
        ]
    )
    for attack in attacks:
        assertions = ", ".join(
            assertion.get("type", "unknown")
            for assertion in attack.get("assertions", [])
            if isinstance(assertion, dict)
        )
        lines.append(f"| {attack['id']} | {attack['name']} | {assertions or '-'} |")

    lines.extend(
        [
            "",
            "## Output Artifacts",
            "",
            f"- Agent profile: .redteamci/agent_profile.json",
            f"- Capability profile: .redteamci/capability_profile.json",
            f"- Attack plan: .redteamci/attack_plan.json",
            f"- Generated attack pack: {attack_plan['generated_attack_pack']}",
            "",
        ]
    )
    return "\n".join(lines)


def _categories(attacks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    category_names = {
        "generated-pi-001": "Prompt Injection",
        "generated-exfil-001": "Secret Exfiltration",
        "generated-network-001": "Network Exfiltration",
        "generated-refund-001": "Refund Abuse",
        "generated-email-001": "Email Exfiltration",
        "generated-pii-001": "PII Leakage",
        "generated-safe-001": "Safe Behavior",
    }
    grouped: dict[str, list[str]] = {}
    for attack in attacks:
        category = category_names.get(str(attack.get("id")), "Generated")
        grouped.setdefault(category, []).append(str(attack.get("id")))
    return [
        {"name": name, "count": len(ids), "attack_ids": ids}
        for name, ids in grouped.items()
    ]


def _manifest_attack_pack(manifest: dict[str, Any]) -> Path:
    for key in ["generated_attack_pack", "attack_pack_output"]:
        value = manifest.get(key)
        if isinstance(value, str) and value.strip():
            return Path(value.strip())

    outputs = manifest.get("outputs")
    if isinstance(outputs, dict):
        value = outputs.get("generated_attack_pack")
        if isinstance(value, str) and value.strip():
            return Path(value.strip())

    plan = manifest.get("attack_plan")
    if isinstance(plan, dict):
        value = plan.get("generated_attack_pack")
        if isinstance(value, str) and value.strip():
            return Path(value.strip())

    return DEFAULT_GENERATED_ATTACK_PACK


def _resolve_workspace_path(path: str | Path, workspace: Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return workspace / candidate


def _display_path(path: Path, workspace: Path) -> str:
    try:
        return path.relative_to(workspace).as_posix()
    except ValueError:
        return path.as_posix()


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _honesty_block(onboarding_level: int) -> dict[str, str]:
    if onboarding_level == 2:
        return {
            "level": "Level 2 guarded tool gateway",
            "claim": "RedTeamCI can block unsafe guarded tool calls before execution.",
        }
    if onboarding_level == 1:
        return {
            "level": "Level 1 trace-reporting agent",
            "claim": "RedTeamCI can detect traced unsafe behavior and produce remediation evidence, but cannot force blocking.",
        }
    return {
        "level": "Level 0 output-only agent",
        "claim": "RedTeamCI can inspect final output only and cannot verify tool behavior.",
    }
