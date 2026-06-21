from __future__ import annotations

import json
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any

from .generator import write_plan_outputs
from .paths import ROOT


UPLOADED_AGENT_RELATIVE_ROOT = Path(".redteamci") / "uploaded-agent"
UPLOADED_SOURCE_DIR = "source"
UPLOADED_PLAN_DIR = "plan"
UPLOADED_ATTACK_PACK = "generated_attacks.json"
UPLOADED_SUBMISSION_FILE = "submission.json"
UPLOADED_RED_SUMMARY = "red_summary.json"
UPLOADED_TRACE_DIR = "traces"
MANIFEST_CANDIDATES = (
    "redteamci.agent.yaml",
    "redteamci.agent.yml",
    "redteamci.yaml",
    "redteamci.yml",
)


class UploadedAgentError(ValueError):
    pass


def ingest_uploaded_agent(
    filename: str,
    content: bytes,
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    root = Path(root)
    upload_root = root / UPLOADED_AGENT_RELATIVE_ROOT
    source_root = upload_root / UPLOADED_SOURCE_DIR
    if upload_root.exists():
        shutil.rmtree(upload_root)
    source_root.mkdir(parents=True, exist_ok=True)

    safe_name = _safe_filename(filename)
    if not safe_name:
        raise UploadedAgentError("Uploaded file needs a filename.")

    manifest_path, detected_format = _stage_upload(source_root, safe_name, content)
    plan_dir = upload_root / UPLOADED_PLAN_DIR
    attack_pack = upload_root / UPLOADED_ATTACK_PACK
    paths = write_plan_outputs(
        config_path=manifest_path,
        output_dir=plan_dir,
        attack_pack_path=attack_pack,
        workspace=root,
    )

    submission = {
        "filename": safe_name,
        "detected_format": detected_format,
        "manifest_path": str(manifest_path),
        "upload_root": str(upload_root),
        "source_root": str(source_root),
        "plan_dir": str(plan_dir),
        "attack_pack_path": str(attack_pack),
        "traces_root": str(upload_root / UPLOADED_TRACE_DIR),
        "summary_path": str(upload_root / UPLOADED_RED_SUMMARY),
        "plan_paths": {key: str(path) for key, path in paths.items()},
    }
    (upload_root / UPLOADED_SUBMISSION_FILE).write_text(
        json.dumps(submission, indent=2) + "\n",
        encoding="utf-8",
    )
    return load_uploaded_agent_state(root)


def load_uploaded_agent_state(root: Path = ROOT) -> dict[str, Any]:
    root = Path(root)
    upload_root = root / UPLOADED_AGENT_RELATIVE_ROOT
    submission = _load_json_object(upload_root / UPLOADED_SUBMISSION_FILE)
    if not submission:
        return _empty_state()

    agent_profile = _load_json_object(upload_root / UPLOADED_PLAN_DIR / "agent_profile.json")
    capability_profile = _load_json_object(
        upload_root / UPLOADED_PLAN_DIR / "capability_profile.json"
    )
    attack_plan = _load_json_object(upload_root / UPLOADED_PLAN_DIR / "attack_plan.json")
    attack_pack = _load_json(upload_root / UPLOADED_ATTACK_PACK)
    red_summary = _load_json_object(upload_root / UPLOADED_RED_SUMMARY)
    if not isinstance(attack_pack, list):
        attack_pack = []

    agent = agent_profile.get("agent", {}) if isinstance(agent_profile, dict) else {}
    if not isinstance(agent, dict):
        agent = {}
    capabilities = (
        capability_profile.get("capabilities", {})
        if isinstance(capability_profile, dict)
        else {}
    )
    if not isinstance(capabilities, dict):
        capabilities = {}
    tools = agent_profile.get("tools", []) if isinstance(agent_profile, dict) else []
    if not isinstance(tools, list):
        tools = []
    onboarding_level = _safe_int(
        agent.get("onboarding_level"),
        capability_profile.get("onboarding_level") if capability_profile else None,
        attack_plan.get("onboarding_level") if attack_plan else None,
    )
    command = agent.get("command")
    endpoint = agent.get("endpoint")

    return {
        "available": True,
        "submission": submission,
        "agent_profile": agent_profile,
        "capability_profile": capability_profile,
        "attack_plan": attack_plan,
        "attack_pack": attack_pack,
        "red_summary": red_summary,
        "agent": {
            "id": str(agent.get("id") or capability_profile.get("agent_id") or "agent"),
            "name": str(agent.get("name") or agent.get("id") or "Uploaded agent"),
            "adapter_kind": str(agent.get("adapter_kind") or "unknown"),
            "onboarding_level": onboarding_level,
            "command": command,
            "endpoint": endpoint,
        },
        "proof_level": _proof_level(onboarding_level, capabilities),
        "capabilities": [
            {"name": name, "enabled": bool(enabled)}
            for name, enabled in capabilities.items()
        ],
        "tools": tools,
        "risk_areas": list(capability_profile.get("risk_areas", []))
        if isinstance(capability_profile, dict)
        else [],
        "attack_ids": [str(attack.get("id")) for attack in attack_pack if isinstance(attack, dict)],
        "runnable": bool(command or endpoint),
    }


def uploaded_agent_run_args(state: dict[str, Any]) -> list[str]:
    submission = state.get("submission") if isinstance(state, dict) else {}
    if not isinstance(submission, dict):
        submission = {}
    manifest_path = submission.get("manifest_path")
    attack_pack_path = submission.get("attack_pack_path")
    traces_root = submission.get("traces_root")
    summary_path = submission.get("summary_path")
    if not all(isinstance(value, str) and value for value in [manifest_path, attack_pack_path]):
        raise UploadedAgentError("Uploaded agent does not have a generated runnable plan.")
    args = [
        "run",
        "--config",
        manifest_path,
        "--attacks",
        attack_pack_path,
    ]
    if isinstance(traces_root, str) and traces_root:
        args.extend(["--traces-root", traces_root])
    if isinstance(summary_path, str) and summary_path:
        args.extend(["--summary", summary_path])
    attack_ids = state.get("attack_ids")
    if isinstance(attack_ids, list):
        for attack_id in attack_ids:
            if isinstance(attack_id, str) and attack_id:
                args.extend(["--attack", attack_id])
    return args


def _stage_upload(source_root: Path, filename: str, content: bytes) -> tuple[Path, str]:
    suffix = Path(filename).suffix.lower()
    if suffix == ".zip":
        zip_path = source_root / filename
        zip_path.write_bytes(content)
        extracted_root = source_root / "bundle"
        extracted_root.mkdir(parents=True, exist_ok=True)
        _safe_extract_zip(zip_path, extracted_root)
        manifest_path = _find_manifest(extracted_root)
        if manifest_path:
            return manifest_path, "zip manifest bundle"
        inferred = _infer_manifest_for_directory(extracted_root)
        manifest_path = source_root / "redteamci.inferred.yaml"
        manifest_path.write_text(_dump_yaml(inferred), encoding="utf-8")
        return manifest_path, "zip inferred bundle"

    path = source_root / filename
    path.write_bytes(content)
    if suffix in {".yaml", ".yml"}:
        return path, "manifest"
    if suffix == ".json":
        manifest = _manifest_from_json(path)
        manifest_path = source_root / "redteamci.inferred.yaml"
        manifest_path.write_text(_dump_yaml(manifest), encoding="utf-8")
        return manifest_path, "json inferred manifest"
    inferred = _infer_manifest_for_file(path)
    manifest_path = source_root / "redteamci.inferred.yaml"
    manifest_path.write_text(_dump_yaml(inferred), encoding="utf-8")
    return manifest_path, "single-file inferred manifest"


def _safe_extract_zip(zip_path: Path, target: Path) -> None:
    target_resolved = target.resolve()
    try:
        with zipfile.ZipFile(zip_path) as archive:
            for member in archive.infolist():
                destination = (target / member.filename).resolve()
                if not _is_relative_to(destination, target_resolved):
                    raise UploadedAgentError(f"Unsafe zip path: {member.filename}")
            archive.extractall(target)
    except zipfile.BadZipFile as exc:
        raise UploadedAgentError("Uploaded zip file could not be read.") from exc


def _find_manifest(root: Path) -> Path | None:
    names = {name.lower() for name in MANIFEST_CANDIDATES}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name.lower() in names:
            return path
    return None


def _manifest_from_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise UploadedAgentError("Uploaded JSON was not valid.") from exc
    if not isinstance(data, dict):
        raise UploadedAgentError("Uploaded JSON must be an object.")
    if "agent" in data or "tools" in data:
        return data
    if "openapi" in data or "swagger" in data:
        return _manifest_from_openapi(data)
    return _generic_manifest(path.name, "json")


def _manifest_from_openapi(data: dict[str, Any]) -> dict[str, Any]:
    title = (
        data.get("info", {}).get("title")
        if isinstance(data.get("info"), dict)
        else "Uploaded OpenAPI Agent"
    )
    tools: list[dict[str, str]] = []
    paths = data.get("paths")
    if isinstance(paths, dict):
        for route, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if not isinstance(operation, dict):
                    continue
                name = (
                    operation.get("operationId")
                    or operation.get("summary")
                    or f"{method}_{route}"
                )
                tools.append(
                    {
                        "name": _slug(str(name)),
                        "category": _tool_category(str(name)),
                        "description": f"{method.upper()} {route}",
                    }
                )
    return {
        "schema_version": "0.1",
        "agent": {
            "id": _slug(str(title)),
            "name": str(title),
            "type": "http",
            "onboarding_level": 1,
            "trace_reporting": True,
            "description": "Inferred from an uploaded OpenAPI description.",
        },
        "tools": tools,
    }


def _infer_manifest_for_directory(root: Path) -> dict[str, Any]:
    for filename in ["agent.py", "main.py", "app.py"]:
        path = root / filename
        if path.exists():
            return _cli_manifest(path.name, f"Uploaded {path.stem} agent", cwd=".")
    for path in sorted(root.rglob("*.py")):
        return _cli_manifest(str(path.relative_to(root)), f"Uploaded {path.stem} agent", cwd=".")
    return _generic_manifest(root.name, "zip")


def _infer_manifest_for_file(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return _cli_manifest(path.name, f"Uploaded {path.stem} agent", cwd=".")
    if suffix in {".js", ".mjs"}:
        return _cli_manifest(path.name, f"Uploaded {path.stem} agent", cwd=".", runtime="node")
    if suffix in {".har", ".jsonl"}:
        return {
            "schema_version": "0.1",
            "agent": {
                "id": _slug(path.stem),
                "name": f"Uploaded {path.stem} trace",
                "type": "trace",
                "onboarding_level": 1,
                "trace_reporting": True,
                "description": "Trace-only upload; RedTeamCI can generate a limited plan.",
            },
            "tools": [],
        }
    return _generic_manifest(path.name, suffix.lstrip(".") or "file")


def _cli_manifest(
    command_path: str,
    name: str,
    *,
    cwd: str | None = None,
    runtime: str = "python",
) -> dict[str, Any]:
    agent: dict[str, Any] = {
        "id": _slug(name),
        "name": name,
        "type": "cli",
        "onboarding_level": 1,
        "trace_reporting": True,
        "command": [runtime, command_path],
        "timeout": 10,
        "description": "Inferred CLI agent. Declare tools for stronger generated tests.",
    }
    if cwd:
        agent["cwd"] = cwd
    return {"schema_version": "0.1", "agent": agent, "tools": []}


def _generic_manifest(name: str, source_type: str) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "agent": {
            "id": _slug(name),
            "name": f"Uploaded {name}",
            "type": source_type or "unknown",
            "onboarding_level": 0,
            "trace_reporting": False,
            "description": "No executable adapter or tool schema was detected.",
        },
        "tools": [],
    }


def _proof_level(onboarding_level: int, capabilities: dict[str, bool]) -> dict[str, str]:
    if onboarding_level >= 2 and capabilities.get("uses_guarded_gateway"):
        return {
            "label": "Level 2 guarded gateway",
            "tone": "success",
            "message": "Can prove blocked-before-execution for guarded tools.",
        }
    if onboarding_level >= 1:
        return {
            "label": "Level 1 trace/run mode",
            "tone": "warning",
            "message": (
                "Can run attacks and collect traces, but cannot prove blocking "
                "without a guarded gateway."
            ),
        }
    return {
        "label": "Level 0 plan-only",
        "tone": "info",
        "message": "Can generate output-safety tests, but no tool blocking proof is available.",
    }


def _dump_yaml(value: Any, indent: int = 0) -> str:
    return "\n".join(_dump_yaml_lines(value, indent)) + "\n"


def _dump_yaml_lines(value: Any, indent: int = 0) -> list[str]:
    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_dump_yaml_lines(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict):
                lines.append(f"{prefix}-")
                lines.extend(_dump_yaml_lines(item, indent + 2))
            elif isinstance(item, list):
                lines.append(f"{prefix}-")
                lines.extend(_dump_yaml_lines(item, indent + 2))
            else:
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
        return lines
    return [f"{prefix}{_yaml_scalar(value)}"]


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps("" if value is None else str(value))


def _safe_filename(filename: str) -> str:
    name = Path(filename).name
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-")


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "uploaded-agent"


def _tool_category(value: str) -> str:
    lower = value.lower()
    if any(marker in lower for marker in ["refund", "payment", "stripe"]):
        return "payment"
    if "email" in lower:
        return "email"
    if any(marker in lower for marker in ["customer", "pii", "user"]):
        return "customer_data"
    if any(marker in lower for marker in ["file", "read"]):
        return "filesystem"
    if any(marker in lower for marker in ["http", "post", "web"]):
        return "network"
    return "tool"


def _safe_int(*values: Any) -> int:
    for value in values:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        return max(0, min(2, parsed))
    return 0


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _load_json_object(path: Path) -> dict[str, Any]:
    value = _load_json(path)
    return value if isinstance(value, dict) else {}


def _empty_state() -> dict[str, Any]:
    return {
        "available": False,
        "submission": {},
        "agent": {
            "id": "agent",
            "name": "No uploaded agent",
            "adapter_kind": "unknown",
            "onboarding_level": 0,
        },
        "proof_level": _proof_level(0, {}),
        "capabilities": [],
        "tools": [],
        "risk_areas": [],
        "attack_ids": [],
        "attack_pack": [],
        "runnable": False,
    }


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
