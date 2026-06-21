from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

from .agent import run_agent


DEFAULT_HTTP_DEMO_URL = "http://127.0.0.1:8765/run"
DEFAULT_CLI_TIMEOUT_SECONDS = 10
DEFAULT_MAX_STDOUT_BYTES = 64 * 1024
DEFAULT_MAX_STDERR_BYTES = 16 * 1024


class AgentAdapterError(RuntimeError):
    pass


class HTTPAgentError(AgentAdapterError):
    pass


class CLIAgentError(AgentAdapterError):
    pass


@dataclass(frozen=True)
class AgentConfig:
    kind: str = "builtin"
    name: str | None = None
    url: str | None = None
    command: str | list[str] | tuple[str, ...] | None = None
    cwd: str | None = None
    timeout: int = DEFAULT_CLI_TIMEOUT_SECONDS
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        if self.kind == "http":
            return f"http:{self.url or DEFAULT_HTTP_DEMO_URL}"
        if self.kind == "cli":
            return f"cli:{_format_command(self.command)}"
        if self.kind == "repo":
            return f"repo:{self.cwd or '.'}:{_format_command(self.command)}"
        return self.kind


def run_agent_with_config(
    task: str,
    guardrails: dict[str, list[str]],
    recorder: Any,
    config: AgentConfig,
    *,
    run_id: str | None = None,
    attack_id: str | None = None,
    attack_name: str | None = None,
) -> Any:
    if config.kind == "builtin":
        return run_agent(task, guardrails, recorder)
    if config.kind == "http":
        return run_http_agent(task, recorder, config.url or DEFAULT_HTTP_DEMO_URL)
    if config.kind == "cli":
        return run_cli_agent(
            task,
            recorder,
            config.command,
            timeout=config.timeout,
            cwd=config.cwd,
            max_stdout_bytes=config.max_stdout_bytes,
            max_stderr_bytes=config.max_stderr_bytes,
            run_id=run_id or getattr(recorder, "run_id", None),
            attack_id=attack_id or getattr(recorder, "attack_id", None),
            attack_name=attack_name or getattr(recorder, "attack_name", None),
            guardrails=guardrails,
        )
    if config.kind == "repo":
        return run_cli_agent(
            task,
            recorder,
            config.command,
            timeout=config.timeout,
            cwd=config.cwd,
            max_stdout_bytes=config.max_stdout_bytes,
            max_stderr_bytes=config.max_stderr_bytes,
            run_id=run_id or getattr(recorder, "run_id", None),
            attack_id=attack_id or getattr(recorder, "attack_id", None),
            attack_name=attack_name or getattr(recorder, "attack_name", None),
            guardrails=guardrails,
        )
    raise ValueError(f"Unsupported agent kind: {config.kind}")


def run_http_agent(task: str, recorder: Any, url: str) -> Any:
    data = call_http_agent(task, url)
    output = data.get("output", "")
    events = data.get("events", [])
    recorder.log(
        "http_agent_response",
        {"url": url, "response_preview": json.dumps(data)[:500]},
        title="HTTP agent responded",
        severity="low",
    )
    if events:
        for event in events:
            recorder.log(
                str(event.get("type", "http_agent_event")),
                {key: value for key, value in event.items() if key != "type"},
                title=str(event.get("title", event.get("type", "HTTP agent event"))),
                severity=str(event.get("severity", "medium")),
            )
    else:
        recorder.log(
            "http_agent_output_only",
            {"url": url},
            title="HTTP agent returned no tool trace",
            severity="medium",
        )
    return output


def call_http_agent(task: str, url: str, *, timeout: int = 10) -> dict[str, Any]:
    payload = json.dumps({"task": task}).encode("utf-8")
    http_request = request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except TimeoutError as exc:
        raise HTTPAgentError(f"HTTP agent timed out after {timeout}s: {url}") from exc
    except error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise HTTPAgentError(f"HTTP agent is unreachable at {url}: {reason}") from exc

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPAgentError("HTTP agent response was not valid JSON.") from exc
    if not isinstance(data, dict):
        raise HTTPAgentError("HTTP agent response must be a JSON object.")

    output = data.get("output", "")
    if output is None:
        output = ""
    if not isinstance(output, str):
        output = str(output)
    data["output"] = output

    events = data.get("events", [])
    if events is None:
        events = []
    if not isinstance(events, list):
        raise HTTPAgentError("HTTP agent 'events' field must be a list when present.")
    for event in events:
        if not isinstance(event, dict):
            raise HTTPAgentError("HTTP agent events must be JSON objects.")
    data["events"] = events
    return data


def run_cli_agent(
    task: str,
    recorder: Any,
    command: str | list[str] | tuple[str, ...] | None,
    *,
    timeout: int,
    cwd: str | Path | None = None,
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
    run_id: str | None = None,
    attack_id: str | None = None,
    attack_name: str | None = None,
    guardrails: dict[str, list[str]] | None = None,
) -> Any:
    data = call_cli_agent(
        task,
        command,
        timeout=timeout,
        cwd=cwd,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        run_id=run_id,
        attack_id=attack_id,
        attack_name=attack_name,
        guardrails=guardrails,
    )
    output = data["output"]
    events = data.get("events", [])
    recorder.log(
        "cli_agent_response",
        {
            "command": _format_command(command),
            "cwd": str(cwd) if cwd else None,
            "response_preview": json.dumps(data)[:500],
        },
        title="CLI agent responded",
        severity="low",
    )
    if events:
        for event in events:
            recorder.log(
                str(event.get("type", "cli_agent_event")),
                {key: value for key, value in event.items() if key != "type"},
                title=str(event.get("title", event.get("type", "CLI agent event"))),
                severity=str(event.get("severity", "medium")),
            )
    else:
        recorder.log(
            "cli_agent_output_only",
            {"command": _format_command(command), "cwd": str(cwd) if cwd else None},
            title="CLI agent returned no tool trace",
            severity="medium",
        )
    return output


def call_cli_agent(
    task: str,
    command: str | list[str] | tuple[str, ...] | None,
    *,
    timeout: int,
    cwd: str | Path | None = None,
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
    run_id: str | None = None,
    attack_id: str | None = None,
    attack_name: str | None = None,
    guardrails: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    argv = normalize_command(command)
    if timeout is None or timeout <= 0:
        raise CLIAgentError("CLI agent timeout must be a positive number of seconds.")
    payload = {
        "task": task,
        "run_id": run_id,
        "attack_id": attack_id,
        "attack_name": attack_name,
        "guardrails": guardrails or {},
    }
    stdin = json.dumps(payload).encode("utf-8")
    try:
        completed = subprocess.run(
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            shell=False,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CLIAgentError(
            f"CLI agent timed out after {timeout}s: {_format_argv(argv)}"
        ) from exc
    except OSError as exc:
        raise CLIAgentError(f"CLI agent could not start: {_format_argv(argv)}: {exc}") from exc

    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if len(stdout) > max_stdout_bytes:
        raise CLIAgentError(
            "CLI agent stdout exceeded "
            f"{max_stdout_bytes} bytes: {_format_argv(argv)}"
        )
    if len(stderr) > max_stderr_bytes:
        stderr = stderr[:max_stderr_bytes] + b"\n[stderr truncated]\n"

    stderr_text = stderr.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        detail = f": {stderr_text}" if stderr_text else ""
        raise CLIAgentError(
            f"CLI agent exited with code {completed.returncode}: {_format_argv(argv)}{detail}"
        )

    try:
        body = stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CLIAgentError("CLI agent stdout was not valid UTF-8.") from exc
    return normalize_agent_response(body, adapter_name="CLI agent")


def check_http_agent(url: str, *, timeout: int = 3) -> tuple[bool, str]:
    try:
        call_http_agent("RedTeamCI doctor ping", url, timeout=timeout)
    except HTTPAgentError as exc:
        return False, str(exc)
    return True, f"HTTP agent reachable at {url}"


def check_cli_agent_config(config: AgentConfig) -> tuple[bool, str]:
    try:
        argv = normalize_command(config.command)
    except CLIAgentError as exc:
        return False, str(exc)

    cwd = Path(config.cwd) if config.cwd else None
    if cwd and not cwd.exists():
        return False, f"CLI agent cwd does not exist: {cwd}"
    if Path(argv[0]).is_absolute() or "/" in argv[0]:
        executable = Path(argv[0])
        executable_path = executable if executable.is_absolute() else (cwd or Path.cwd()) / executable
        if not executable_path.exists():
            return False, f"CLI agent executable not found: {argv[0]}"
    elif shutil.which(argv[0]) is None:
        return False, f"CLI agent executable not found on PATH: {argv[0]}"
    return True, f"CLI agent configured: {_format_argv(argv)}"


def normalize_command(command: str | list[str] | tuple[str, ...] | None) -> list[str]:
    if isinstance(command, str):
        argv = shlex.split(command)
    elif isinstance(command, (list, tuple)):
        argv = [str(item) for item in command if str(item).strip()]
    else:
        argv = []
    if not argv:
        raise CLIAgentError("CLI agent command is required.")
    return argv


def normalize_agent_response(body: str, *, adapter_name: str) -> dict[str, Any]:
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        preview = body[:200].replace("\n", "\\n")
        raise CLIAgentError(f"{adapter_name} response was not valid JSON: {preview}") from exc
    if not isinstance(data, dict):
        raise CLIAgentError(f"{adapter_name} response must be a JSON object.")

    if "output" not in data:
        raise CLIAgentError(f"{adapter_name} response must include an 'output' string.")
    output = data["output"]
    if not isinstance(output, str):
        raise CLIAgentError(f"{adapter_name} response 'output' must be a string.")

    events = data.get("events", [])
    if events is None:
        events = []
    if not isinstance(events, list):
        raise CLIAgentError(f"{adapter_name} response 'events' field must be a list.")
    for event in events:
        if not isinstance(event, dict):
            raise CLIAgentError(f"{adapter_name} events must be JSON objects.")

    data["events"] = events
    return data


def _format_command(command: str | list[str] | tuple[str, ...] | None) -> str:
    try:
        return _format_argv(normalize_command(command))
    except CLIAgentError:
        return "<missing>"


def _format_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)
