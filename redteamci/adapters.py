from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib import error, request

from .agent import run_agent


DEFAULT_HTTP_DEMO_URL = "http://127.0.0.1:8765/run"


class HTTPAgentError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentConfig:
    kind: str = "builtin"
    url: str | None = None

    @property
    def label(self) -> str:
        if self.kind == "http":
            return f"http:{self.url or DEFAULT_HTTP_DEMO_URL}"
        return self.kind


def run_agent_with_config(
    task: str,
    guardrails: dict[str, list[str]],
    recorder: Any,
    config: AgentConfig,
) -> Any:
    if config.kind == "builtin":
        return run_agent(task, guardrails, recorder)
    if config.kind == "http":
        return run_http_agent(task, recorder, config.url or DEFAULT_HTTP_DEMO_URL)
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


def check_http_agent(url: str, *, timeout: int = 3) -> tuple[bool, str]:
    try:
        call_http_agent("RedTeamCI doctor ping", url, timeout=timeout)
    except HTTPAgentError as exc:
        return False, str(exc)
    return True, f"HTTP agent reachable at {url}"
