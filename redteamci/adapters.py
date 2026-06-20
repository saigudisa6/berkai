from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib import request

from .agent import run_agent


DEFAULT_HTTP_DEMO_URL = "http://127.0.0.1:8765/run"


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
    payload = json.dumps({"task": task}).encode("utf-8")
    http_request = request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(http_request, timeout=10) as response:
        body = response.read().decode("utf-8")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("HTTP agent response must be a JSON object")

    recorder.log(
        "http_agent_response",
        {"url": url, "response_preview": body[:500]},
        title="HTTP agent responded",
        severity="low",
    )
    for event in data.get("events", []) or []:
        if isinstance(event, dict):
            recorder.log(
                str(event.get("type", "http_agent_event")),
                {key: value for key, value in event.items() if key != "type"},
                title=str(event.get("title", event.get("type", "HTTP agent event"))),
                severity=str(event.get("severity", "medium")),
            )
    return data.get("output", "")
