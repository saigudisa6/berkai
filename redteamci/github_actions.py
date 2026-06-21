from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request


DEFAULT_GITHUB_API_URL = "https://api.github.com"
DEFAULT_GITHUB_BRANCH = "main"
DEFAULT_WORKFLOW_FILE = "redteamci.yml"


class GitHubActionsError(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkflowRun:
    id: int
    status: str
    conclusion: str | None
    html_url: str
    display_title: str
    branch: str
    event: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "WorkflowRun":
        return cls(
            id=int(data.get("id", 0)),
            status=str(data.get("status", "")),
            conclusion=(
                str(data["conclusion"]) if data.get("conclusion") is not None else None
            ),
            html_url=str(data.get("html_url", "")),
            display_title=str(data.get("display_title") or data.get("name") or ""),
            branch=str(data.get("head_branch", "")),
            event=str(data.get("event", "")),
        )


def github_available() -> tuple[bool, str]:
    if not _github_token():
        return (
            False,
            "GITHUB_TOKEN is not set. It needs Actions: write and Contents: read.",
        )
    if not _github_repository():
        return False, "GITHUB_REPOSITORY is not set, for example saigudisa6/berkai."
    return True, "GitHub Actions trigger is configured."


def trigger_workflow(
    workflow_file: str,
    ref: str,
    inputs: dict[str, str],
) -> str:
    correlation_id = inputs.get("correlation_id") or _new_correlation_id()
    payload = {
        "ref": ref,
        "inputs": {**inputs, "correlation_id": correlation_id},
    }
    _request_json(
        "POST",
        f"/repos/{_github_repository()}/actions/workflows/{workflow_file}/dispatches",
        payload=payload,
        expect_empty=True,
    )
    return correlation_id


def find_workflow_run(
    workflow_file: str,
    branch: str,
    correlation_id: str,
) -> WorkflowRun | None:
    query = parse.urlencode(
        {
            "event": "workflow_dispatch",
            "branch": branch,
            "per_page": "30",
        }
    )
    data = _request_json(
        "GET",
        f"/repos/{_github_repository()}/actions/workflows/{workflow_file}/runs?{query}",
    )
    for run in data.get("workflow_runs", []):
        if not isinstance(run, dict):
            continue
        display_title = str(run.get("display_title") or run.get("name") or "")
        if correlation_id in display_title:
            return WorkflowRun.from_api(run)
    return None


def poll_workflow_run(
    run_id: int,
    timeout_seconds: int = 180,
    interval_seconds: int = 5,
) -> WorkflowRun:
    deadline = time.monotonic() + timeout_seconds
    last_run: WorkflowRun | None = None
    while time.monotonic() <= deadline:
        data = _request_json(
            "GET",
            f"/repos/{_github_repository()}/actions/runs/{run_id}",
        )
        last_run = WorkflowRun.from_api(data)
        if last_run.status == "completed":
            return last_run
        time.sleep(interval_seconds)
    if last_run is not None:
        return last_run
    raise GitHubActionsError(f"Workflow run {run_id} was not found.")


def wait_for_workflow_run(
    workflow_file: str,
    branch: str,
    correlation_id: str,
    timeout_seconds: int = 60,
    interval_seconds: int = 5,
) -> WorkflowRun | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() <= deadline:
        run = find_workflow_run(workflow_file, branch, correlation_id)
        if run is not None:
            return run
        time.sleep(interval_seconds)
    return None


def workflow_run_url(run: WorkflowRun) -> str:
    return run.html_url


def list_artifacts(run_id: int) -> list[dict[str, Any]]:
    data = _request_json(
        "GET",
        f"/repos/{_github_repository()}/actions/runs/{run_id}/artifacts",
    )
    artifacts = data.get("artifacts", [])
    return [artifact for artifact in artifacts if isinstance(artifact, dict)]


def configured_workflow_file() -> str:
    return os.environ.get("REDTEAMCI_WORKFLOW_FILE", DEFAULT_WORKFLOW_FILE)


def configured_branch() -> str:
    return os.environ.get("GITHUB_BRANCH", DEFAULT_GITHUB_BRANCH)


def trigger_support_story_workflow(mode: str) -> str:
    return trigger_workflow(
        configured_workflow_file(),
        configured_branch(),
        {"scenario": "support-story", "mode": mode},
    )


def _request_json(
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    expect_empty: bool = False,
) -> dict[str, Any]:
    token = _github_token()
    if not token:
        raise GitHubActionsError("GITHUB_TOKEN is not set.")
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    api_request = request.Request(
        _api_url(path),
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with request.urlopen(api_request, timeout=20) as response:
            response_body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        raise GitHubActionsError(
            f"GitHub API {method} {path} failed: HTTP {exc.code} {response_body}"
        ) from exc
    except error.URLError as exc:
        raise GitHubActionsError(f"GitHub API {method} {path} failed: {exc}") from exc
    if expect_empty or not response_body:
        return {}
    try:
        data = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise GitHubActionsError("GitHub API response was not valid JSON.") from exc
    return data if isinstance(data, dict) else {}


def _api_url(path: str) -> str:
    return _github_api_url().rstrip("/") + "/" + path.lstrip("/")


def _github_api_url() -> str:
    return os.environ.get("GITHUB_API_URL", DEFAULT_GITHUB_API_URL)


def _github_token() -> str:
    return os.environ.get("GITHUB_TOKEN", "").strip()


def _github_repository() -> str:
    return os.environ.get("GITHUB_REPOSITORY", "").strip()


def _new_correlation_id() -> str:
    return "rtci-" + uuid.uuid4().hex[:12]
