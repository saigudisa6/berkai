import json
import unittest
from unittest.mock import patch

from redteamci.github_actions import (
    configured_branch,
    configured_workflow_file,
    find_workflow_run,
    github_available,
    list_artifacts,
    poll_workflow_run,
    trigger_workflow,
    workflow_run_url,
)


class FakeResponse:
    def __init__(self, payload: dict | None = None) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        if self.payload is None:
            return b""
        return json.dumps(self.payload).encode("utf-8")


class GitHubActionsClientTest(unittest.TestCase):
    def test_github_available_reports_missing_env(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            ok, message = github_available()

        self.assertFalse(ok)
        self.assertIn("GITHUB_TOKEN", message)

    def test_trigger_workflow_posts_dispatch_with_correlation_id(self) -> None:
        requests = []

        def fake_urlopen(req, timeout):
            requests.append(req)
            return FakeResponse()

        with patch.dict(
            "os.environ",
            {
                "GITHUB_TOKEN": "token",
                "GITHUB_REPOSITORY": "owner/repo",
            },
            clear=True,
        ):
            with patch("redteamci.github_actions.request.urlopen", fake_urlopen):
                correlation_id = trigger_workflow(
                    "redteamci.yml",
                    "main",
                    {
                        "scenario": "support-story",
                        "mode": "red",
                        "correlation_id": "demo-123",
                    },
                )

        self.assertEqual(correlation_id, "demo-123")
        self.assertEqual(requests[0].get_method(), "POST")
        self.assertIn("/actions/workflows/redteamci.yml/dispatches", requests[0].full_url)
        body = json.loads(requests[0].data.decode("utf-8"))
        self.assertEqual(body["ref"], "main")
        self.assertEqual(body["inputs"]["correlation_id"], "demo-123")

    def test_find_poll_and_artifacts_parse_workflow_run(self) -> None:
        responses = [
            FakeResponse(
                {
                    "workflow_runs": [
                        {
                            "id": 10,
                            "status": "in_progress",
                            "conclusion": None,
                            "html_url": "https://github.com/owner/repo/actions/runs/10",
                            "display_title": "RedTeamCI support-story red demo-123",
                            "head_branch": "main",
                            "event": "workflow_dispatch",
                        }
                    ]
                }
            ),
            FakeResponse(
                {
                    "id": 10,
                    "status": "completed",
                    "conclusion": "failure",
                    "html_url": "https://github.com/owner/repo/actions/runs/10",
                    "display_title": "RedTeamCI support-story red demo-123",
                    "head_branch": "main",
                    "event": "workflow_dispatch",
                }
            ),
            FakeResponse(
                {
                    "artifacts": [
                        {"id": 1, "name": "redteamci-support-story-red"},
                        "bad",
                    ]
                }
            ),
        ]

        def fake_urlopen(req, timeout):
            return responses.pop(0)

        with patch.dict(
            "os.environ",
            {
                "GITHUB_TOKEN": "token",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_BRANCH": "main",
                "REDTEAMCI_WORKFLOW_FILE": "redteamci.yml",
            },
            clear=True,
        ):
            with patch("redteamci.github_actions.request.urlopen", fake_urlopen):
                run = find_workflow_run("redteamci.yml", "main", "demo-123")
                completed = poll_workflow_run(10, timeout_seconds=1, interval_seconds=0)
                artifacts = list_artifacts(10)

        self.assertIsNotNone(run)
        assert run is not None
        self.assertEqual(run.id, 10)
        self.assertEqual(completed.conclusion, "failure")
        self.assertEqual(workflow_run_url(completed), "https://github.com/owner/repo/actions/runs/10")
        self.assertEqual(artifacts, [{"id": 1, "name": "redteamci-support-story-red"}])
        self.assertEqual(configured_branch(), "main")
        self.assertEqual(configured_workflow_file(), "redteamci.yml")


if __name__ == "__main__":
    unittest.main()
