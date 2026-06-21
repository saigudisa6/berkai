import json
import unittest
from io import BytesIO
from unittest.mock import patch
from urllib import error

from redteamci.integrations.sentry_api import enrich_sentry_event, enrich_sentry_events


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class SentryApiTest(unittest.TestCase):
    def test_missing_token_is_noop_for_batch_enrichment(self) -> None:
        self.assertEqual(
            enrich_sentry_events(
                ["event-123"],
                environ={
                    "SENTRY_ORG": "demo-org",
                    "SENTRY_PROJECT": "redteamci",
                },
            ),
            [],
        )

    def test_successful_event_lookup_normalizes_metadata(self) -> None:
        environ = {
            "SENTRY_AUTH_TOKEN": "token",
            "SENTRY_ORG": "demo-org",
            "SENTRY_PROJECT": "redteamci",
            "SENTRY_BASE_URL": "https://sentry.example",
        }

        def fake_urlopen(req: object, timeout: int = 3) -> FakeResponse:
            self.assertEqual(timeout, 3)
            url = getattr(req, "full_url")
            self.assertEqual(getattr(req, "get_header")("Authorization"), "Bearer token")
            if "/events/event-123/" in url:
                return FakeResponse(
                    {
                        "eventID": "event-123",
                        "title": "RedTeamCI failed generated-refund-001",
                        "message": "Unsafe refund executed",
                        "level": "error",
                        "groupID": "42",
                        "webUrl": "https://sentry.example/event/event-123",
                        "tags": [
                            {"key": "environment", "value": "local-demo"},
                            {"key": "release", "value": "abc123"},
                        ],
                        "release": {"version": "abc123"},
                    }
                )
            if "/issues/42/" in url:
                return FakeResponse(
                    {
                        "id": "42",
                        "title": "Unsafe refund issue",
                        "status": "unresolved",
                        "permalink": "https://sentry.example/issues/42",
                    }
                )
            raise AssertionError(f"unexpected url {url}")

        with patch("redteamci.integrations.sentry_api.request.urlopen", fake_urlopen):
            result = enrich_sentry_event("event-123", environ=environ)

        self.assertTrue(result["api_verified"])
        self.assertEqual(result["event_id"], "event-123")
        self.assertEqual(result["title"], "RedTeamCI failed generated-refund-001")
        self.assertEqual(result["message"], "Unsafe refund executed")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["group_id"], "42")
        self.assertEqual(result["event_url"], "https://sentry.example/event/event-123")
        self.assertEqual(result["issue"]["status"], "unresolved")
        self.assertEqual(result["issue_url"], "https://sentry.example/issues/42")
        self.assertEqual(result["tags"]["environment"], "local-demo")
        self.assertEqual(result["release"], "abc123")
        self.assertEqual(result["environment"], "local-demo")

    def test_http_errors_return_unverified_lookup(self) -> None:
        environ = {
            "SENTRY_AUTH_TOKEN": "token",
            "SENTRY_ORG": "demo-org",
            "SENTRY_PROJECT": "redteamci",
        }

        def raise_http_error(req: object, timeout: int = 3) -> None:
            raise error.HTTPError(
                url=getattr(req, "full_url"),
                code=401,
                msg="Unauthorized",
                hdrs=None,
                fp=BytesIO(b""),
            )

        with patch("redteamci.integrations.sentry_api.request.urlopen", raise_http_error):
            result = enrich_sentry_event("event-123", environ=environ)

        self.assertFalse(result["api_verified"])
        self.assertEqual(result["event_id"], "event-123")
        self.assertEqual(result["error"], "http 401")


if __name__ == "__main__":
    unittest.main()
