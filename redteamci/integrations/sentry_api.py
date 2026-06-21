from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any
from urllib import error, parse, request


DEFAULT_SENTRY_BASE_URL = "https://sentry.io/"


def sentry_api_configured(environ: Mapping[str, str] | None = None) -> bool:
    environ = os.environ if environ is None else environ
    return bool(
        environ.get("SENTRY_AUTH_TOKEN")
        and environ.get("SENTRY_ORG")
        and environ.get("SENTRY_PROJECT")
    )


def enrich_sentry_events(
    event_ids: list[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    environ = os.environ if environ is None else environ
    if not sentry_api_configured(environ):
        return []
    enriched: list[dict[str, Any]] = []
    for event_id in event_ids:
        if event_id:
            enriched.append(enrich_sentry_event(event_id, environ=environ))
    return enriched


def enrich_sentry_event(
    event_id: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environ = os.environ if environ is None else environ
    if not sentry_api_configured(environ):
        return {"event_id": event_id, "api_verified": False, "error": "missing config"}

    try:
        event = _get_json(_event_url(event_id, environ), environ)
    except Exception as exc:
        return {
            "event_id": event_id,
            "api_verified": False,
            "error": _short_error(exc),
        }

    normalized = _normalize_event(event_id, event, environ)
    group_id = normalized.get("group_id")
    if group_id:
        try:
            issue = _get_json(_issue_url(str(group_id), environ), environ)
        except Exception as exc:
            normalized["issue_error"] = _short_error(exc)
        else:
            normalized["issue"] = _normalize_issue(issue)
            if normalized["issue"].get("permalink"):
                normalized["issue_url"] = normalized["issue"]["permalink"]
    return normalized


def _event_url(event_id: str, environ: Mapping[str, str]) -> str:
    base = _base_url(environ)
    org = parse.quote(environ["SENTRY_ORG"], safe="")
    project = parse.quote(environ["SENTRY_PROJECT"], safe="")
    event = parse.quote(event_id, safe="")
    return f"{base}/api/0/projects/{org}/{project}/events/{event}/"


def _issue_url(group_id: str, environ: Mapping[str, str]) -> str:
    base = _base_url(environ)
    org = parse.quote(environ["SENTRY_ORG"], safe="")
    issue = parse.quote(group_id, safe="")
    return f"{base}/api/0/organizations/{org}/issues/{issue}/"


def _base_url(environ: Mapping[str, str]) -> str:
    return environ.get("SENTRY_BASE_URL", DEFAULT_SENTRY_BASE_URL).rstrip("/")


def _get_json(url: str, environ: Mapping[str, str]) -> dict[str, Any]:
    req = request.Request(
        url,
        headers={
            "Authorization": f"Bearer {environ['SENTRY_AUTH_TOKEN']}",
            "Accept": "application/json",
        },
        method="GET",
    )
    with request.urlopen(req, timeout=3) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("response was not a JSON object")
    return data


def _normalize_event(
    requested_event_id: str,
    event: dict[str, Any],
    environ: Mapping[str, str],
) -> dict[str, Any]:
    tags = _tags_dict(event.get("tags"))
    group_id = _first_text(
        event.get("groupID"),
        event.get("groupId"),
        event.get("group_id"),
    )
    issue_url = ""
    if group_id:
        organization = parse.quote(environ["SENTRY_ORG"], safe="")
        issue_url = (
            f"{_base_url(environ)}/organizations/{organization}/"
            f"issues/{parse.quote(group_id, safe='')}/"
        )
    return {
        "event_id": _first_text(
            event.get("eventID"),
            event.get("event_id"),
            requested_event_id,
        ),
        "api_verified": True,
        "title": _first_text(
            event.get("title"),
            event.get("metadata", {}).get("title"),
        ),
        "message": _first_text(
            event.get("message"),
            event.get("metadata", {}).get("value"),
        ),
        "level": _first_text(event.get("level"), tags.get("level")),
        "group_id": group_id,
        "event_url": _first_text(event.get("webUrl"), event.get("permalink")),
        "issue_url": issue_url,
        "tags": tags,
        "release": _release_value(event.get("release"), tags),
        "environment": _first_text(event.get("environment"), tags.get("environment")),
    }


def _normalize_issue(issue: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _first_text(issue.get("id")),
        "title": _first_text(issue.get("title")),
        "status": _first_text(issue.get("status"), issue.get("substatus")),
        "permalink": _first_text(issue.get("permalink")),
    }


def _tags_dict(raw: Any) -> dict[str, str]:
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items()}
    tags: dict[str, str] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            if key:
                tags[str(key)] = str(item.get("value", ""))
    return tags


def _release_value(raw: Any, tags: dict[str, str]) -> str:
    if isinstance(raw, dict):
        return _first_text(raw.get("version"), raw.get("shortVersion"), raw.get("name"))
    return _first_text(raw, tags.get("release"))


def _first_text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value:
            return value
        if value is not None and not isinstance(value, (dict, list, tuple, set)):
            return str(value)
    return ""


def _short_error(exc: Exception) -> str:
    if isinstance(exc, error.HTTPError):
        try:
            exc.close()
        except Exception:
            pass
        return f"http {exc.code}"
    if isinstance(exc, error.URLError):
        return "url error"
    if isinstance(exc, TimeoutError):
        return "timeout"
    return type(exc).__name__
