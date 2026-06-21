from __future__ import annotations

from pathlib import Path
from typing import Any

from .sentry_integration import (
    build_failure_event_context,
    build_verification_event_context,
    capture_failure_if_configured,
    capture_verification_if_configured,
)
from .redis_integration import RedisTraceEmitter, write_summary_if_configured
from .sentry_api import enrich_sentry_event, enrich_sentry_events, sentry_api_configured


def summarize_patch_metric(before: int, after: int) -> dict[str, Any]:
    return {
        "metric": "pass_rate_after_patch",
        "before_percent": before,
        "after_percent": after,
    }


__all__ = [
    "RedisTraceEmitter",
    "build_failure_event_context",
    "build_verification_event_context",
    "capture_failure_if_configured",
    "capture_verification_if_configured",
    "enrich_sentry_event",
    "enrich_sentry_events",
    "sentry_api_configured",
    "summarize_patch_metric",
    "write_summary_if_configured",
]
