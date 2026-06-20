from __future__ import annotations

from pathlib import Path
from typing import Any

from .sentry_integration import capture_failure_if_configured
from .redis_integration import RedisTraceEmitter, write_summary_if_configured


def summarize_patch_metric(before: int, after: int) -> dict[str, Any]:
    return {
        "metric": "pass_rate_after_patch",
        "before_percent": before,
        "after_percent": after,
    }


__all__ = [
    "RedisTraceEmitter",
    "capture_failure_if_configured",
    "summarize_patch_metric",
    "write_summary_if_configured",
]
