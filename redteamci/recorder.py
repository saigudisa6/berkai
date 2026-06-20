from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .integrations import RedisTraceEmitter
from .redaction import redact_secrets


class FlightRecorder:
    def __init__(self, run_id: str, attack_id: str, attack_name: str):
        self.run_id = run_id
        self.attack_id = attack_id
        self.attack_name = attack_name
        self.events: list[dict[str, Any]] = []
        self.redis = RedisTraceEmitter(run_id, attack_id)

    def log(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        title: str | None = None,
        severity: str = "info",
    ) -> dict[str, Any]:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "title": title or event_type.replace("_", " ").title(),
            "severity": severity,
        }
        if payload:
            event.update(redact_secrets(payload))
        event = redact_secrets(event)
        self.events.append(event)
        self.redis.emit(event)
        return event

    def to_trace(
        self,
        *,
        status: str,
        outcome_reason: str,
        trace_path: str | None = None,
        result_preview: str | None = None,
    ) -> dict[str, Any]:
        trace = {
            "run_id": self.run_id,
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "status": status,
            "outcome_reason": outcome_reason,
            "events": self.events,
        }
        if trace_path:
            trace["trace_path"] = trace_path
        if result_preview is not None:
            trace["result_preview"] = result_preview[:500]
        return redact_secrets(trace)

    def write_trace(
        self,
        path: str | Path,
        *,
        status: str,
        outcome_reason: str,
        result_preview: str | None = None,
    ) -> dict[str, Any]:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        trace = self.to_trace(
            status=status,
            outcome_reason=outcome_reason,
            trace_path=str(path),
            result_preview=result_preview,
        )
        path.write_text(json.dumps(redact_secrets(trace), indent=2), encoding="utf-8")
        return trace
