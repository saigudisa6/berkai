from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class FlightRecorder:
    def __init__(self, run_id: str, attack_id: str, attack_name: str):
        self.run_id = run_id
        self.attack_id = attack_id
        self.attack_name = attack_name
        self.events: list[dict[str, Any]] = []
        self._redis_client = self._make_redis_client()

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
            event.update(payload)
        self.events.append(event)
        self._emit_redis(event)
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
        return trace

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
        path.write_text(json.dumps(trace, indent=2), encoding="utf-8")
        return trace

    def _make_redis_client(self) -> Any:
        redis_url = os.environ.get("REDTEAMCI_REDIS_URL")
        if not redis_url:
            return None
        try:
            import redis

            return redis.from_url(redis_url)
        except Exception:
            return None

    def _emit_redis(self, event: dict[str, Any]) -> None:
        if not self._redis_client:
            return
        try:
            self._redis_client.xadd(
                "redteamci:runs",
                {
                    "run_id": self.run_id,
                    "attack_id": self.attack_id,
                    "event_type": event["type"],
                    "payload": json.dumps(event),
                },
            )
        except Exception:
            self._redis_client = None
