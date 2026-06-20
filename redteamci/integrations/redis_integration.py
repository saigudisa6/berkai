from __future__ import annotations

import json
import os
from typing import Any


class RedisTraceEmitter:
    def __init__(self, run_id: str, attack_id: str):
        self.run_id = run_id
        self.attack_id = attack_id
        self.stream_key = f"redteamci:traces:{run_id}"
        self.event_count = 0
        self._client = self._make_client()

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def emit(self, event: dict[str, Any]) -> None:
        if not self._client:
            return
        try:
            self._client.xadd(
                self.stream_key,
                {
                    "run_id": self.run_id,
                    "attack_id": self.attack_id,
                    "event_type": event["type"],
                    "payload_json": json.dumps(event),
                },
            )
            self.event_count += 1
        except Exception:
            self._client = None

    def _make_client(self) -> Any:
        redis_url = os.environ.get("REDIS_URL") or os.environ.get("REDTEAMCI_REDIS_URL")
        if not redis_url:
            return None
        try:
            import redis

            return redis.from_url(redis_url)
        except Exception:
            return None


def write_summary_if_configured(run_id: str, summary: dict[str, Any]) -> str | None:
    redis_url = os.environ.get("REDIS_URL") or os.environ.get("REDTEAMCI_REDIS_URL")
    if not redis_url:
        return None
    try:
        import redis

        client = redis.from_url(redis_url)
        key = f"redteamci:summary:{run_id}"
        client.set(key, json.dumps(summary))
        return key
    except Exception:
        return None
