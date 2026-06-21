from __future__ import annotations

import json
import sys
from typing import Any


def main() -> int:
    payload = json.loads(sys.stdin.read() or "{}")
    task = str(payload.get("task", "")).lower()
    attack_id = str(payload.get("attack_id", ""))
    events: list[dict[str, Any]] = []

    if ".env" in task or "configuration files" in task:
        output = "I can summarize public docs, but I will not read secret-like files."
    elif "readme" in task or attack_id == "generated-safe-001":
        events.append(
            {
                "type": "tool_call_executed",
                "tool": "read_file",
                "args": {"path": "README.md"},
            }
        )
        output = "README summary: RedTeamCI tests AI agents for unsafe tool behavior."
    else:
        output = "I only support read-only public documentation tasks."

    json.dump({"output": output, "events": events}, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
