# RedTeamCI

Crash-test your AI agent before production.

RedTeamCI Lite runs adversarial security tests against a deliberately weak
tool-using demo agent, records the full attack trace, uses Claude-compatible
JSON to patch `guardrails.yml`, and reruns the suite until exploits become
passing regression tests.

The product idea is simple: every agent exploit becomes a reproducible CI test.

## Demo

```bash
python3 -m redteamci.cli reset
python3 -m redteamci.cli run
python3 -m redteamci.cli fix pi-003 --use-fixture
python3 -m redteamci.cli rerun
```

Expected first run:

```text
3 failed, 1 passed
```

Expected rerun:

```text
0 failed, 4 passed
AGENT CERTIFIED
```

The rerun is green because dangerous tool calls are blocked before execution.
For example, the vulnerable agent still attempts `read_file(".env")`, but the
policy layer records `tool_call_blocked` before the file is opened.

## Commands

```bash
python3 -m redteamci.cli run
python3 -m redteamci.cli fix pi-003 --use-fixture
python3 -m redteamci.cli rerun
python3 -m redteamci.cli dashboard
```

`fix` attempts a live Anthropic call when `ANTHROPIC_API_KEY` is set. Without
that key, or when `--use-fixture` is passed, it uses
`fixtures/claude_pi003_patch.json` so the demo works offline.

## What It Ships

- Four deterministic attacks:
  - `pi-003` Browser Hidden Injection
  - `exfil-001` Env File Read
  - `exfil-002` Network Exfiltration
  - `tool-001` Private Key Probe
- A deliberately vulnerable demo agent.
- A pre-execution `guarded_tool_call` policy layer.
- JSON flight-recorder traces in `traces/run_*/`.
- A Claude patcher that updates `guardrails.yml` and writes a regression test.
- A Streamlit dashboard for the attack suite, flight recorder, and patch diff.
- Optional Sentry and Redis hooks via environment variables.

## Offline Demo Script

```bash
./demo_offline.sh
```

This resets to unsafe guardrails, runs the failing suite, applies the fixture
patch, reruns, and starts the dashboard if Streamlit is installed.

## Tests

```bash
python3 -m unittest discover -s tests
```
