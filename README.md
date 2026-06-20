# RedTeamCI

RedTeamCI - Crash-test your AI agent before production.

RedTeamCI turns agent exploits into failing tests, Claude Code patches, generated
regression tests, and green CI.

## What It Does

RedTeamCI runs adversarial security tests against a deliberately weak
tool-using demo agent. The weak agent is intentional: it gives a deterministic
red-to-green demonstration of the security workflow.

RedTeamCI itself is the attack runner, policy boundary, flight recorder,
Claude Code remediation layer, report generator, dashboard, and CI workflow.
After patching, the vulnerable agent may still try the dangerous action, but
`guarded_tool_call` blocks it before execution.

## Live Claude Code Demo

Use this when the `claude` CLI is installed:

```bash
python -m redteamci.cli reset
python -m redteamci.cli run --expect-fail --summary before.json
python -m redteamci.cli fix pi-003 --claude-code --apply
python -m redteamci.cli rerun --expect-pass --summary after.json
python -m redteamci.cli report --before before.json --after after.json
streamlit run redteamci/dashboard.py
```

## Offline Demo

Fixture mode is for offline demo reliability and CI. It uses a
Claude-compatible patch document from `fixtures/`.

```bash
python -m redteamci.cli reset
python -m redteamci.cli run --expect-fail --summary before.json
python -m redteamci.cli fix pi-003 --use-fixture --apply
python -m redteamci.cli rerun --expect-pass --summary after.json
python -m redteamci.cli report --before before.json --after after.json
streamlit run redteamci/dashboard.py
```

Expected before patch:

```text
3 failed, 1 passed
```

Expected after patch:

```text
0 failed, 4 passed
AGENT CERTIFIED
```

## Commands

```bash
python -m redteamci.cli reset
python -m redteamci.cli run --expect-fail --summary before.json
python -m redteamci.cli fix pi-003 --use-fixture --apply
python -m redteamci.cli rerun --expect-pass --summary after.json
python -m redteamci.cli report --before before.json --after after.json
python -m redteamci.cli dashboard
```

## What It Ships

- Four deterministic tests:
  - `pi-003` Browser Hidden Injection
  - `exfil-001` Env File Read
  - `exfil-002` Network Exfiltration
  - `safe-001` Benign README Read
- A deliberately vulnerable demo agent.
- A pre-execution `guarded_tool_call` policy layer.
- Secret-redacted JSON flight-recorder traces in `traces/run_*/`.
- Fixture and Claude Code remediation paths.
- Generated regression tests in `regressions/generated_attacks.json`.
- Patch summaries and diffs in `patches/`.
- A Markdown security report.
- A Streamlit dashboard.
- A green GitHub Actions workflow using deterministic fixture mode.

## Tests

```bash
python -m unittest discover -s tests
```
