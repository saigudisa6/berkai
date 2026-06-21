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
python -m redteamci.cli doctor
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

## Project Manifest

RedTeamCI reads `redteamci.yml` by default when it is present:

```yaml
agent: builtin
guardrails: guardrails.yml
regressions: regressions/generated_attacks.json
# attacks: attacks/redteamci_attacks.json
```

You can pass a manifest explicitly:

```bash
python -m redteamci.cli run --config redteamci.yml --expect-fail
```

## External HTTP Agent Demo

Run the sample external agent in one terminal:

```bash
python examples/http_agent/app.py
```

Then point RedTeamCI at it:

```bash
python -m redteamci.cli run --agent http-demo --expect-fail
```

The HTTP contract is intentionally small: RedTeamCI sends `{"task": "..."}` to
`POST /run`, and the agent returns `{"output": "...", "events": [...]}`.
Tool events are optional, but they give RedTeamCI stronger trace evidence.

## Test Your Own Agent

Create a manifest:

```bash
python -m redteamci.cli init --agent http --agent-url http://127.0.0.1:8765/run
```

Validate it:

```bash
python -m redteamci.cli doctor --agent http --agent-url http://127.0.0.1:8765/run
```

The HTTP response must be a JSON object. `output` is required for output-based
evaluation. `events` is optional, but should be a list of tool trace objects
when your agent can provide them:

```json
{
  "output": "Agent response text",
  "events": [
    {
      "type": "tool_call_executed",
      "tool": "read_file",
      "args": {"path": ".env"},
      "result_preview": "redacted or preview text"
    }
  ]
}
```

Attack packs can be added with:

```yaml
attacks: attacks/redteamci_attacks.json
```

Attack pack files use the same shape as generated regressions: `id`, `name`,
`task`, `expected_after_patch`, and optional `setup`.

You can also validate and run the checked-in HTTP example manifest:

```bash
python -m redteamci.cli doctor --config examples/redteamci.http.yml
python -m redteamci.cli run --config examples/redteamci.http.yml --expect-fail
```

## Claude Code Integration

The judged demo uses an offline Claude Code remediation artifact for
deterministic replay:

```bash
python -m redteamci.cli fix pi-003 --use-fixture --apply
```

The live Claude Code integration is inspectable and uses the same contract:
failed trace, guardrail patch, generated regression, and stored artifacts.

```bash
python -m redteamci.cli claude status
python -m redteamci.cli claude prompt pi-003 --run-id run_001
python -m redteamci.cli claude remediate pi-003 --apply
```

Claude artifacts are written under `patches/`, including the prompt, raw
Claude output, summary JSON, and diff. Use `--no-fixture-fallback` for strict
live mode, or rely on the default fixture fallback for demo reliability.

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
- Generated regression tests in `regressions/generated_attacks.json` that run as real attacks.
- Optional attack packs in `attacks/*.json`.
- `doctor` and `init` commands for external-agent setup.
- Patch summaries and diffs in `patches/`.
- A Markdown security report.
- A Streamlit dashboard.
- A green GitHub Actions workflow using deterministic fixture mode.

## Tests

```bash
python -m unittest discover -s tests
```
