from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .redaction import redact_secrets
from .summary import load_summary

DEFAULT_GITHUB_SUMMARY_PATH = Path("redteamci_github_summary.md")


def write_github_summary(
    *,
    before_path: str | Path,
    after_path: str | Path,
    output_path: str | Path = DEFAULT_GITHUB_SUMMARY_PATH,
    github_step_summary: bool = False,
    env: dict[str, str] | None = None,
) -> tuple[Path, Path | None]:
    before = load_summary(before_path)
    after = load_summary(after_path)
    markdown = render_github_summary(before, after)
    output = Path(output_path)
    output.write_text(markdown, encoding="utf-8")

    appended_path = None
    if github_step_summary:
        appended_path = append_github_step_summary(markdown, env=env)
    return output, appended_path


def append_github_step_summary(
    markdown: str,
    *,
    env: dict[str, str] | None = None,
) -> Path | None:
    environment = os.environ if env is None else env
    step_summary_path = environment.get("GITHUB_STEP_SUMMARY")
    if not step_summary_path:
        return None
    path = Path(step_summary_path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(markdown)
        if not markdown.endswith("\n"):
            handle.write("\n")
    return path


def render_github_summary(before: dict[str, Any], after: dict[str, Any]) -> str:
    before = redact_secrets(before)
    after = redact_secrets(after)
    certified = "AGENT CERTIFIED" if after.get("certified") else "NOT CERTIFIED"
    generated_attacks = [
        attack for attack in after.get("attacks", []) if attack.get("source") == "generated"
    ]

    lines = [
        "# RedTeamCI Agent Security Gate",
        "",
        "## Gate Result",
        f"- Before patch: {_count_line(before)}",
        f"- After patch: {_count_line(after)}",
        f"- Certification: **{certified}**",
        (
            "- Generated regressions loaded: "
            f"{_cell(after.get('generated_regressions_loaded', 0))}"
        ),
        "",
        "## Attack Matrix",
        "",
        "Attack | Source | Before | After",
        "--- | --- | --- | ---",
    ]

    for attack_id in _attack_ids(before, after):
        before_attack = _attack_by_id(before, attack_id) or {}
        after_attack = _attack_by_id(after, attack_id) or {}
        source = after_attack.get("source") or before_attack.get("source") or "unknown"
        attack_label = _attack_label(before_attack, after_attack, attack_id)
        lines.append(
            " | ".join(
                [
                    _cell(attack_label),
                    _cell(source),
                    _cell(_attack_status(before_attack)),
                    _cell(_attack_status(after_attack)),
                ]
            )
        )

    lines.extend(["", "## Generated Regression", ""])
    if generated_attacks:
        lines.extend(["Attack | Status | Assertions | Trace", "--- | --- | --- | ---"])
        for attack in generated_attacks:
            lines.append(
                " | ".join(
                    [
                        _cell(_attack_label({}, attack, str(attack.get("id") or "unknown"))),
                        _cell(_attack_status(attack)),
                        _cell(_assertion_state(attack)),
                        _cell(attack.get("trace_path") or "-"),
                    ]
                )
            )
    else:
        lines.append("- No generated regression loaded.")

    assertion_gate_lines = _assertion_gate_lines(before, after)
    if assertion_gate_lines:
        lines.extend(["", "## Assertion Gates", "", *assertion_gate_lines])

    lines.extend(
        [
            "",
            "## Artifact Checklist",
            "- [x] `redteamci_report.md` full Markdown report",
            "- [x] `redteamci_github_summary.md` GitHub job summary artifact",
            "- [x] `before.json` and `after.json` JSON summaries",
            "- [x] `before.junit.xml` and `after.junit.xml` JUnit results",
            "- [x] `before.sarif` and `after.sarif` SARIF security results",
            "- [x] `traces/` replayable flight-recorder traces",
            "- [x] `patches/` Claude Code prompts, proposals, summaries, and diffs",
            "",
            "## Trace Replay",
            "```bash",
            "python -m redteamci.cli trace pi-003 --run-id <run>",
            "python -m redteamci.cli trace pi-003 --json",
            "```",
            f"- Before run: `{_code_value(before.get('run_id') or '-')}`",
            f"- After run: `{_code_value(after.get('run_id') or '-')}`",
        ]
    )
    if generated_attacks:
        generated_id = generated_attacks[0].get("id") or "generated-regression"
        after_run = after.get("run_id") or "<run>"
        lines.append(
            "- Generated regression replay: "
            f"`python -m redteamci.cli trace {_code_value(generated_id)} "
            f"--run-id {_code_value(after_run)}`"
        )

    return redact_secrets("\n".join(lines).rstrip() + "\n")


def _count_line(summary: dict[str, Any]) -> str:
    total = _int(summary.get("total_attacks"))
    passed = _int(summary.get("passed"))
    failed = summary.get("failed")
    failed_count = _int(failed) if failed is not None else max(total - passed, 0)
    return f"{passed} passed / {total} total ({failed_count} failed)"


def _attack_ids(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    attack_ids: list[str] = []
    seen = set()
    for summary in [before, after]:
        for attack in summary.get("attacks", []):
            attack_id = str(attack.get("id") or "unknown")
            if attack_id in seen:
                continue
            seen.add(attack_id)
            attack_ids.append(attack_id)
    return attack_ids


def _attack_by_id(summary: dict[str, Any], attack_id: str) -> dict[str, Any] | None:
    for attack in summary.get("attacks", []):
        if str(attack.get("id") or "unknown") == attack_id:
            return attack
    return None


def _attack_label(
    before_attack: dict[str, Any],
    after_attack: dict[str, Any],
    attack_id: str,
) -> str:
    attack = after_attack or before_attack
    name = str(attack.get("name") or attack_id)
    return f"{attack_id}: {name}" if name != attack_id else attack_id


def _attack_status(attack: dict[str, Any]) -> str:
    return str(attack.get("status") or "NOT RUN") if attack else "NOT RUN"


def _assertion_gate_lines(
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[str]:
    rows: list[str] = []
    failures: list[str] = []
    for attack_id in _attack_ids(before, after):
        before_attack = _attack_by_id(before, attack_id) or {}
        after_attack = _attack_by_id(after, attack_id) or {}
        if not (
            _has_assertion_evidence(before_attack)
            or _has_assertion_evidence(after_attack)
        ):
            continue
        source = after_attack.get("source") or before_attack.get("source") or "unknown"
        label = _attack_label(before_attack, after_attack, attack_id)
        rows.append(
            " | ".join(
                [
                    _cell(label),
                    _cell(source),
                    _cell(_assertion_state(before_attack)),
                    _cell(_assertion_state(after_attack)),
                ]
            )
        )
        for failure in before_attack.get("assertion_failures") or []:
            failures.append(f"- `{_code_value(attack_id)}` before: {_text(failure)}")
        for failure in after_attack.get("assertion_failures") or []:
            failures.append(f"- `{_code_value(attack_id)}` after: {_text(failure)}")

    if not rows:
        return []
    lines = [
        "Attack | Source | Before Assertions | After Assertions",
        "--- | --- | --- | ---",
        *rows,
    ]
    if failures:
        lines.extend(["", "Assertion failure details:", *failures])
    return lines


def _has_assertion_evidence(attack: dict[str, Any]) -> bool:
    return bool(attack.get("assertion_count") or attack.get("assertion_failures"))


def _assertion_state(attack: dict[str, Any]) -> str:
    if not attack:
        return "NOT RUN"
    failures = attack.get("assertion_failures") or []
    if failures:
        return f"FAIL ({len(failures)} failed)"
    count = _int(attack.get("assertion_count"))
    if count:
        return f"PASS ({count} passed)"
    return "-"


def _cell(value: Any) -> str:
    return _text(value).replace("|", "\\|")


def _text(value: Any) -> str:
    if value is None:
        return "-"
    text = str(redact_secrets(value))
    text = " ".join(text.splitlines()).strip()
    return text or "-"


def _code_value(value: Any) -> str:
    return _text(value).replace("`", "'")


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
