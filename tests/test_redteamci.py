import json
import shutil
import tempfile
import unittest
from pathlib import Path

from redteamci.config import load_guardrails
from redteamci.patcher import apply_patch_document, load_fixture_patch
from redteamci.paths import ROOT
from redteamci.policy import domain_matches, path_matches
from redteamci.runner import run_suite


class RedTeamCITest(unittest.TestCase):
    def test_path_and_domain_matching(self) -> None:
        self.assertEqual(path_matches(".env", [".env"])[0], True)
        self.assertEqual(path_matches("./.env", ["**/.env"])[0], True)
        self.assertEqual(path_matches("~/.ssh/id_rsa", ["id_rsa"])[0], True)
        self.assertEqual(
            domain_matches(
                "http://sub.attacker.example.com/collect",
                ["attacker.example.com"],
            )[0],
            True,
        )

    def test_red_to_green_flow_blocks_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            guardrails_path = tmp_path / "guardrails.yml"
            traces_root = tmp_path / "traces"
            shutil.copyfile(ROOT / "guardrails.unsafe.yml", guardrails_path)

            first = run_suite(guardrails_path=guardrails_path, traces_root=traces_root)
            self.assertEqual(len(first.failed), 3)
            self.assertEqual(len(first.passed), 1)

            patch_doc = load_fixture_patch("pi-003")
            apply_patch_document(
                patch_doc,
                guardrails_path=guardrails_path,
                regression_tests_root=tmp_path / "regression_tests",
            )
            guardrails = load_guardrails(guardrails_path)
            self.assertIn(".env", guardrails["denied_file_patterns"])
            self.assertIn("attacker.example.com", guardrails["denied_domains"])

            second = run_suite(guardrails_path=guardrails_path, traces_root=traces_root)
            self.assertEqual(len(second.failed), 0)
            self.assertEqual(len(second.passed), 4)

            trace = json.loads((traces_root / second.run_id / "pi-003.json").read_text())
            event_types = [event["type"] for event in trace["events"]]
            self.assertIn("tool_call_blocked", event_types)

            blocked_index = event_types.index("tool_call_blocked")
            blocked = trace["events"][blocked_index]
            self.assertEqual(blocked["tool"], "read_file")
            self.assertEqual(blocked["args"]["path"], ".env")

            later_events = trace["events"][blocked_index + 1 :]
            self.assertFalse(
                any(
                    event.get("type") == "tool_call_executed"
                    and event.get("tool") == "read_file"
                    and event.get("args", {}).get("path") == ".env"
                    for event in later_events
                )
            )


if __name__ == "__main__":
    unittest.main()
