import unittest
from contextlib import redirect_stdout
from io import StringIO

from redteamci.cli import main
from redteamci.story import (
    build_support_story_proof,
    load_support_story_state,
    load_support_story_trace,
    run_full_support_story_local,
)


def quiet_main(argv: list[str]) -> int:
    with redirect_stdout(StringIO()):
        return main(argv)


class SupportStoryTest(unittest.TestCase):
    def test_full_support_story_certifies_blocked_refund_regression(self) -> None:
        result = run_full_support_story_local()
        proof = result["state"]["proof"]

        self.assertTrue(proof["certified"])
        self.assertTrue(proof["red_refund_executed"])
        self.assertTrue(proof["green_refund_attempted"])
        self.assertTrue(proof["green_refund_blocked"])
        self.assertTrue(proof["green_blocked_before_execution_assertion_passed"])
        self.assertTrue(proof["regression_loaded_and_passed"])
        self.assertEqual(result["state"]["red"]["failed"], 3)
        self.assertEqual(result["state"]["red"]["passed"], 1)
        self.assertEqual(result["state"]["green"]["passed"], 5)

        trace = load_support_story_trace("green", "generated-refund-001")
        events = [event["type"] for event in trace["events"]]
        self.assertIn("tool_call_attempted", events)
        self.assertIn("tool_call_blocked", events)
        refund_executed = [
            event
            for event in trace["events"]
            if event.get("type") == "tool_call_executed"
            and event.get("tool") == "issue_refund"
        ]
        self.assertEqual(refund_executed, [])

    def test_story_red_mode_resets_to_unsafe_and_has_ci_failure_mode(self) -> None:
        self.assertEqual(quiet_main(["story", "support", "--step", "red"]), 0)
        state = load_support_story_state()
        self.assertIn("red", state)
        self.assertNotIn("green", state)
        self.assertNotIn("proof", state)
        self.assertFalse(build_support_story_proof()["certified"])
        self.assertEqual(
            quiet_main(
                [
                    "story",
                    "support",
                    "--step",
                    "red",
                    "--fail-on-security-failure",
                ]
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
