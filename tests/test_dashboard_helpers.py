import json
import tempfile
import unittest
from pathlib import Path

from redteamci.dashboard import (
    LEVEL_1_WARNING,
    build_sentry_dashboard_context,
    demo_readiness_status,
    deterministic_demo_proof_commands,
    load_generated_plan_panel,
    load_support_story_dashboard_state,
    onboarding_level_notice,
    support_story_certified,
)


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class DashboardHelperTest(unittest.TestCase):
    def test_generated_plan_panel_loads_without_redteamci_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = load_generated_plan_panel(Path(tmp))

        self.assertFalse(state["available"])
        self.assertEqual(state["agent"]["id"], "agent")
        self.assertEqual(state["onboarding"]["label"], "Level 0 output-only agent")
        self.assertEqual(state["capabilities"], [])
        self.assertEqual(state["categories"], [])
        self.assertEqual(state["attack_ids"], [])
        self.assertEqual(state["plan_artifacts"], [])

    def test_generated_plan_panel_surfaces_level1_plan_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            redteamci = root / ".redteamci"
            write_json(
                redteamci / "agent_profile.json",
                {
                    "agent": {
                        "id": "support-agent",
                        "name": "Support Agent",
                        "adapter_kind": "http",
                        "onboarding_level": 1,
                    }
                },
            )
            write_json(
                redteamci / "capability_profile.json",
                {
                    "agent_id": "support-agent",
                    "adapter_kind": "http",
                    "onboarding_level": 1,
                    "capabilities": {
                        "can_read_files": True,
                        "can_send_email": True,
                        "uses_guarded_gateway": False,
                    },
                    "risk_areas": ["secret_exfiltration", "email_exfiltration"],
                },
            )
            write_json(
                redteamci / "attack_plan.json",
                {
                    "agent_id": "support-agent",
                    "onboarding_level": 1,
                    "categories": [
                        {
                            "name": "Secret Exfiltration",
                            "count": 1,
                            "attack_ids": ["generated-exfil-001"],
                        },
                        {
                            "name": "Email Exfiltration",
                            "count": 1,
                            "attack_ids": ["generated-email-001"],
                        },
                    ],
                    "generated_attack_pack": "attacks/generated.json",
                },
            )
            (redteamci / "attack_plan.md").write_text("# Generated Plan\n", encoding="utf-8")
            write_json(
                root / "attacks" / "generated.json",
                [
                    {"id": "generated-exfil-001", "name": "Secret Exfiltration"},
                    {"id": "generated-email-001", "name": "Email Exfiltration"},
                ],
            )
            write_json(root / "before.json", {"failed": 2})
            write_json(root / "traces" / "run_001" / "generated-exfil-001.json", {"events": []})
            write_json(root / "patches" / "run_001_summary.json", {"success": True})

            state = load_generated_plan_panel(root)

        self.assertTrue(state["available"])
        self.assertEqual(state["agent"]["name"], "Support Agent")
        self.assertEqual(state["agent"]["adapter_kind"], "http")
        self.assertEqual(state["onboarding"]["label"], "Level 1 trace-reporting agent")
        self.assertEqual(state["onboarding"]["tone"], "warning")
        self.assertEqual(state["onboarding"]["message"], LEVEL_1_WARNING)
        self.assertIn(
            {"name": "can_read_files", "label": "Can read files", "enabled": True},
            state["capabilities"],
        )
        self.assertEqual(
            state["categories"],
            [
                {
                    "name": "Secret Exfiltration",
                    "count": 1,
                    "attack_ids": ["generated-exfil-001"],
                },
                {
                    "name": "Email Exfiltration",
                    "count": 1,
                    "attack_ids": ["generated-email-001"],
                },
            ],
        )
        self.assertEqual(
            state["attack_ids"],
            ["generated-exfil-001", "generated-email-001"],
        )
        self.assertEqual(state["generated_attack_pack"], "attacks/generated.json")
        self.assertTrue(state["generated_attack_pack_exists"])
        self.assertEqual(state["attack_plan_markdown"], "# Generated Plan\n")
        self.assertEqual(
            {artifact["path"] for artifact in state["plan_artifacts"]},
            {
                ".redteamci/agent_profile.json",
                ".redteamci/capability_profile.json",
                ".redteamci/attack_plan.json",
                ".redteamci/attack_plan.md",
            },
        )
        self.assertIn("before.json", {artifact["path"] for artifact in state["evidence_artifacts"]})
        self.assertIn(
            "traces/run_001/generated-exfil-001.json",
            {artifact["path"] for artifact in state["evidence_artifacts"]},
        )
        self.assertIn(
            "patches/run_001_summary.json",
            {artifact["path"] for artifact in state["evidence_artifacts"]},
        )

    def test_generated_plan_panel_falls_back_to_attack_pack_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(
                root / ".redteamci" / "attack_plan.json",
                {"generated_attack_pack": "attacks/generated.json"},
            )
            write_json(
                root / "attacks" / "generated.json",
                [{"id": "generated-a"}, {"id": "generated-b"}],
            )

            state = load_generated_plan_panel(root)

        self.assertTrue(state["available"])
        self.assertEqual(
            state["categories"],
            [
                {
                    "name": "Generated",
                    "count": 2,
                    "attack_ids": ["generated-a", "generated-b"],
                }
            ],
        )
        self.assertEqual(state["attack_ids"], ["generated-a", "generated-b"])

    def test_onboarding_level_notice_is_honest_about_blocking(self) -> None:
        self.assertEqual(onboarding_level_notice(2)["tone"], "success")
        self.assertEqual(onboarding_level_notice(1)["message"], LEVEL_1_WARNING)
        self.assertEqual(onboarding_level_notice(0)["label"], "Level 0 output-only agent")
        self.assertEqual(
            onboarding_level_notice(1, uses_guarded_gateway=True)["label"],
            "Level 2 guarded gateway",
        )

    def test_deterministic_demo_proof_commands_use_fixture_path(self) -> None:
        self.assertEqual(
            deterministic_demo_proof_commands(),
            [
                ["story", "support", "--step", "prepare"],
                ["story", "support", "--step", "plan"],
                ["story", "support", "--step", "red"],
                ["story", "support", "--step", "remediate"],
                ["story", "support", "--step", "green"],
            ],
        )

    def test_demo_readiness_status_requires_complete_proof_chain(self) -> None:
        empty = demo_readiness_status({"available": False})
        self.assertEqual(empty["status"], "empty")
        self.assertEqual(empty["label"], "NO RUN YET")

        red_only = demo_readiness_status(
            {
                "available": True,
                "red_summary": {"failed": 3, "passed": 1},
                "proof": {"red_refund_executed": True},
            }
        )
        self.assertEqual(red_only["status"], "partial")
        self.assertEqual(red_only["label"], "INCOMPLETE")
        self.assertFalse(red_only["ready"])

        failed_green = demo_readiness_status(
            {
                "available": True,
                "proof": {
                    "red_refund_executed": True,
                    "green_refund_attempted": True,
                    "green_refund_blocked": True,
                    "green_blocked_before_execution_assertion_passed": True,
                    "regression_loaded_and_passed": True,
                    "green_failed": 1,
                },
                "remediation_summary_exists": True,
                "generated_regression_exists": True,
            }
        )
        self.assertEqual(failed_green["status"], "partial")
        self.assertFalse(failed_green["checks"]["green failures = 0"])

        ready = demo_readiness_status(
            {
                "available": True,
                "proof": {
                    "red_refund_executed": True,
                    "green_refund_attempted": True,
                    "green_refund_blocked": True,
                    "green_blocked_before_execution_assertion_passed": True,
                    "regression_loaded_and_passed": True,
                    "green_failed": 0,
                },
                "remediation_summary_exists": True,
                "generated_regression_exists": True,
            }
        )
        self.assertEqual(ready["status"], "ready")
        self.assertEqual(ready["label"], "DEMO READY")
        self.assertTrue(ready["ready"])

    def test_support_story_dashboard_state_requires_hard_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            story = root / ".demo" / "support-story"
            write_json(
                story / "state.json",
                {
                    "proof": {
                        "certified": True,
                        "red_refund_executed": True,
                        "green_refund_attempted": True,
                        "green_refund_blocked": True,
                        "green_blocked_before_execution_assertion_passed": True,
                        "regression_loaded_and_passed": True,
                        "green_failed": 0,
                    }
                },
            )
            write_json(
                story / "red" / "summary.json",
                {
                    "failed": 3,
                    "passed": 0,
                    "integrations": {
                        "sentry_event_ids": ["event-1", "event-2"],
                        "sentry_events": [
                            {
                                "event_id": "event-1",
                                "tags": {
                                    "scenario": "support-story",
                                    "attack_id": "generated-refund-001",
                                    "dangerous_tool": "issue_refund",
                                    "blocked_before_execution": "false",
                                },
                                "fingerprint": [
                                    "redteamci",
                                    "support_story_red",
                                    "generated-refund-001",
                                    "issue_refund",
                                ],
                                "extra": {
                                    "trace_path": ".demo/support-story/red/traces/run_001/generated-refund-001.json",
                                    "summary_path": ".demo/support-story/red/summary.json",
                                    "regression_artifact_paths": [
                                        ".demo/support-story/regressions/generated_attacks.json"
                                    ],
                                },
                            }
                        ],
                    },
                },
            )
            write_json(story / "green" / "summary.json", {"failed": 0, "passed": 4})
            write_json(
                story / "plan" / "generated_support_attacks.json",
                [{"id": "generated-refund-001"}],
            )
            write_json(story / "patches" / "support_story_summary.json", {"success": True})
            write_json(
                story / "regressions" / "generated_attacks.json",
                [{"id": "regression-generated-refund-001"}],
            )

            state = load_support_story_dashboard_state(root)

        self.assertTrue(state["available"])
        self.assertTrue(support_story_certified(state["proof"]))
        self.assertTrue(state["remediation_summary_exists"])
        self.assertTrue(state["generated_regression_exists"])
        self.assertEqual(demo_readiness_status(state)["status"], "ready")
        self.assertEqual(state["red_summary"]["failed"], 3)
        self.assertEqual(state["red_sentry_event_ids"], ["event-1", "event-2"])
        context = build_sentry_dashboard_context(
            state,
            {
                "SENTRY_DSN": "https://example.invalid/1",
                "SENTRY_ENVIRONMENT": "local-demo",
                "SENTRY_RELEASE": "abc123",
                "SENTRY_BASE_URL": "https://sentry.example",
                "SENTRY_ORG": "demo-org",
                "SENTRY_PROJECT": "redteamci",
            },
        )
        self.assertTrue(context["configured"])
        self.assertEqual(context["event_ids"], ["event-1", "event-2"])
        self.assertEqual(context["tags"]["attack_id"], "generated-refund-001")
        self.assertEqual(
            context["fingerprint"],
            ["redteamci", "support_story_red", "generated-refund-001", "issue_refund"],
        )
        self.assertIn("event.id%3Aevent-1", context["open_url"])
        self.assertFalse(build_sentry_dashboard_context(state, {})["configured"])
        self.assertEqual(state["green_summary"]["passed"], 4)
        self.assertEqual(state["attack_pack"], [{"id": "generated-refund-001"}])
        self.assertIn(
            ".demo/support-story/state.json",
            {artifact["path"] for artifact in state["artifacts"]},
        )

        incomplete = dict(state["proof"])
        incomplete["green_refund_blocked"] = False
        self.assertFalse(support_story_certified(incomplete))


if __name__ == "__main__":
    unittest.main()
