import json
import tempfile
import unittest
from pathlib import Path

from redteamci.dashboard import (
    LEVEL_1_WARNING,
    load_generated_plan_panel,
    onboarding_level_notice,
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


if __name__ == "__main__":
    unittest.main()
