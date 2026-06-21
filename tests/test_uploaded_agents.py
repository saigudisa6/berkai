from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from redteamci.uploads import (
    UploadedAgentError,
    ingest_uploaded_agent,
    uploaded_agent_run_args,
)


class UploadedAgentIntakeTest(unittest.TestCase):
    def test_manifest_upload_generates_runnable_attack_plan(self) -> None:
        manifest = """
schema_version: "0.1"
agent:
  id: uploaded-support-agent
  name: Uploaded Support Agent
  type: cli
  onboarding_level: 1
  trace_reporting: true
  command:
    - python
    - agent.py
tools:
  - name: issue_refund
    category: payment
  - name: send_email
    category: email
  - name: read_customer_data
    category: customer_data
sensitive_resources:
  - customer_pii
  - ssn
"""
        with tempfile.TemporaryDirectory() as tmp:
            state = ingest_uploaded_agent(
                "redteamci.agent.yaml",
                manifest.encode("utf-8"),
                root=Path(tmp),
            )

        self.assertTrue(state["available"])
        self.assertTrue(state["runnable"])
        self.assertEqual(state["agent"]["name"], "Uploaded Support Agent")
        self.assertEqual(state["proof_level"]["label"], "Level 1 trace/run mode")
        self.assertIn("generated-refund-001", state["attack_ids"])
        self.assertIn("generated-email-001", state["attack_ids"])
        self.assertIn("generated-pii-001", state["attack_ids"])
        self.assertIn("--config", uploaded_agent_run_args(state))

    def test_plain_source_upload_generates_limited_safe_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = ingest_uploaded_agent(
                "agent.py",
                b"print('not a redteamci cli contract')\n",
                root=Path(tmp),
            )

        self.assertTrue(state["available"])
        self.assertTrue(state["runnable"])
        self.assertEqual(state["tools"], [])
        self.assertEqual(state["attack_ids"], ["generated-safe-001"])

    def test_zip_path_traversal_is_rejected(self) -> None:
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("../evil.txt", "nope")

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(UploadedAgentError, "Unsafe zip path"):
                ingest_uploaded_agent("agent.zip", payload.getvalue(), root=Path(tmp))


if __name__ == "__main__":
    unittest.main()
