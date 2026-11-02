"""Agent harness: learn, diagnose, recall, and the finding evidence gate."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import harness
from netcast3r.server.index import Index


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "netcast3r.db")
        self.mission = self.index.create_mission(
            title="Harness lab", target="https://example.com",
            objective="prove the harness compounds memory",
            scope=["example.com"], status="active", autonomy="supervised")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_status_and_diagnose_are_evidence_backed(self):
        snap = harness.status(self.index)
        self.assertTrue(snap["ok"])
        self.assertIn("director", snap)
        self.assertIn("memory", snap)
        self.assertIn("hunt", snap)

        diagnosis = harness.diagnose(self.index, mission_id=self.mission["id"])
        self.assertEqual(diagnosis["mission_id"], self.mission["id"])
        self.assertTrue(diagnosis["issues"])

    def test_learn_tick_reflects_failed_tool_calls(self):
        call = self.index.add_tool_call(
            tool="http_probe", risk="medium", status="denied",
            actor="test", mission_id=self.mission["id"],
            args={"target": "https://evil.example", "mission_id": self.mission["id"]},
            result={"ok": False}, error="target is outside the declared scope")
        learned = harness.learn_tick(self.index, mission_id=self.mission["id"])
        self.assertGreaterEqual(len(learned["lessons_created"]), 1)
        self.assertEqual(learned["lessons_created"][0]["source"],
                         f"tool_call:{call['id']}")
        # Second tick is idempotent for the same call.
        again = harness.learn_tick(self.index, mission_id=self.mission["id"])
        self.assertEqual(again["lessons_created"], [])

    def test_develop_skill_from_repeated_successes(self):
        for index in range(2):
            self.index.add_lesson(
                title=f"path diff win {index}",
                lesson=("Encoded final segment skipped the route gate and reached "
                        "the handler with a 400 validation body."),
                technique="http_path_diff", outcome="success",
                next_step="Confirm the object entitlement next.",
                tags=["authz", "encoding"], mission_id=self.mission["id"],
                source=f"manual:{index}")
        developed = harness.develop_skill(
            self.index, mission_id=self.mission["id"], limit=2, apply=True)
        self.assertEqual(len(developed["created"]), 1)
        skill = self.index.get_skill(developed["created"][0]["name"])
        self.assertIsNotNone(skill)
        self.assertEqual(skill["status"], "draft")
        self.assertIn("http_path_diff", skill["body"])

    def test_recall_returns_progressive_pack(self):
        self.index.upsert_skill(
            name="authz-matrix", body="# Authz\n\nTest each role against each object.\n" * 8,
            title="Authz matrix", description="two-account object matrix",
            tags=["authz", "idor"], source="test")
        self.index.set_skill_status("authz-matrix", "active")
        pack = harness.recall(
            self.index, mission_id=self.mission["id"], goal="test idor authz")
        self.assertTrue(pack["skills"])
        self.assertEqual(pack["skills"][0]["name"], "authz-matrix")
        self.assertIn("issues", pack)
        self.assertIn("next_actions", pack)

    def test_finding_requires_evidence(self):
        with self.assertRaises(ValueError):
            self.index.create_finding("Bare claim", "high")
        finding = self.index.create_finding(
            "IDOR on /api/orders/{id}", "high",
            evidence=("GET /api/orders/2 as user A returned user B's order "
                      "payload with HTTP 200."),
            impact="Cross-account order disclosure.", source="manual")
        self.assertTrue(finding["id"].startswith("fnd_"))
        self.assertGreaterEqual(len(finding["evidence"]), 32)


if __name__ == "__main__":
    unittest.main()
