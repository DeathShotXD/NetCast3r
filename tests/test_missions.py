import tempfile
import unittest
from pathlib import Path

from netcast3r.server.index import Index


class MissionIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.index = Index(self.tmp / "index.db")

    def tearDown(self):
        self.index.conn.close()

    def test_create_list_and_filter_missions(self):
        mission = self.index.create_mission(
            "Operation Test", "example.com", "Check authz",
            status="draft", autonomy="supervised",
            budget={"max_usd": 25}, scope=["example.com", "api.example.com"],
        )
        self.assertEqual(mission["status"], "draft")
        self.assertEqual(mission["budget"], {"max_usd": 25})
        self.assertEqual(mission["scope"], ["example.com", "api.example.com"])

        active = self.index.create_mission("Operation Two", "api.example.com", status="active")
        self.assertIsNotNone(active["started_at"])

        items, total = self.index.list_missions()
        self.assertEqual(total, 2)
        self.assertEqual(len(items), 2)
        drafts, total = self.index.list_missions(status="draft")
        self.assertEqual(total, 1)
        self.assertEqual(drafts[0]["id"], mission["id"])

    def test_create_requires_title_and_target(self):
        with self.assertRaises(ValueError):
            self.index.create_mission("", "example.com")
        with self.assertRaises(ValueError):
            self.index.create_mission("Operation Test", "")

    def test_patch_status_sets_timestamps(self):
        mission = self.index.create_mission("Operation Test", "example.com")
        active = self.index.patch_mission(mission["id"], status="active")
        self.assertEqual(active["status"], "active")
        self.assertIsNotNone(active["started_at"])
        done = self.index.patch_mission(mission["id"], status="done")
        self.assertEqual(done["status"], "done")
        self.assertIsNotNone(done["finished_at"])

    def test_runs_link_to_a_mission(self):
        mission = self.index.create_mission("Operation Test", "example.com")
        with self.index.conn:
            self.index.conn.execute(
                "INSERT INTO runs (id, target, status, created_at, started_at, options_json, counts_json) "
                "VALUES ('run_1', 'example.com', 'done', '2026-10-28T00:00:00Z', "
                "'2026-10-28T00:00:00Z', '{}', '{}')"
            )
        updated = self.index.add_mission_run(mission["id"], "run_1")
        self.assertEqual(updated["run_count"], 1)
        self.assertEqual(updated["last_run_id"], "run_1")
        self.assertEqual(updated["runs"][0]["id"], "run_1")

    def test_approval_decision_cannot_be_replayed(self):
        mission = self.index.create_mission("Operation Test", "example.com")
        approval = self.index.create_approval(
            mission["id"], "Run active authz test", risk="high", reason="two accounts"
        )
        self.assertEqual(approval["status"], "pending")
        self.assertTrue(approval["nonce"])
        pending, total = self.index.list_approvals(status="pending")
        self.assertEqual(total, 1)

        decided = self.index.decide_approval(approval["id"], "approved")
        self.assertEqual(decided["status"], "approved")
        with self.assertRaises(ValueError):
            self.index.decide_approval(approval["id"], "rejected")

        self.assertEqual(self.index.get_mission(mission["id"])["pending_approvals"], 0)

    def test_delete_mission_removes_links_and_approvals(self):
        mission = self.index.create_mission("Operation Test", "example.com")
        self.index.create_approval(mission["id"], "Risky action")
        self.assertTrue(self.index.delete_mission(mission["id"]))
        self.assertIsNone(self.index.get_mission(mission["id"]))
        self.assertEqual(self.index.list_approvals()[1], 0)


if __name__ == "__main__":
    unittest.main()
