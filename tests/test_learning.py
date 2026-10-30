import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import learning
from netcast3r.server.index import Index


class ReflectionTests(unittest.TestCase):
    def test_scope_failure_is_classified(self):
        draft = learning.reflect_tool_call({
            "id": "tcl_1", "tool": "http_probe", "status": "error",
            "error": "target is outside the declared scope",
            "args": {"target": "https://example.com"}, "result": {},
        })
        self.assertEqual(draft["outcome"], "failure")
        self.assertIn("scope", draft["tags"])
        self.assertIn("scope", draft["lesson"].lower())
        self.assertTrue(draft["next_step"])

    def test_policy_denial_is_blocked(self):
        draft = learning.reflect_tool_call({
            "id": "tcl_2", "tool": "recon_active", "status": "denied",
            "error": "approval required", "args": {},
        })
        self.assertEqual(draft["outcome"], "blocked")
        self.assertTrue({"policy", "approval"} & set(draft["tags"]))

    def test_timeout_is_reliability(self):
        draft = learning.reflect_tool_call({
            "id": "tcl_3", "tool": "http_request", "status": "error",
            "error": "request timed out after 15s", "args": {"target": "example.com"},
        })
        self.assertIn("reliability", draft["tags"])
        self.assertIn("backoff", draft["next_step"].lower())

    def test_success_names_the_tool_and_target(self):
        draft = learning.reflect_tool_call({
            "id": "tcl_4", "tool": "http_request", "status": "ok",
            "args": {"target": "https://api.example.com/v1"}, "result": {"status": 200},
        })
        self.assertEqual(draft["outcome"], "success")
        self.assertIn("http_request", draft["lesson"])
        self.assertIn("api.example.com", draft["context"])
        self.assertIn("HTTP 200", draft["lesson"])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "netcast3r.db")
        self.mission = self.index.create_mission(
            "Learning test", "example.com", scope=["example.com"])

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_lessons_round_trip_and_filter(self):
        lesson = self.index.add_lesson(
            "Use a path differential", "The encoded variant skipped the gate.",
            technique="http_path_diff", outcome="success", tags=["encoding", "authz"],
            mission_id=self.mission["id"], confidence=0.9)
        self.assertEqual(lesson["technique"], "http_path_diff")
        items, total = self.index.list_lessons(q="encoded")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["id"], lesson["id"])
        items, total = self.index.list_lessons(tag="authz", outcome="success")
        self.assertEqual(total, 1)
        self.assertEqual(self.index.get_lesson(lesson["id"])["title"],
                         "Use a path differential")
        self.assertTrue(self.index.delete_lesson(lesson["id"]))

    def test_skill_versions_in_place(self):
        first = self.index.upsert_skill("idor-checklist", "# IDOR\n\nCheck ids.",
                                        tags=["idor"], source="writeup")
        self.assertEqual(first["version"], 1)
        second = self.index.upsert_skill("idor-checklist", "# IDOR\n\nCheck ids and roles.",
                                         description="two objects", tags=["idor"])
        self.assertEqual(second["version"], 2)
        self.assertEqual(second["id"], first["id"])
        self.assertIn("roles", second["body"])
        items, total = self.index.list_skills(q="idor")
        self.assertEqual(total, 1)
        self.assertEqual(self.index.get_skill("idor-checklist")["id"], first["id"])
        self.assertTrue(self.index.delete_skill("idor-checklist"))

    def test_reflect_run_and_suggest_next(self):
        call = self.index.add_tool_call(
            "http_probe", status="error", mission_id=self.mission["id"],
            args={"target": "https://example.com"},
            error="target is outside the declared scope")
        draft = learning.reflect_tool_call(call)
        self.index.add_lesson(**draft)
        self.index.add_lesson(
            "Tag-only lesson", "A tagged note.", tags=["example"],
            next_step="Test the tagged surface", mission_id=self.mission["id"])
        actions = learning.suggest_next(self.index, self.mission["id"])
        self.assertEqual(actions["mission_id"], self.mission["id"])
        self.assertTrue(actions["actions"])
        self.assertTrue(all(item["tool"] for item in actions["actions"]))
        self.assertIn("Test the tagged surface",
                      [item["title"] for item in actions["actions"]])


if __name__ == "__main__":
    unittest.main()
