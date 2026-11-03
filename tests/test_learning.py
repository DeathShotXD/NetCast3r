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
        items, total = self.index.list_lessons(mission_id=self.mission["id"])
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

    def test_skill_lifecycle_counts_and_status(self):
        skill = self.index.upsert_skill("path-diff", "# Path diff\n\nEncode the segment.")
        self.assertEqual(skill["status"], "active")
        used = self.index.use_skill("path-diff", success=True)
        self.assertEqual(used["use_count"], 1)
        self.assertEqual(used["success_count"], 1)
        failed = self.index.use_skill(skill["id"], success=False)
        self.assertEqual(failed["use_count"], 2)
        self.assertEqual(failed["success_count"], 1)
        retired = self.index.set_skill_status("path-diff", "retired")
        self.assertEqual(retired["status"], "retired")
        active, total = self.index.list_skills(status="active")
        self.assertEqual(total, 0)
        with self.assertRaises(ValueError):
            self.index.set_skill_status("path-diff", "bogus")

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
        self.index.add_lesson(
            "Mission-only lesson", "An unlabelled training note.",
            tags=["unrelatedtag"], next_step="Try the mission-only step",
            mission_id=self.mission["id"])
        actions = learning.suggest_next(self.index, self.mission["id"])
        self.assertEqual(actions["mission_id"], self.mission["id"])
        self.assertTrue(actions["actions"])
        self.assertTrue(all(item["tool"] for item in actions["actions"]))
        titles = [item["title"] for item in actions["actions"]]
        self.assertIn("Test the tagged surface", titles)
        self.assertIn("Try the mission-only step", titles)

    def test_successful_probe_contradicts_unreachable_lesson(self):
        stale = self.index.add_lesson(
            "http_probe: failure",
            "http_probe returned error: ConnectError on stale.example.com",
            technique="http_probe",
            context="stale.example.com",
            outcome="failure",
            tags=["failure", "http_probe", "stale.example.com"],
            mission_id=self.mission["id"],
        )
        self.index.add_tool_call(
            "http_probe", status="ok", mission_id=self.mission["id"],
            args={"target": "https://stale.example.com/"},
            result={"status": 200, "url": "https://stale.example.com/"},
        )
        updated = self.index.get_lesson(stale["id"])
        self.assertIn("contradicted", updated["tags"])
        self.assertIn("superseded", updated["tags"])
        self.assertIn("provisional=false", updated["tags"])
        self.assertNotIn("provisional=true", updated["tags"])
        self.assertEqual(updated["outcome"], "observation")
        self.assertFalse(updated["provisional"])
        self.assertTrue(updated["contradicted"])
        self.assertTrue(learning.lesson_is_active(updated) is False)

    def test_failure_lesson_tags_host_error_class_and_provisional_then_supersedes(self):
        failed = self.index.add_tool_call(
            "http_probe", status="error", mission_id=self.mission["id"],
            args={"target": "https://apply.example.com/login"},
            error="probe failed: ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED]",
        )
        draft = learning.reflect_tool_call(failed)
        self.assertEqual(draft["host"], "apply.example.com")
        self.assertEqual(draft["error_class"], "ConnectError")
        self.assertTrue(draft["provisional"])
        self.assertIn("host:apply.example.com", draft["tags"])
        self.assertIn("error_class:ConnectError", draft["tags"])
        self.assertIn("provisional=true", draft["tags"])

        stored = self.index.add_lesson(**draft)
        self.assertTrue(stored["provisional"])
        self.assertFalse(stored["contradicted"])
        self.assertEqual(stored["host"], "apply.example.com")
        self.assertEqual(stored["error_class"], "ConnectError")

        res = learning.supersede_host_lesson(
            self.index, "apply.example.com", mission_id=self.mission["id"],
            status_code=200, tool="http_probe", tls_insecure=True,
        )
        self.assertEqual(res["lessons"], 1)
        self.assertIn(stored["id"], res["contradicted_ids"])
        refreshed = self.index.get_lesson(stored["id"])
        self.assertTrue(refreshed["contradicted"])
        self.assertFalse(refreshed["provisional"])
        self.assertIn("provisional=false", refreshed["tags"])

    def test_supported_hypothesis_compounds_verified_skill(self):
        hyp = self.index.create_hypothesis(
            "BOLA on apply.example.com/admit",
            target="https://apply.example.com/admit",
            mission_id=self.mission["id"],
            technique="bola",
            rationale="Object id looks sequential on a live portal path.",
            expected="Account A reads account B record with only the id changed.",
        )
        self.index.patch_hypothesis(
            hyp["id"],
            status="supported",
            result={"ok": True, "passed": 1, "failed": 0, "steps": 1},
        )
        skill = self.index.get_skill("verified-bola")
        self.assertIsNotNone(skill)
        self.assertIn("verified-ttp", skill["tags"])
        self.assertIn("bola", skill["tags"])
        self.assertIn("Expected observation", skill["body"])
        self.assertNotIn("payload", skill["body"].lower())

    def test_suggest_next_prefers_verified_skill_and_skips_contradicted(self):
        self.index.upsert_skill(
            "verified-idor",
            "# Verified IDOR\n\nChecklist for two-account object reads.",
            title="Verified IDOR",
            tags=["verified-ttp", "idor", "example.com"],
            source="test",
        )
        self.index.add_lesson(
            "Stale host lesson",
            "Host unreachable [superseded: HTTP 200]",
            tags=["contradicted", "superseded", "example.com"],
            outcome="observation",
            next_step="Ignore this stale step",
            mission_id=self.mission["id"],
        )
        self.index.add_lesson(
            "Active lesson",
            "A live note.",
            tags=["example"],
            next_step="Follow the active lesson",
            mission_id=self.mission["id"],
        )
        actions = learning.suggest_next(self.index, self.mission["id"])
        titles = [item["title"] for item in actions["actions"]]
        self.assertTrue(any(t.startswith("Load verified playbook") for t in titles))
        self.assertNotIn("Ignore this stale step", titles)
        self.assertIn("Follow the active lesson", titles)


if __name__ == "__main__":
    unittest.main()
