import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.mcp import tools
from netcast3r.server.index import Index


class HypothesisStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.index = Index(self.base / "index.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_create_list_and_patch(self):
        hypothesis = self.index.create_hypothesis(
            "Percent-encoded route bypasses the scope guard",
            target="https://example.com", technique="path-encoding",
            rationale="the router normalises before the guard",
            expected="encoded path returns 200 while the plain path returns 403")
        self.assertTrue(hypothesis["id"].startswith("hyp"))
        self.assertEqual(hypothesis["status"], "open")
        self.assertEqual(hypothesis["target"], "https://example.com")

        items, total = self.index.list_hypotheses(q="encoded")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["id"], hypothesis["id"])

        patched = self.index.patch_hypothesis(
            hypothesis["id"], status="refuted",
            result={"ok": False, "failed": 1})
        self.assertEqual(patched["status"], "refuted")
        self.assertEqual(patched["result"]["failed"], 1)

    def test_mission_target_is_inherited(self):
        mission = self.index.create_mission(
            "Example", target="example.com", scope=["example.com"])
        hypothesis = self.index.create_hypothesis(
            "Test the API", mission_id=mission["id"])
        self.assertEqual(hypothesis["target"], "example.com")

    def test_promotion_is_refused_until_supported(self):
        hypothesis = self.index.create_hypothesis(
            "A precise test", target="https://example.com")
        with self.assertRaises(ValueError):
            self.index.promote_hypothesis(
                hypothesis["id"], title="Too early", severity="high",
                impact="none")
        self.index.patch_hypothesis(
            hypothesis["id"], status="supported",
            result={"ok": False, "failed": 1})
        with self.assertRaises(ValueError):
            self.index.promote_hypothesis(
                hypothesis["id"], title="Still too early", severity="high",
                impact="none")

    def test_supported_hypothesis_promotes_with_evidence(self):
        mission = self.index.create_mission(
            "Example", target="example.com", scope=["example.com"])
        hypothesis = self.index.create_hypothesis(
            "Encoded path bypass", mission_id=mission["id"],
            technique="path-encoding", expected="encoded path returns 200")
        self.index.patch_hypothesis(
            hypothesis["id"], status="supported",
            result={"ok": True, "passed": 2, "failed": 0,
                    "results": [{"step": 1, "pass": True}]})
        finding = self.index.promote_hypothesis(
            hypothesis["id"], title="Scope bypass via encoded path",
            severity="high", impact="deploy token reaches manage routes",
            tags=["confirmed"])
        self.assertTrue(finding["id"].startswith("fnd"))
        self.assertEqual(finding["source"], f"hypothesis:{hypothesis['id']}")
        self.assertIn(hypothesis["id"], finding["tags"])
        self.assertEqual(finding["secret_type"], "path-encoding")
        artifacts = self.index.list_finding_artifacts(finding["id"])
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0]["content_type"], "application/json")
        promoted = self.index.get_hypothesis(hypothesis["id"])
        self.assertEqual(promoted["status"], "promoted")
        self.assertEqual(promoted["finding_id"], finding["id"])
        with self.assertRaises(ValueError):
            self.index.promote_hypothesis(
                hypothesis["id"], title="Duplicate", severity="high",
                impact="none")


class HypothesisToolTests(unittest.TestCase):
    def test_hypothesis_test_marks_supported(self):
        calls = []

        def fake_call(ctx, method, path, body=None, **kwargs):
            calls.append((method, path, body))
            if method == "GET":
                return {"id": "hyp_1", "title": "Precise test",
                        "target": "https://example.com", "mission_id": "msn_1"}
            return {"id": "hyp_1", "status": body["status"],
                    "result": body["result"]}

        ctx = SimpleNamespace(base="/tmp", policy="supervised")
        args = {"hypothesis_id": "hyp_1", "steps": [
            {"path": "/api", "expect_status": 200}]}
        with mock.patch.object(tools, "_call", side_effect=fake_call), \
                mock.patch.object(tools, "http_request",
                                  return_value={"status": 200, "body": "ok",
                                                "headers": {}}):
            result = tools.hypothesis_test(ctx, args)
        self.assertEqual(result["status"], "supported")
        self.assertEqual(calls[-1][0], "PATCH")
        self.assertEqual(calls[-1][2]["status"], "supported")


if __name__ == "__main__":
    unittest.main()
