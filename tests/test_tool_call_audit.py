"""Tool-call audit compaction and API pagination helpers."""

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.autopilot import prepare_tool_call_audit
from netcast3r.server import build_server


class ToolCallAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            title="audit", target="https://lab.example.com")

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_successful_http_audit_keeps_body_sample_not_raw_body(self):
        payload = {
            "ok": True,
            "tool": "http_probe",
            "status": 200,
            "url": "https://lab.example.com/",
            "body": '{"token":"visible-in-sample"}',
            "headers": {"content-type": "application/json",
                        "set-cookie": "session=secret"},
            "tls_insecure": True,
            "tls_fallback": "ConnectError",
        }
        stored = prepare_tool_call_audit("http_probe", "ok", payload)
        self.assertIn("body_sample", stored)
        self.assertIn("token", stored["body_sample"])
        self.assertNotIn("body", stored)
        self.assertNotIn("set-cookie", stored.get("headers", {}))
        self.assertTrue(stored["tls_insecure"])
        self.assertEqual(stored["tls_fallback"], "ConnectError")

    def test_add_tool_call_persists_compacted_http_result(self):
        call = self.server.index.add_tool_call(
            "http_request", status="ok", mission_id=self.mission["id"],
            result={
                "status": 200,
                "url": "https://lab.example.com/api",
                "body": '{"hint":"keep-me"}',
                "set_cookie": ["sid=super-secret"],
            },
        )
        result = call["result"]
        self.assertIn("body_sample", result)
        self.assertIn("hint", result["body_sample"])
        self.assertNotIn("body", result)
        serialized = json.dumps(result)
        self.assertNotIn("super-secret", serialized)

    def test_add_lesson_ignores_unknown_draft_fields(self):
        lesson = self.server.index.add_lesson(
            title="probe: success",
            lesson="http_probe succeeded.",
            extra_draft_field="ignored",
            another="also ignored",
        )
        self.assertTrue(lesson["id"].startswith("lsn_"))


class QueryPaginationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def call(self, method, path, query=None):
        headers = {"host": "127.0.0.1:7857", "x-netcast3r-token": self.server.token}
        if "?" in path:
            base, qs = path.split("?", 1)
            parsed = dict(item.split("=", 1) for item in qs.split("&") if "=" in item)
            return self.server.route(method, base, parsed, headers, b"")
        return self.server.route(method, path, dict(query or {}), headers, b"")

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_hypotheses_honor_limit_query_param(self):
        mission = self.server.index.create_mission(title="h", target="https://h.example.com")
        for index in range(3):
            self.server.index.create_hypothesis(
                title=f"lead {index}", target="https://h.example.com",
                mission_id=mission["id"])
        response = self.call(
            "GET",
            f"/api/v1/hypotheses?mission_id={mission['id']}&limit=2&offset=0",
        )
        self.assertEqual(response.status, 200)
        payload = self.data(response)
        self.assertEqual(len(payload["items"]), 2)
        self.assertGreaterEqual(payload["total"], 3)


if __name__ == "__main__":
    unittest.main()
