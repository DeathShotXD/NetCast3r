import os
import unittest
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.mcp import tools


class TestCaseTests(unittest.TestCase):
    def test_assertions_pass_and_fail(self):
        responses = [
            {"status": 403, "body": '{"error":"forbidden"}', "headers": {}},
            {"status": 400, "body": '{"field":"invalid"}', "headers": {}},
        ]

        def fake_request(ctx, args):
            return responses.pop(0)

        ctx = SimpleNamespace(base="/tmp", policy="supervised")
        steps = [
            {"name": "baseline", "path": "/api/services/addons", "method": "POST",
             "expect_status": 403, "expect_body_contains": "forbidden"},
            {"name": "encoded", "path": "/api/services/%61ddons", "method": "POST",
             "expect_status": 400, "expect_body_contains": "invalid"},
        ]
        with mock.patch.object(tools, "http_request", side_effect=fake_request):
            result = tools.test_case_run(ctx, {
                "name": "scope differential", "base_url": "https://example.com",
                "steps": steps})
        self.assertTrue(result["ok"])
        self.assertEqual(result["passed"], 2)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["results"][1]["checks"][0]["actual"], 400)

    def test_failed_assertion_stops_by_default(self):
        def fake_request(ctx, args):
            return {"status": 500, "body": "trace", "headers": {}}

        ctx = SimpleNamespace(base="/tmp", policy="supervised")
        with mock.patch.object(tools, "http_request", side_effect=fake_request):
            result = tools.test_case_run(ctx, {
                "base_url": "https://example.com",
                "steps": [
                    {"path": "/a", "expect_status": 200},
                    {"path": "/b", "expect_status": 200},
                ]})
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed"], 1)
        self.assertEqual(len(result["results"]), 1)

    def test_empty_steps_are_rejected(self):
        ctx = SimpleNamespace(base="/tmp", policy="supervised")
        with self.assertRaises(tools.ToolError):
            tools.test_case_run(ctx, {"steps": []})


if __name__ == "__main__":
    unittest.main()
