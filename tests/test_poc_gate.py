"""PoC builder, live verify, and the candidate promotion gate."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from netcast3r import poc
from netcast3r.server import build_server


class PocBuilderTests(unittest.TestCase):
    def test_builds_curl_python_and_assertions(self):
        candidate = {
            "id": "cnd_1",
            "title": "Cloud metadata SSRF",
            "module_id": "web-ssrf-imds",
            "evidence": {
                "expected": "IMDS credentials",
                "steps": [{
                    "tool": "http_request",
                    "target": "https://lab.example.com/fetch?u=http://169.254.169.254/",
                    "observation": {
                        "method": "GET",
                        "headers": {"accept": "*/*"},
                        "status": 200,
                        "marker": "ami-id",
                    },
                }],
            },
        }
        result = poc.build_poc(candidate, {"target": "https://lab.example.com/"})
        self.assertTrue(result["ready"])
        self.assertEqual(result["reproduced_steps"], 1)
        self.assertIn("curl", result["curl"])
        self.assertIn("requests.request", result["python"])
        self.assertIn("ami-id", result["python"])
        self.assertEqual(result["assertions"][0]["expected_status"], 200)
        self.assertEqual(result["assertions"][0]["marker"], "ami-id")

    def test_verify_scores_assertions_with_transport(self):
        candidate = {
            "id": "cnd_2",
            "title": "IDOR",
            "module_id": "web-idor-object",
            "evidence": {"steps": [{
                "target": "https://lab.example.com/api/user/2",
                "observation": {"method": "GET", "status": 200,
                                "marker": "\"id\":2"},
            }]},
        }
        mission = {"target": "https://lab.example.com/",
                   "scope": ["lab.example.com"]}

        def transport(step):
            return {"status": 200, "body": '{"id":2,"email":"x"}',
                    "url": step["target"], "headers": {}}

        result = poc.verify_poc(candidate, mission, transport=transport)
        self.assertTrue(result["verified"])
        self.assertEqual(result["passed"], 1)
        self.assertEqual(result["failed"], 0)

    def test_verify_refuses_out_of_scope(self):
        candidate = {
            "id": "cnd_3",
            "title": "leak",
            "evidence": {"steps": [{
                "target": "https://evil.example.net/x",
                "observation": {"method": "GET", "status": 200, "marker": "ok"},
            }]},
        }
        mission = {"target": "https://lab.example.com/",
                   "scope": ["lab.example.com"]}
        result = poc.verify_poc(candidate, mission, transport=lambda s: {})
        self.assertFalse(result["verified"])
        self.assertIn("outside mission scope", result["results"][0]["error"])

    def test_promotion_gate_requires_steps_or_force(self):
        empty = {"id": "cnd_4", "title": "guess", "evidence": {"steps": []}}
        mission = {"target": "https://lab.example.com/"}
        refused = poc.promotion_gate(empty, mission)
        self.assertFalse(refused["allowed"])
        forced = poc.promotion_gate(empty, mission, force=True,
                                    notes="operator reviewed the raw capture")
        self.assertTrue(forced["allowed"])
        ready = {
            "id": "cnd_5", "title": "real",
            "evidence": {"steps": [{
                "target": "https://lab.example.com/a",
                "observation": {"method": "GET", "status": 200, "marker": "ok"},
            }]},
        }
        allowed = poc.promotion_gate(ready, mission)
        self.assertTrue(allowed["allowed"])
        self.assertIn("Reproduction", allowed["evidence"])


class PocRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "PoC", "https://lab.example.com/", status="active",
            scope=["lab.example.com"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def call(self, method, path, body=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_promote_refuses_without_poc_then_accepts_with_steps(self):
        bare = self.server.index.create_candidate(
            self.mission["id"], title="bare guess", module_id="web-idor",
            evidence={"steps": []})
        refused = self.call("POST", f"/api/v1/candidates/{bare['id']}/promote",
                            {"severity": "high"})
        self.assertEqual(refused.status, 400)

        ready = self.server.index.create_candidate(
            self.mission["id"], title="object read", module_id="web-idor",
            evidence={"expected": "other user object", "steps": [{
                "target": "https://lab.example.com/api/user/2",
                "observation": {"method": "GET", "status": 200,
                                "marker": "\"id\": 2",
                                "headers": {"accept": "application/json"}},
            }]})
        verify = self.call("POST",
                           f"/api/v1/candidates/{ready['id']}/poc/verify")
        # Live verify hits the network; without a lab it should still return
        # a structured body (fail is fine). Build and promote without verify.
        self.assertEqual(verify.status, 200)
        poc_body = self.call("POST", f"/api/v1/candidates/{ready['id']}/poc")
        self.assertEqual(poc_body.status, 200)
        self.assertTrue(self.data(poc_body)["ready"])
        promoted = self.call("POST",
                             f"/api/v1/candidates/{ready['id']}/promote",
                             {"severity": "high",
                              "notes": "reproduced object read"})
        self.assertEqual(promoted.status, 200)
        body = self.data(promoted)
        self.assertEqual(body["candidate"]["status"], "promoted")
        self.assertGreaterEqual(len(body["finding"]["evidence"]), 32)
        self.assertIn("Reproduction", body["finding"]["evidence"])


if __name__ == "__main__":
    unittest.main()
