import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import evolve, graph, postex
from netcast3r.server import build_server


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Evo", "https://acme.example/", status="active", scope=["acme.example"])

    def tearDown(self):
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_ledger_counts_outcomes_from_evidence(self):
        for status in ("supported", "refuted", "refuted"):
            hyp = self.index.create_hypothesis(
                "lead", target="https://acme.example/x",
                mission_id=self.mission["id"], technique="web-sqli-error")
            self.index.patch_hypothesis(hyp["id"], status=status)
        run = self.index.create_run("https://acme.example/",
                                    {"mode": "exploit", "module_id": "web-idor-object"})
        self.index.update_run(run["id"], status="done", counts_json={
            "mode": "exploit", "module_id": "web-idor-object", "state": "verified"})
        self.index.add_mission_run(self.mission["id"], run["id"])
        self.index.create_candidate(self.mission["id"], title="IDOR",
                                    module_id="web-idor-object", severity="high")
        table = {row["technique"]: row for row in evolve.ledger(self.index)["techniques"]}
        self.assertEqual(table["web-sqli-error"]["supported"], 1)
        self.assertEqual(table["web-sqli-error"]["refuted"], 2)
        self.assertEqual(table["web-sqli-error"]["win_rate"], 0.33)
        self.assertEqual(table["web-idor-object"]["verified"], 1)
        self.assertEqual(table["web-idor-object"]["candidates"], 1)

    def test_mature_outcomes_bumps_expertise_only_on_a_real_outcome(self):
        target = {"tech": ["graphql", "nginx"]}
        self.index.upsert_target_profile(self.mission["id"], **target)
        before = evolve.mature_outcomes(self.index, self.mission["id"])
        self.assertEqual(before["outcome"], "partial")
        hyp = self.index.create_hypothesis(
            "lead", target="https://acme.example/x",
            mission_id=self.mission["id"], technique="api-graphql-introspection")
        self.index.patch_hypothesis(hyp["id"], status="supported")
        after = evolve.mature_outcomes(self.index, self.mission["id"])
        self.assertEqual(after["outcome"], "success")
        expertise = {row["tech"]: row for row in self.index.list_expertise(limit=50)}
        self.assertIn("graphql", expertise)
        self.assertGreaterEqual(expertise["graphql"]["successes"], 1)

    def test_scan_proposes_and_never_applies(self):
        for _ in range(4):
            hyp = self.index.create_hypothesis(
                "dead lead", target="https://acme.example/x",
                mission_id=self.mission["id"], technique="web-xxe")
            self.index.patch_hypothesis(hyp["id"], status="refuted")
        result = evolve.scan(self.index, limit=3)
        self.assertTrue(result["created"])
        self.assertIn("human-gated", result["note"])
        titles = [p["title"] for p in self.index.list_upgrade_proposals(limit=200)]
        self.assertTrue(any("web-xxe" in title for title in titles))
        # A second scan does not duplicate the pattern proposal.
        again = evolve.scan(self.index, limit=3)
        self.assertFalse(any("web-xxe" in p["title"] for p in again["created"]))


class PostexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "PostEx", "https://acme.example/", status="active", scope=["acme.example"])

    def tearDown(self):
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_plan_reads_the_graph(self):
        graph.rebuild(self.index, self.mission["id"])
        self.index.upsert_graph_node(self.mission["id"], "service", "445/tcp",
                                     label="445/tcp microsoft-ds")
        self.index.upsert_graph_node(self.mission["id"], "technology", "aws",
                                     label="aws")
        self.index.upsert_graph_node(self.mission["id"], "identity", "svc-sql",
                                     label="svc-sql")
        result = postex.plan(self.index, self.mission["id"], limit=20)
        self.assertTrue(result["evidence"]["service"])
        self.assertTrue(result["evidence"]["domain_foothold"])
        self.assertTrue(result["evidence"]["cloud_provider"])
        ready = {item["module_id"]: item for item in result["objectives"]}
        self.assertTrue(ready["cloud-s3-public"]["ready"])
        self.assertIn("445/tcp microsoft-ds", result["services"])
        self.assertEqual(self.index.totals().get("findings", 0), 0)

    def test_missing_evidence_is_reported(self):
        graph.rebuild(self.index, self.mission["id"])
        result = postex.plan(self.index, self.mission["id"], limit=20)
        by_id = {item["module_id"]: item for item in result["objectives"]}
        self.assertFalse(by_id["id-kerberoast"]["ready"])
        self.assertIn("domain_foothold", by_id["id-kerberoast"]["missing"])


class EvolveSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Surface", "https://acme.example/", status="active", scope=["acme.example"])

    def tearDown(self):
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def call(self, method, path, body=None, query=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, query or {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_evolve_and_postex_routes(self):
        status = self.call("GET", "/api/v1/evolve")
        self.assertEqual(status.status, 200)
        self.assertIn("overall", self.data(status))
        ledger = self.call("GET", "/api/v1/evolve/ledger")
        self.assertEqual(ledger.status, 200)
        scan = self.call("POST", "/api/v1/evolve/scan", {"limit": 2})
        self.assertEqual(scan.status, 200)
        postex_route = self.call(
            "GET", f"/api/v1/missions/{self.mission['id']}/postex")
        self.assertEqual(postex_route.status, 200)
        self.assertIn("objectives", self.data(postex_route))

    def test_the_evolution_tools_are_catalogued(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        names = [tool["name"] for tool in catalog()]
        for name in ("evolve_status", "evolve_ledger", "evolve_scan", "postex_plan"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)

    def test_submissions_are_never_created(self):
        self.call("POST", "/api/v1/evolve/scan", {"limit": 2})
        self.assertEqual(self.server.index.list_submissions()[1], 0)


if __name__ == "__main__":
    unittest.main()
