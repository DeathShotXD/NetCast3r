import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import discovery, exploits
from netcast3r.server import build_server


class _LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"orders": [{"id": 7, "owner": "ada"}, {"id": 8, "owner": "bob"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def supporting(messages=None):
    return {"text": json.dumps({"verdict": "supports", "reason": "a real difference"}),
            "provider": "fake", "model": "free"}


class ModuleExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.lab = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
        threading.Thread(target=self.lab.serve_forever, daemon=True).start()
        self.target = f"http://127.0.0.1:{self.lab.server_address[1]}/"
        self.mission = self.index.create_mission(
            "Exec", self.target, status="active", scope=["127.0.0.1"])

    def tearDown(self):
        if getattr(self.server, "exploit_runner", None) is not None:
            self.server.exploit_runner.shutdown(wait=True)
        self.lab.shutdown()
        self.lab.server_close()
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_a_module_runs_and_stages_a_candidate_not_a_finding(self):
        from netcast3r.server.exploit_runner import ExploitRunner

        runner = ExploitRunner(self.server, complete=supporting)
        run = runner.start(self.mission["id"], "web-idor-object",
                           {"policy": "supervised"})
        deadline = time.time() + 30
        state = None
        while time.time() < deadline:
            state = self.index.get_run(run["id"])
            if state["status"] in ("done", "failed", "stopped"):
                break
            time.sleep(0.05)
        runner.shutdown(wait=True)
        self.assertEqual(state["status"], "done", state.get("error"))
        self.assertEqual(state["counts"]["mode"], "exploit")
        self.assertEqual(state["counts"]["state"], "verified")
        self.assertEqual(state["counts"]["findings"], 0)
        candidates = self.index.list_candidates(self.mission["id"])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["status"], "candidate")
        self.assertEqual(candidates[0]["module_id"], "web-idor-object")
        # A candidate is not a finding.
        self.assertEqual(self.index.totals().get("findings", 0), 0)

    def test_an_unknown_module_is_refused(self):
        from netcast3r.server.exploit_runner import ExploitRunner

        runner = ExploitRunner(self.server, complete=supporting)
        try:
            with self.assertRaises(ValueError):
                runner.start(self.mission["id"], "nope-not-a-module")
        finally:
            runner.shutdown(wait=True)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Cand", "https://acme.example/", status="active", scope=["acme.example"])
        self.candidate = self.index.create_candidate(
            self.mission["id"], title="IDOR on /api/orders", severity="high",
            module_id="web-idor-object",
            evidence={"module": "web-idor-object", "supports": 2})

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def call(self, method, path, body=None, query=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, query or {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_a_candidate_is_listed_and_promoted_by_an_operator(self):
        listing = self.call("GET", f"/api/v1/missions/{self.mission['id']}/candidates")
        self.assertEqual(len(self.data(listing)["items"]), 1)
        promote = self.call(
            "POST", f"/api/v1/candidates/{self.candidate['id']}/promote",
            {"severity": "high", "impact": "A user reads another user's order"})
        self.assertEqual(promote.status, 200)
        body = self.data(promote)
        self.assertEqual(body["candidate"]["status"], "promoted")
        self.assertEqual(body["finding"]["severity"], "high")
        self.assertEqual(self.index.totals().get("findings", 0), 1)
        # Promoting twice is refused.
        again = self.call(
            "POST", f"/api/v1/candidates/{self.candidate['id']}/promote", {})
        self.assertEqual(again.status, 409)

    def test_a_candidate_can_be_dismissed(self):
        dismiss = self.call(
            "POST", f"/api/v1/candidates/{self.candidate['id']}/dismiss", {})
        self.assertEqual(dismiss.status, 200)
        self.assertEqual(self.data(dismiss)["status"], "dismissed")
        self.assertEqual(self.index.totals().get("findings", 0), 0)


class ParameterExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Params", "https://acme.example/", status="active", scope=["acme.example"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_parameters_are_read_from_stored_evidence(self):
        self.index.upsert_graph_node(self.mission["id"], "endpoint",
                                     "https://acme.example/api/orders?id=7&page=2")
        self.index.add_agent_note(self.mission["id"], "note", "api",
                                  "filter params: ?q=x and {\"limit\": 10}")
        result = discovery.extract_parameters(self.index, self.mission["id"])
        names = {row["name"] for row in result["parameters"]}
        for expected in ("id", "page", "q", "limit"):
            self.assertIn(expected, names)
        nodes = self.index.list_graph_nodes(self.mission["id"], kind="parameter")
        self.assertGreaterEqual(len(nodes), 4)
        entries = self.index.list_kb_entries(scope="global", kind="parameter")
        self.assertGreaterEqual(len(entries), 4)
        self.assertEqual(self.index.totals().get("findings", 0), 0)

    def test_params_route(self):
        self.index.upsert_graph_node(self.mission["id"], "endpoint",
                                     "https://acme.example/x?token=abc")
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        body = json.dumps({"limit": 50}).encode()
        response = self.server.route(
            "POST", f"/api/v1/missions/{self.mission['id']}/params", {}, headers, body)
        self.assertEqual(response.status, 200)
        payload = json.loads(response.body.decode())
        self.assertIn("token", {row["name"] for row in payload["parameters"]})


class ExecutionSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Surface", "https://acme.example/", status="active", scope=["acme.example"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_the_execution_tools_are_catalogued(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        names = [tool["name"] for tool in catalog()]
        for name in ("exploit_run", "candidates_list", "candidate_promote",
                     "candidate_dismiss", "params_extract"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)

    def test_the_run_route_passes_the_module(self):
        class FakeExploits:
            def __init__(self):
                self.calls = []

            def start(self, mission_id, module_id, options):
                self.calls.append((mission_id, module_id, dict(options)))
                return {"id": "run_fake", "options": dict(options)}

        fake = FakeExploits()
        self.server._exploits = lambda: fake
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        body = json.dumps({"module_id": "web-idor-object",
                           "policy": "full"}).encode()
        response = self.server.route(
            "POST", f"/api/v1/missions/{self.mission['id']}/exploits/run",
            {}, headers, body)
        self.assertEqual(response.status, 201)
        mission_id, module_id, options = fake.calls[0]
        self.assertEqual(mission_id, self.mission["id"])
        self.assertEqual(module_id, "web-idor-object")
        self.assertEqual(options["policy"], "full")


if __name__ == "__main__":
    unittest.main()
