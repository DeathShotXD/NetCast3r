import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import graph
from netcast3r.server import build_server


class FakeRegistry:
    def __init__(self, error=False, payload=None):
        self.calls = []
        self.error = error
        self.payload = payload or {}

    def call(self, name, args, actor=""):
        self.calls.append((name, dict(args), actor))
        if self.error:
            return {"error": {"message": "refused by test"}}, True
        body = {"ok": True, "url": args.get("target", ""), "status": 200,
                "title": "test"}
        body.update(self.payload)
        return body, False

    def names(self):
        return [name for name, _, _ in self.calls]


def verifier(verdict):
    def complete(role, messages):
        return {"text": json.dumps({"verdict": verdict, "reason": "judged"}),
                "provider": "fake", "model": "free"}
    return complete


class GraphBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Graph demo", "https://lab.example.com/", status="active",
            scope=["lab.example.com", "10.0.0.5"])
        self.run = self.index.create_run("https://lab.example.com/",
                                         {"mode": "hunt"})
        self.index.add_mission_run(self.mission["id"], self.run["id"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def seed(self):
        self.index.add_findings(self.run["id"], [{
            "title": "IDOR on order", "severity": "high",
            "value": "https://lab.example.com/api/orders/7", "source": "run"}])
        self.index.create_hypothesis(
            "Order lookup is IDOR",
            target="https://lab.example.com/api/orders/7",
            mission_id=self.mission["id"], technique="idor",
            expected="user B reads user A order")
        self.index.add_agent_note(self.mission["id"], "note", "saw login",
                                  "POST https://lab.example.com/login then /api/orders")
        self.index.add_tool_call("http_probe", risk="low", status="ok",
                                 actor="agent:swarm", mission_id=self.mission["id"],
                                 run_id=self.run["id"], args={
                                     "target": "https://lab.example.com/api/orders/7"},
                                 result={})

    def test_the_graph_is_derived_from_real_evidence(self):
        self.seed()
        summary = graph.rebuild(self.index, self.mission["id"])
        self.assertGreaterEqual(summary["nodes"], 6)
        self.assertGreaterEqual(summary["edges"], 6)
        nodes = {(n["kind"], n["key"]) for n in
                 self.index.list_graph_nodes(self.mission["id"])}
        self.assertIn(("host", "lab.example.com"), nodes)
        self.assertIn(("ip", "10.0.0.5"), nodes)
        self.assertIn(("finding", [n for n in
                                   self.index.list_graph_nodes(self.mission["id"])
                                   if n["kind"] == "finding"][0]["key"]), nodes)
        edges = self.index.list_graph_edges(self.mission["id"])
        kinds = {e["kind"] for e in edges}
        for kind in ("resolves_to", "in_scope", "tests", "leads_to", "exposes",
                     "tested_by"):
            self.assertIn(kind, kinds)
        # Every edge carries provenance.
        for edge in edges:
            self.assertTrue(edge["evidence"], edge)

    def test_rebuilding_is_idempotent(self):
        self.seed()
        graph.rebuild(self.index, self.mission["id"])
        first = (len(self.index.list_graph_nodes(self.mission["id"])),
                 len(self.index.list_graph_edges(self.mission["id"])),
                 len(self.index.list_graph_paths(self.mission["id"])))
        graph.rebuild(self.index, self.mission["id"])
        second = (len(self.index.list_graph_nodes(self.mission["id"])),
                  len(self.index.list_graph_edges(self.mission["id"])),
                  len(self.index.list_graph_paths(self.mission["id"])))
        self.assertEqual(first, second)

    def test_a_path_is_derived_per_open_lead_with_an_impact_step(self):
        self.seed()
        graph.rebuild(self.index, self.mission["id"])
        paths = self.index.list_graph_paths(self.mission["id"])
        self.assertEqual(len(paths), 1, paths)
        self.assertEqual(paths[0]["state"], "candidate")
        self.assertEqual([step["kind"] for step in paths[0]["steps"]],
                         ["test", "impact"])

    def test_a_hypothesis_node_is_marked_as_a_hypothesis(self):
        self.seed()
        graph.rebuild(self.index, self.mission["id"])
        hypotheses = self.index.list_graph_nodes(self.mission["id"],
                                                 kind="hypothesis")
        self.assertTrue(hypotheses)
        self.assertEqual(hypotheses[0]["confidence"], "hypothesis")


class PathVerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Verify demo", "https://lab.example.com/", status="active",
            scope=["lab.example.com"])
        self.index.create_hypothesis(
            "Order lookup is IDOR", target="https://lab.example.com/api/orders/7",
            mission_id=self.mission["id"], technique="idor",
            expected="user B reads user A order")
        graph.rebuild(self.index, self.mission["id"])
        self.path = self.index.list_graph_paths(self.mission["id"])[0]
        self.mission = self.index.get_mission(self.mission["id"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_verification_runs_scoped_steps_and_creates_no_finding(self):
        registry = FakeRegistry()
        result = graph.verify_path(self.index, self.mission, self.path, registry,
                                   complete=verifier("supports"))
        self.assertEqual(result["state"], "verified")
        self.assertEqual(result["findings"], 0)
        # One hypothesis step (a finding would add an impact step).
        self.assertEqual(registry.names(), ["http_request"])
        self.assertEqual(self.index.totals().get("findings", 0), 0)
        stored = self.index.get_graph_path(self.path["id"])
        self.assertEqual(stored["state"], "verified")
        self.assertEqual(stored["verdict"]["supports"], 1)

    def test_a_refuted_step_refutes_the_path(self):
        result = graph.verify_path(self.index, self.mission, self.path,
                                   FakeRegistry(), complete=verifier("refutes"))
        self.assertEqual(result["state"], "refuted")

    def test_without_a_verifier_model_a_run_is_inconclusive(self):
        result = graph.verify_path(self.index, self.mission, self.path,
                                   FakeRegistry(), complete=None)
        self.assertEqual(result["state"], "inconclusive")
        self.assertEqual(result["findings"], 0)

    def test_a_refused_tool_blocks_the_path(self):
        result = graph.verify_path(self.index, self.mission, self.path,
                                   FakeRegistry(error=True),
                                   complete=verifier("supports"))
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["blocked"], len(self.path["steps"]))


class _LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"orders": [{"id": 7, "owner": "ada"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class PathRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index

    def tearDown(self):
        if getattr(self.server, "path_runner", None) is not None:
            self.server.path_runner.shutdown(wait=True)
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_the_runner_turns_a_path_into_a_live_run(self):
        from netcast3r.server.path_runner import PathRunner

        lab = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
        threading.Thread(target=lab.serve_forever, daemon=True).start()
        try:
            target = f"http://127.0.0.1:{lab.server_address[1]}/"
            mission = self.index.create_mission(
                "Path live", target, status="active", scope=["127.0.0.1"])
            self.index.create_hypothesis(
                "Order API is readable", target=target + "api/orders/7",
                mission_id=mission["id"], technique="api",
                expected="a JSON order body")
            graph.rebuild(self.index, mission["id"])
            path = self.index.list_graph_paths(mission["id"])[0]

            def complete(messages):
                return {"text": json.dumps({"verdict": "supports",
                                            "reason": "json body returned"}),
                        "provider": "fake", "model": "free"}

            runner = PathRunner(self.server, complete=complete)
            run = runner.start(path["id"], {"policy": "supervised"})
            deadline = time.time() + 30
            state = None
            while time.time() < deadline:
                state = self.index.get_run(run["id"])
                if state["status"] in ("done", "failed", "stopped"):
                    break
                time.sleep(0.05)
            runner.shutdown(wait=True)
            self.assertEqual(state["status"], "done", state.get("error"))
            self.assertEqual(state["counts"]["mode"], "path")
            self.assertEqual(state["counts"]["findings"], 0)
            self.assertEqual(state["counts"]["state"], "verified")
            self.assertEqual(self.index.get_graph_path(path["id"])["state"],
                             "verified")
        finally:
            lab.shutdown()
            lab.server_close()


class GraphSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Graph route", "https://lab.example.com/", status="active",
            scope=["lab.example.com"])

    def tearDown(self):
        if getattr(self.server, "path_runner", None) is not None:
            self.server.path_runner.shutdown(wait=True)
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

    def test_graph_routes_build_and_read(self):
        build = self.call("POST", f"/api/v1/missions/{self.mission['id']}/graph/build")
        self.assertEqual(build.status, 200)
        self.assertIn("nodes", self.data(build))
        view = self.call("GET", f"/api/v1/missions/{self.mission['id']}/graph")
        self.assertEqual(view.status, 200)
        payload = self.data(view)
        self.assertIn("nodes", payload)
        self.assertIn("edges", payload)
        self.assertIn("paths", payload)
        paths = self.call("GET", f"/api/v1/missions/{self.mission['id']}/paths")
        self.assertEqual(paths.status, 200)

    def test_the_graph_tools_are_catalogued(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        names = [tool["name"] for tool in catalog()]
        for name in ("graph_build", "mission_graph", "paths_list", "path_verify",
                     "graph_node_add", "graph_edge_add"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)


if __name__ == "__main__":
    unittest.main()
