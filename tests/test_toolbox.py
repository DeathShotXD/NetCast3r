import json
import os
import shutil
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import apispec, poc, toolbox
from netcast3r.server import build_server


class CatalogTests(unittest.TestCase):
    def test_catalog_is_typed_and_covers_categories(self):
        items = toolbox.catalog()
        self.assertGreaterEqual(len(items), 12)
        ids = [item["id"] for item in items]
        self.assertEqual(len(ids), len(set(ids)))
        for item in items:
            for field in ("id", "title", "category", "binary", "risk", "stage",
                          "scope", "options", "installed"):
                self.assertIn(field, item, item.get("id"))
            self.assertIn(item["risk"], {"low", "medium", "high"})
            self.assertIn(item["stage"], {"passive", "active", "intrusive"})
            self.assertIn(item["scope"], {"url", "host"})
        categories = {item["category"] for item in items}
        for expected in ("recon", "web", "ad"):
            self.assertIn(expected, categories)

    def test_builders_reject_unallowed_options(self):
        with self.assertRaises(toolbox.ToolboxError):
            toolbox._nmap("example.com", {"ports": "all;rm -rf"})
        argv = toolbox._nmap("example.com", {"ports": "top100"})
        self.assertIn("--top-ports", argv)
        self.assertEqual(argv[-1], "example.com")


class ScopeTests(unittest.TestCase):
    def test_host_allowlist_and_metadata_refusal(self):
        self.assertTrue(toolbox._host_allowed("lab.example.com", {"lab.example.com"}))
        self.assertFalse(toolbox._host_allowed("evil.example.com", {"lab.example.com"}))
        self.assertFalse(toolbox._host_allowed("169.254.169.254", {"169.254.169.254"}))
        self.assertFalse(toolbox._host_allowed("metadata.google.internal",
                                               {"metadata.google.internal"}))

    def test_run_refuses_out_of_scope_before_anything_else(self):
        tmp = Path(tempfile.mkdtemp())
        server = build_server(results_dir=str(tmp / "results"), base=tmp, recover=False)
        try:
            with self.assertRaises(toolbox.ToolboxError) as ctx:
                toolbox.run(server.index, "nmap", "evil.example.com",
                            {"lab.example.com"})
            self.assertIn("scope", str(ctx.exception))
        finally:
            server.index.close()
            server.jobs.shutdown(wait=False)

    def test_unknown_tool_is_refused(self):
        tmp = Path(tempfile.mkdtemp())
        server = build_server(results_dir=str(tmp / "results"), base=tmp, recover=False)
        try:
            with self.assertRaises(toolbox.ToolboxError):
                toolbox.run(server.index, "nope", "lab.example.com", {"lab.example.com"})
        finally:
            server.index.close()
            server.jobs.shutdown(wait=False)


class ParserTests(unittest.TestCase):
    def test_nmap(self):
        parsed = toolbox.parse("nmap",
                               '<port protocol="tcp" portid="443">'
                               '<state state="open"/>'
                               '<service name="https" product="nginx"/></port>')
        self.assertEqual(parsed["services"][0]["port"], 443)

    def test_nuclei(self):
        line = json.dumps({"template-id": "exposed-panel",
                           "info": {"name": "Exposed panel", "severity": "high"},
                           "matched-at": "https://lab.example.com/admin"})
        parsed = toolbox.parse("nuclei", line)
        self.assertEqual(parsed["findings"][0]["severity"], "high")

    def test_sqlmap_and_urls(self):
        self.assertTrue(toolbox.parse("sqlmap", "Parameter: id\nis vulnerable")["vulnerable"])
        urls = toolbox.parse("ffuf", "http://lab.example.com/a\nhttp://lab.example.com/b")
        self.assertEqual(len(urls["endpoints"]), 2)


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Toolbox", "https://lab.example.com/", status="active",
            scope=["lab.example.com"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_parsed_output_becomes_nodes_and_candidates(self):
        entry = {"id": "nuclei-1", "tool": "nuclei", "target": "https://lab.example.com/",
                 "mission_id": self.mission["id"], "run_id": "run_x"}
        parsed = {"findings": [{"template": "exposed-panel",
                                "name": "Exposed panel", "severity": "high",
                                "matched_at": "https://lab.example.com/admin"}],
                  "endpoints": ["https://lab.example.com/admin"]}
        written = toolbox._persist(self.index, entry, parsed)
        self.assertGreaterEqual(written["nodes"], 1)
        self.assertEqual(written["candidates"], 1)
        self.assertEqual(self.index.totals().get("findings", 0), 0)
        candidates = self.index.list_candidates(self.mission["id"])
        self.assertEqual(candidates[0]["module_id"], "exposed-panel")

    def test_services_and_tech_become_nodes(self):
        entry = {"id": "nmap-1", "tool": "nmap", "target": "https://lab.example.com/",
                 "mission_id": self.mission["id"], "run_id": ""}
        toolbox._persist(self.index, entry, {
            "services": [{"port": 443, "protocol": "tcp", "service": "https",
                          "product": "nginx"}],
            "tech": ["nginx"]})
        nodes = {n["kind"] for n in self.index.list_graph_nodes(self.mission["id"])}
        self.assertIn("service", nodes)
        self.assertIn("technology", nodes)


class ApiSpecTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "API", "https://api.example.com/", status="active",
            scope=["api.example.com"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_openapi_ingest(self):
        spec = json.dumps({
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com"}],
            "paths": {"/users/{id}": {"get": {"parameters": [{"name": "verbose"}]}},
                      "/orders": {"post": {}}}})
        result = apispec.ingest(self.index, self.mission["id"], spec)
        self.assertEqual(result["endpoints"], 2)
        self.assertIn("id", {n["label"] for n in
                             self.index.list_graph_nodes(self.mission["id"],
                                                         kind="parameter")})

    def test_postman_ingest(self):
        spec = json.dumps({
            "info": {"name": "collection"},
            "item": [{"name": "u", "request": {
                "method": "GET",
                "url": {"raw": "https://api.example.com/users?limit=10",
                        "query": [{"key": "limit"}]}}}]})
        result = apispec.ingest(self.index, self.mission["id"], spec)
        self.assertEqual(result["kind"], "postman")
        self.assertEqual(result["endpoints"], 1)

    def test_a_bad_spec_is_refused(self):
        with self.assertRaises(apispec.ApiSpecError):
            apispec.ingest(self.index, self.mission["id"], '{"nothing": true}')


class PocTests(unittest.TestCase):
    def test_poc_from_candidate_evidence(self):
        candidate = {"id": "cnd_1", "title": "Exposed admin", "module_id": "web-idor-object",
                     "evidence": {"expected": "admin data", "steps": [
                         {"tool": "http_request", "target": "https://lab.example.com/admin",
                          "observation": {"method": "GET",
                                          "headers": {"content-type": "text/html"}}}]}}
        result = poc.build_poc(candidate, {"target": "https://lab.example.com/"})
        self.assertIn("curl", result["curl"])
        self.assertIn("requests.get", result["python"])
        self.assertEqual(result["reproduced_steps"], 1)
        self.assertEqual(result["findings"], 0)


class ToolboxSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Surface", "https://lab.example.com/", status="active",
            scope=["lab.example.com"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def call(self, method, path, body=None, query=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, query or {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_toolbox_and_apispec_and_poc_routes(self):
        catalog = self.call("GET", "/api/v1/toolbox")
        self.assertEqual(catalog.status, 200)
        self.assertTrue(self.data(catalog)["items"])
        # A run against an off-scope target is refused.
        refused = self.call(
            "POST", f"/api/v1/missions/{self.mission['id']}/toolbox/run",
            {"tool": "nmap", "target": "evil.example.com"})
        self.assertEqual(refused.status, 400)
        spec = json.dumps({"openapi": "3.0.0",
                           "servers": [{"url": "https://lab.example.com"}],
                           "paths": {"/x": {"get": {}}}})
        ingest = self.call(
            "POST", f"/api/v1/missions/{self.mission['id']}/apispec", {"spec": spec})
        self.assertEqual(ingest.status, 200)
        candidate = self.server.index.create_candidate(
            self.mission["id"], title="c", module_id="m",
            evidence={"steps": []})
        poc_route = self.call("POST", f"/api/v1/candidates/{candidate['id']}/poc")
        self.assertEqual(poc_route.status, 200)

    def test_the_toolbox_tools_are_catalogued(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        names = [tool["name"] for tool in catalog()]
        for name in ("toolbox_catalog", "toolbox_run", "toolbox_processes",
                     "toolbox_kill", "api_spec_ingest", "candidate_poc"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)


class _Lab(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>toolbox lab</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which("httpx"), "httpx not installed")
class LiveToolTests(unittest.TestCase):
    def setUp(self):
        import threading

        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.lab = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
        threading.Thread(target=self.lab.serve_forever, daemon=True).start()
        self.target = f"http://127.0.0.1:{self.lab.server_address[1]}/"
        self.mission = self.index.create_mission(
            "Live", self.target, status="active", scope=["127.0.0.1"])

    def tearDown(self):
        self.lab.shutdown()
        self.lab.server_close()
        self.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_a_real_tool_runs_in_scope_and_records_a_tool_call(self):
        result = toolbox.run(self.index, "httpx", self.target, {"127.0.0.1"},
                             base=self.tmp, mission_id=self.mission["id"],
                             options={"timeout": 30})
        self.assertIn("exit_code", result)
        self.assertEqual(self.index.totals().get("findings", 0), 0)
        calls = self.index.list_tool_calls(mission_id=self.mission["id"])[0]
        self.assertTrue(calls)


if __name__ == "__main__":
    unittest.main()
