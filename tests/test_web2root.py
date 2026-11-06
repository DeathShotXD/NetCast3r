"""Web2root surface map, schedules, and PDF companion."""

from __future__ import annotations

import json
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

from netcast3r import report, schedule, web2root
from netcast3r.server import build_server


class _Lab(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>web2root lab</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Web2RootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.target = f"http://127.0.0.1:{self.port}/"
        self.mission = self.server.index.create_mission(
            "W2R", self.target, status="active",
            scope=["127.0.0.1"])

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

    def test_surface_seed_records_only_in_scope_hosts(self):
        response = self.call(
            "POST", f"/api/v1/missions/{self.mission['id']}/surface/seed",
            {"hosts": [f"127.0.0.1:{self.port}", "outside.example.com"],
             "probe": True, "limit": 10})
        self.assertEqual(response.status, 200)
        payload = self.data(response)
        self.assertEqual(payload["accepted"], 1)
        self.assertEqual(payload["hosts_rejected"], 1)
        self.assertGreaterEqual(payload["hosts_live"], 1)
        self.assertIn(str(self.port), payload["live"][0].get("url") or "")
        hosts = self.server.index.list_graph_nodes(self.mission["id"], kind="host")
        self.assertTrue(any(node.get("key") == "127.0.0.1" for node in hosts))
        endpoints = self.server.index.list_graph_nodes(
            self.mission["id"], kind="endpoint")
        self.assertTrue(endpoints)

    def test_surface_seed_rejects_an_empty_list(self):
        response = self.call(
            "POST", f"/api/v1/missions/{self.mission['id']}/surface/seed",
            {"hosts": []})
        self.assertEqual(response.status, 400)

    def test_map_surface_records_live_host(self):
        # Passive depth still resolves; standard probes HTTP against the lab.
        result = web2root.map_surface(
            self.server.index, self.mission["id"], depth="standard",
            probe_limit=5)
        self.assertGreaterEqual(result["hosts_live"], 1)
        self.assertEqual(result["findings"], 0)
        hosts = self.server.index.list_graph_nodes(self.mission["id"], kind="host")
        self.assertTrue(hosts)
        route = self.call("POST", f"/api/v1/missions/{self.mission['id']}/web2root",
                          {"depth": "passive", "probe_limit": 5})
        self.assertEqual(route.status, 200)

    def test_schedule_create_and_fire(self):
        row = schedule.create(self.server.index, self.mission["id"],
                              mode="once", name="retest",
                              run_at="2020-01-01T00:00:00Z")
        self.assertEqual(row["mode"], "once")
        fired = schedule.fire(self.server.index, row)
        self.assertEqual(fired["schedule"]["status"], "done")
        self.assertTrue(fired["direction"]["id"])
        directions = self.server.index.list_directions(self.mission["id"])
        self.assertTrue(directions)

    def test_pdf_export_route(self):
        pdf = report.markdown_to_pdf_bytes("# Title\n\n- item\n")
        self.assertTrue(pdf.startswith(b"%PDF"))
        response = self.call("GET",
                             f"/api/v1/missions/{self.mission['id']}/report.pdf")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.content_type, "application/pdf")
        self.assertTrue(response.body.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
