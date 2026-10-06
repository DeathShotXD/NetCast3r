import json
import os
import re
import shutil
import socket
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from netcast3r import dashboard as dash
from netcast3r import theme as T

DATA_RE = re.compile(
    r'<script id="nc-data" type="application/json">(.*?)</script>', re.S
)


class RenderTests(unittest.TestCase):
    def test_render_fills_both_placeholders(self):
        html = dash.render(dash.demo_data())
        self.assertNotIn("__NETCAST3R_VARS__", html)
        self.assertNotIn("__NETCAST3R_DATA__", html)
        self.assertIn(f"--acid: {T.ACID};", html)

    def test_rendered_data_is_valid_json(self):
        html = dash.render(dash.demo_data())
        data = json.loads(DATA_RE.search(html).group(1))
        self.assertEqual(data["target"], "https://target.example")
        self.assertEqual(len(data["findings"]), 4)
        self.assertEqual(len(data["stages"]), 6)

    def test_close_script_in_a_value_cannot_break_out(self):
        data = dash.build_data(target="x",
                               findings=[{"value": "</script><b>&amp;<!--"}])
        payload = DATA_RE.search(dash.render(data)).group(1)
        self.assertNotIn("</script", payload)
        self.assertNotIn("<", payload)
        self.assertNotIn(">", payload)
        self.assertNotIn("&", payload)
        parsed = json.loads(payload)
        self.assertEqual(parsed["findings"][0]["value"], "</script><b>&amp;<!--")

    def test_line_separators_stay_ascii_and_read_back(self):
        data = dash.build_data(target="x", findings=[{"value": "a\u2028b\u2029c"}])
        payload = DATA_RE.search(dash.render(data)).group(1)
        self.assertTrue(payload.isascii())
        self.assertEqual(json.loads(payload)["findings"][0]["value"], "a\u2028b\u2029c")

    def test_a_value_holding_a_token_is_not_substituted_again(self):
        data = dash.build_data(target="x",
                               findings=[{"value": "__NETCAST3R_LOGO__"}])
        payload = DATA_RE.search(dash.render(data)).group(1)
        self.assertEqual(json.loads(payload)["findings"][0]["value"],
                         "__NETCAST3R_LOGO__")

    def test_summary_and_counts_are_carried(self):
        data = dash.build_data(summary={"pages": 3}, counts={"secrets": 9},
                               findings=[], events=[])
        self.assertEqual(data["summary"]["pages"], 3)
        self.assertEqual(data["counts"]["secrets"], 9)


class StageTests(unittest.TestCase):
    def test_stages_completed_infers_the_earlier_stages(self):
        events = [{"agent": "recon"}, {"agent": "assayer"}, {"agent": "scribe"}]
        self.assertEqual(dash.stages_completed(events),
                         [s["key"] for s in T.STAGES])

    def test_stages_completed_stops_where_the_run_stopped(self):
        events = [{"agent": "recon"}, {"agent": "exegete"}]
        self.assertEqual(dash.stages_completed(events), ["crawl", "readjs"])

    def test_stages_completed_ignores_unknown_agents(self):
        self.assertEqual(dash.stages_completed([{"agent": "nobody"}]), [])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_save_writes_html_and_payload(self):
        path = dash.save(self.tmp, dash.demo_data())
        self.assertTrue(path.exists())
        self.assertEqual(path.name, "dashboard.html")
        self.assertTrue((self.tmp / "dashboard.json").exists())
        self.assertIn("NETCAST", path.read_text())

    def test_save_honours_a_custom_file_name(self):
        path = dash.save(self.tmp, dash.demo_data(), name="report.html")
        self.assertEqual(path.name, "report.html")
        self.assertTrue((self.tmp / "report.json").exists())

    def test_load_reads_the_payload_back(self):
        dash.save(self.tmp, dash.demo_data())
        loaded = dash.load(self.tmp)
        self.assertEqual(loaded["target"], "https://target.example")
        self.assertEqual(len(loaded["findings"]), 4)

    def test_load_falls_back_to_results_json(self):
        (self.tmp / "results.json").write_text(json.dumps(
            {"summary": {"pages": 7}, "findings": [{"value": "abc"}]}))
        loaded = dash.load(self.tmp)
        self.assertEqual(loaded["summary"]["pages"], 7)
        self.assertEqual(loaded["findings"][0]["value"], "abc")


class ServerTests(unittest.TestCase):
    def _server(self, path):
        handler = type("H", (dash._Handler,), {
            "path_file": path, "data_file": path.with_suffix(".json")})
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.addCleanup(srv.shutdown)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_loopback_hosts_are_allowed(self):
        for host in ("127.0.0.1", "localhost", "127.0.0.1:8899",
                     "localhost:8899", "[::1]:8899"):
            self.assertTrue(dash._host_allowed(host), host)

    def test_other_hosts_are_rejected(self):
        for host in ("evil.example", "example.com:8899", "10.0.0.5", ""):
            self.assertFalse(dash._host_allowed(host), host)

    def test_events_stream_pushes_a_reload_on_change(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        path = dash.save(tmp, dash.demo_data())
        srv = self._server(path)

        sock = socket.create_connection(("127.0.0.1", srv.server_address[1]))
        self.addCleanup(sock.close)
        sock.settimeout(8)
        sock.sendall(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")

        seen = b""
        while b": connected" not in seen:
            chunk = sock.recv(4096)
            if not chunk:
                break
            seen += chunk
        self.assertIn(b"text/event-stream", seen)
        self.assertIn(b": connected", seen)

        os.utime(path, (time.time() + 5, time.time() + 5))
        while b"event: reload" not in seen:
            chunk = sock.recv(4096)
            if not chunk:
                break
            seen += chunk
        self.assertIn(b"event: reload", seen)

    def test_findings_api_pages_filters_and_sorts(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        path = dash.save(tmp, dash.demo_data())
        srv = self._server(path)
        base = f"http://127.0.0.1:{srv.server_address[1]}"

        page = json.loads(urllib.request.urlopen(base + "/api/findings?limit=2").read())
        self.assertEqual(page["total"], 4)
        self.assertEqual(len(page["items"]), 2)

        tail = json.loads(urllib.request.urlopen(base + "/api/findings?offset=3").read())
        self.assertEqual(len(tail["items"]), 1)

        confirmed = json.loads(
            urllib.request.urlopen(base + "/api/findings?status=confirmed").read())
        self.assertEqual(confirmed["total"], 1)

        data = json.loads(urllib.request.urlopen(base + "/api/data").read())
        self.assertEqual(data["target"], "https://target.example")


class DemoTests(unittest.TestCase):
    def test_demo_data_covers_every_state_and_stage(self):
        data = dash.demo_data()
        states = {f["status"] for f in data["findings"]}
        self.assertEqual(states,
                         {"confirmed", "corroborated", "inferred", "unresolved"})
        self.assertEqual(data["stages"], [s["key"] for s in T.STAGES])
        self.assertTrue(data["log"])
        self.assertGreater(data["summary"]["pages"], 0)

    def test_template_ships_with_the_package(self):
        text = dash.template_text()
        self.assertTrue(text.lstrip().startswith("<!doctype html>"))
        self.assertIn("--font-mono", text)
        self.assertIn("prefers-reduced-motion", text)
        self.assertTrue(text.isascii())


if __name__ == "__main__":
    unittest.main()
