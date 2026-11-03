import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server import build_server


class HuntHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>Hunt target</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class HuntRunnerTests(unittest.TestCase):
    def setUp(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), HuntHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.target = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)

    def tearDown(self):
        if self.server.hunt_runner is not None:
            self.server.hunt_runner.shutdown(wait=True)
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_hunt_runs_without_an_external_agent(self):
        mission = self.server.index.create_mission(
            "Standalone hunt", self.target, status="active",
            scope=["127.0.0.1"])
        run = self.server._hunts().start(mission["id"])
        deadline = time.time() + 20
        while time.time() < deadline:
            state = self.server.index.get_run(run["id"])
            if state["status"] in {"done", "failed", "stopped", "interrupted"}:
                break
            time.sleep(0.05)
        self.assertEqual(state["status"], "done", state.get("error"))
        self.assertEqual(state["counts"]["mode"], "hunt")
        self.assertEqual(state["counts"]["findings"], 0)
        self.assertGreaterEqual(state["counts"]["leads"], 1)
        hypotheses, total = self.server.index.list_hypotheses(
            mission_id=mission["id"])
        self.assertGreaterEqual(total, 1)

    def test_hunt_emits_map_note_and_specific_hypotheses(self):
        # The local handler answers every GET, so the seed exposes live
        # auth/api/object surfaces and the hunt should emit a rich map note
        # plus falsifiable, object-specific critical-chain hypotheses.
        mission = self.server.index.create_mission(
            "Mapping hunt", self.target, status="active",
            scope=["127.0.0.1"])
        run = self.server._hunts().start(mission["id"])
        deadline = time.time() + 20
        while time.time() < deadline:
            state = self.server.index.get_run(run["id"])
            if state["status"] in {"done", "failed", "stopped", "interrupted"}:
                break
            time.sleep(0.05)
        self.assertEqual(state["status"], "done", state.get("error"))

        notes = self.server.index.list_agent_notes(mission["id"])
        kinds = {note["kind"] for note in notes}
        self.assertIn("hunt.map", kinds)
        map_note = next(n for n in notes if n["kind"] == "hunt.map")
        self.assertIn("suggested_chains", map_note["body"])
        self.assertIn("path_map", map_note["body"])

        hypotheses, _ = self.server.index.list_hypotheses(
            mission_id=mission["id"])
        titles = [str(h.get("title") or "") for h in hypotheses]
        host = "127.0.0.1"
        # At least one falsifiable, object-specific chain lead exists.
        self.assertTrue(
            any(t.startswith("BOLA on ") and host in t for t in titles),
            titles)
        # Every lead names a concrete host so it is testable as written.
        self.assertTrue(all(host in t for t in titles), titles)


class HuntHelperTests(unittest.TestCase):
    def test_classify_path_buckets(self):
        from netcast3r.server.hunt_runner import _classify_path
        self.assertEqual(_classify_path("/login"), "auth")
        self.assertEqual(_classify_path("/oauth/callback"), "auth")
        self.assertEqual(_classify_path("/api/v1/users"), "api")
        self.assertEqual(_classify_path("/admit"), "object")
        self.assertEqual(_classify_path("/result"), "object")
        self.assertEqual(_classify_path("/robots.txt"), "other")

    def test_is_live_accepts_auth_walled_surfaces(self):
        from netcast3r.server.hunt_runner import _is_live
        for status in (200, 301, 302, 401, 403):
            self.assertTrue(_is_live(status), status)
        for status in (0, 404, 500, None, "x"):
            self.assertFalse(_is_live(status), status)


if __name__ == "__main__":
    unittest.main()
