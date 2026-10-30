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


if __name__ == "__main__":
    unittest.main()
