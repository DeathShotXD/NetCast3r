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

    def test_fallback_prefers_an_application_surface(self):
        mission = self.server.index.create_mission(
            "Wildcard priority", "http://127.0.0.1:9/", status="active",
            scope=["127.0.0.1"])
        self.server.index.upsert_graph_node(
            mission["id"], "endpoint", "http://127.0.0.1/static",
            label="static", data={"status": 200})
        self.server.index.upsert_graph_node(
            mission["id"], "endpoint", "http://127.0.0.1/portal/login",
            label="portal", data={"status": 200})
        runner = self.server._hunts()
        self.assertEqual(runner._fallback_target(mission["id"]),
                         "http://127.0.0.1/portal/login")

    def test_fallback_rotates_the_seed_across_runs(self):
        mission = self.server.index.create_mission(
            "Wildcard rotate", "http://127.0.0.1:9/", status="active",
            scope=["127.0.0.1"])
        for name in ("alpha", "beta", "gamma"):
            self.server.index.upsert_graph_node(
                mission["id"], "endpoint", f"http://127.0.0.1/{name}",
                label=name, data={"status": 200})
        runner = self.server._hunts()
        first = runner._fallback_target(mission["id"])
        run = self.server.index.create_run(
            "http://127.0.0.1:9/", {"mode": "hunt", "mission_id": mission["id"]})
        self.server.index.add_mission_run(mission["id"], run["id"])
        second = runner._fallback_target(mission["id"])
        self.assertNotEqual(first, second)

    def test_fallback_never_picks_an_out_of_scope_endpoint(self):
        mission = self.server.index.create_mission(
            "Wildcard skip", "http://127.0.0.1:9/", status="active",
            scope=["127.0.0.1"])
        self.server.index.upsert_graph_node(
            mission["id"], "endpoint", "http://203.0.113.9/portal",
            label="outside", data={"status": 200})
        self.server.index.upsert_graph_node(
            mission["id"], "endpoint", self.target, label="live",
            data={"status": 200})
        runner = self.server._hunts()
        self.assertEqual(runner._fallback_target(mission["id"]), self.target)

    def test_hunt_pivots_when_the_seed_host_does_not_answer(self):
        # A wildcard programme often has an apex that does not serve HTTP while
        # its child hosts do. The hunt must pivot to an in-scope graph host
        # instead of failing on the first request.
        mission = self.server.index.create_mission(
            "Wildcard programme", "http://127.0.0.1:9/", status="active",
            scope=["127.0.0.1"])
        self.server.index.upsert_graph_node(
            mission["id"], "endpoint", self.target, label="live child",
            confidence="observed", data={"status": 200})
        run = self.server._hunts().start(mission["id"])
        deadline = time.time() + 20
        while time.time() < deadline:
            state = self.server.index.get_run(run["id"])
            if state["status"] in {"done", "failed", "stopped", "interrupted"}:
                break
            time.sleep(0.05)
        self.assertEqual(state["status"], "done", state.get("error"))
        notes = self.server.index.list_agent_notes(mission["id"])
        self.assertIn("hunt.map", {note["kind"] for note in notes})

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
        self.assertIn("hunt.critical", kinds)
        map_note = next(n for n in notes if n["kind"] == "hunt.map")
        critical_note = next(n for n in notes if n["kind"] == "hunt.critical")
        self.assertIn("top_leads", critical_note["body"])
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


class SpaShellHandler(BaseHTTPRequestHandler):
    """Every route returns one small static shell; /api/* is 404.

    This is the apply.fpsc.gov.pk shape: path-guessing is settled and the real
    object API lives behind the JS bundle, so the hunt should flag the shell.
    """

    SHELL = (b"<html><head><title>Portal</title></head>"
             b"<body><div id='root'></div></body></html>")

    def do_GET(self):
        if self.path.startswith("/api"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(self.SHELL)))
        self.end_headers()
        self.wfile.write(self.SHELL)

    def log_message(self, *args):
        pass


class SpaHuntTests(unittest.TestCase):
    def setUp(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), SpaShellHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
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

    def test_spa_shell_is_flagged_and_seeds_portal_leads(self):
        mission = self.server.index.create_mission(
            "SPA hunt", self.target, status="active", scope=["127.0.0.1"])
        run = self.server._hunts().start(mission["id"])
        deadline = time.time() + 20
        while time.time() < deadline:
            state = self.server.index.get_run(run["id"])
            if state["status"] in {"done", "failed", "stopped", "interrupted"}:
                break
            time.sleep(0.05)
        self.assertEqual(state["status"], "done", state.get("error"))

        notes = self.server.index.list_agent_notes(mission["id"])
        map_note = next(n for n in notes if n["kind"] == "hunt.map")
        self.assertIn('"spa_shell": true', map_note["body"])
        self.assertIn("JS bundle", map_note["body"])

        hypotheses, _ = self.server.index.list_hypotheses(
            mission_id=mission["id"])
        techniques = {str(h.get("technique") or "") for h in hypotheses}
        # A new portal-class lead that forces raw capture is seeded beyond the
        # three staple BOLA/IDOR/OAuth chains.
        self.assertTrue(
            {"auth-reset-token", "auth-sqli-login-bypass", "upload-policy",
             "spa-api-extract"} & techniques,
            techniques)


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

    def test_reset_paths_classify_as_auth(self):
        from netcast3r.server.hunt_runner import _classify_path
        self.assertEqual(_classify_path("/forgot-password"), "auth")
        self.assertEqual(_classify_path("/reset-password"), "auth")
        self.assertEqual(_classify_path("/account/recover"), "auth")

    def test_is_upload_path(self):
        from netcast3r.server.hunt_runner import _is_upload_path
        self.assertTrue(_is_upload_path("/upload"))
        self.assertTrue(_is_upload_path("/api/import"))
        self.assertTrue(_is_upload_path("/candidate/attachment"))
        self.assertFalse(_is_upload_path("/login"))

    def test_detect_spa_shell(self):
        from netcast3r.server.hunt_runner import _detect_spa_shell
        shell_surface = [{"path": p, "status": 200, "bytes": 531}
                         for p in ("/login", "/admit", "/result",
                                   "/dashboard", "/account")]
        detected, size = _detect_spa_shell(shell_surface)
        self.assertTrue(detected)
        self.assertEqual(size, 531)
        # Varied body sizes are a real backend, not a catch-all shell.
        varied = [{"path": "/a", "status": 200, "bytes": 100},
                  {"path": "/b", "status": 200, "bytes": 2048},
                  {"path": "/c", "status": 200, "bytes": 30000},
                  {"path": "/d", "status": 200, "bytes": 640}]
        self.assertFalse(_detect_spa_shell(varied)[0])
        # Too few samples cannot establish a shell.
        self.assertFalse(_detect_spa_shell(
            [{"path": "/a", "status": 200, "bytes": 531}])[0])
        # A large common body is a real page, not a tiny SPA shell.
        big = [{"path": f"/{i}", "status": 200, "bytes": 40000}
               for i in range(5)]
        self.assertFalse(_detect_spa_shell(big)[0])


if __name__ == "__main__":
    unittest.main()
