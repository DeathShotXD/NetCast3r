import base64
import hashlib
import json
import os
import re
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server import Server, Stream
from netcast3r.server.events import Event, EventBus
from netcast3r.server.index import Index
from netcast3r.server.jobs import JobManager
from netcast3r.server.keys import KeyStore, mask, redact

TOKEN = "test-token"
APP_PATH = Path(__file__).resolve().parent.parent / "src" / "netcast3r" / "web" / "index.html"
requires_app = unittest.skipUnless(APP_PATH.exists(), "dashboard not built yet")


def fake_runner(run_id, target, options, emit, should_stop):
    emit(Event(type="log", agent="recon", payload={"text": "crawling"}))
    emit(Event(type="finding.created", payload={"secret_type": "aws", "value": "AKIAIOSFODNN7EXAMPLE"}))
    return {
        "target": target, "pages": 2, "js_files": 3, "endpoints": 4, "candidates": 1,
        "verified": 1, "findings": 1, "report": "results/report.md",
        "findings_list": [{
            "title": "AWS key", "severity": "high", "secret_type": "aws",
            "value": "AKIAIOSFODNN7EXAMPLE", "status": "verified", "confidence": 0.9,
        }],
    }


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        base = Path(self.tmp.name)
        self.index = Index(base / "netcast3r.db")
        self.bus = EventBus()
        self.keys = KeyStore(base)
        self.jobs = JobManager(self.index, self.bus, fake_runner, workers=1)
        self.server = Server(self.index, self.bus, self.jobs, self.keys, token=TOKEN)

    def tearDown(self):
        self.jobs.shutdown()
        self.index.close()
        self.tmp.cleanup()

    def call(self, method, path, body=None, query=None, token=TOKEN, host="127.0.0.1:7857",
             origin=None):
        headers = {"host": host}
        if token:
            headers["x-netcast3r-token"] = token
        if origin:
            headers["origin"] = origin
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, query or {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def wait(self, run_id, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            run = self.index.get_run(run_id)
            if run and run["status"] in ("done", "failed", "stopped", "interrupted"):
                return run
            time.sleep(0.02)
        return self.index.get_run(run_id)

    def test_meta(self):
        response = self.call("GET", "/api/v1/meta")
        self.assertEqual(response.status, 200)
        self.assertEqual(self.data(response)["api_version"], "v1")

    def test_host_is_validated(self):
        response = self.call("GET", "/api/v1/meta", host="evil.example")
        self.assertEqual(response.status, 421)

    def test_token_is_required(self):
        response = self.call("GET", "/api/v1/meta", token=None)
        self.assertEqual(response.status, 401)

    def test_bad_origin_is_refused_on_write(self):
        response = self.call("POST", "/api/v1/runs", body={"target": "x"}, origin="http://evil.example")
        self.assertEqual(response.status, 403)

    def test_root_serves_placeholder(self):
        response = self.call("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"NETCAST3R", response.body)

    def test_create_run_and_complete(self):
        response = self.call("POST", "/api/v1/runs", body={"target": "example.com"})
        self.assertEqual(response.status, 201)
        run_id = self.data(response)["id"]
        run = self.wait(run_id)
        self.assertEqual(run["status"], "done")
        self.assertEqual(run["counts"]["pages"], 2)

    def test_run_listing_and_get(self):
        created = self.data(self.call("POST", "/api/v1/runs", body={"target": "a.com"}))["id"]
        self.wait(created)
        listing = self.data(self.call("GET", "/api/v1/runs", query={"q": "a.com"}))
        self.assertEqual(listing["total"], 1)
        self.assertEqual(self.call("GET", f"/api/v1/runs/{created}").status, 200)
        self.assertEqual(self.call("GET", "/api/v1/runs/run_missing").status, 404)

    def test_findings_are_indexed_masked_and_triageable(self):
        run_id = self.data(self.call("POST", "/api/v1/runs", body={"target": "b.com"}))["id"]
        self.wait(run_id)
        listing = self.data(self.call("GET", "/api/v1/findings", query={"run_id": run_id}))
        self.assertEqual(listing["total"], 1)
        finding = listing["items"][0]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", finding["value"])
        self.assertIn("...", finding["value"])
        patched = self.data(self.call("PATCH", f"/api/v1/findings/{finding['id']}",
                                      body={"status": "confirmed", "tags": ["aws"]}))
        self.assertEqual(patched["triage_status"], "confirmed")
        self.assertEqual(patched["tags"], ["aws"])

    def test_events_are_persisted(self):
        run_id = self.data(self.call("POST", "/api/v1/runs", body={"target": "c.com"}))["id"]
        self.wait(run_id)
        events = self.data(self.call("GET", f"/api/v1/runs/{run_id}/events"))["items"]
        kinds = {event["type"] for event in events}
        self.assertIn("log", kinds)
        self.assertIn("run.state", kinds)

    def test_event_stream_replays_backlog(self):
        run_id = self.data(self.call("POST", "/api/v1/runs", body={"target": "d.com"}))["id"]
        self.wait(run_id)
        stream = self.call("GET", f"/api/v1/runs/{run_id}/events/stream")
        self.assertIsInstance(stream, Stream)
        frame = next(stream.frames)
        self.assertIn("data:", frame)
        stream.frames.close()

    def test_keys_lifecycle_and_masking(self):
        put = self.call("PUT", "/api/v1/keys/openai", body={"value": "sk-live-abcdefghijkl"})
        self.assertEqual(put.status, 200)
        self.assertNotIn("abcdefghijkl", put.body.decode())
        listing = self.data(self.call("GET", "/api/v1/keys"))["items"]
        self.assertEqual(listing[0]["name"], "openai")
        self.assertTrue(listing[0]["masked"].endswith("ijkl"))
        deleted = self.data(self.call("DELETE", "/api/v1/keys/openai"))
        self.assertTrue(deleted["deleted"])

    def test_settings_roundtrip(self):
        self.call("PATCH", "/api/v1/settings", body={"theme": "dark", "depth": 2})
        settings = self.data(self.call("GET", "/api/v1/settings"))["items"]
        self.assertEqual(settings["theme"], "dark")
        self.assertEqual(settings["depth"], 2)

    def test_providers_lifecycle_and_test(self):
        created = self.data(self.call("POST", "/api/v1/providers", body={
            "name": "openai", "kind": "openai", "base_url": "https://api.openai.com/v1",
            "key_name": "openai", "api_key": "sk-test"}) )
        self.assertEqual(created["name"], "openai")
        self.server._test_provider = lambda provider: {"ok": True, "reason": "ok"}
        tested = self.data(self.call("POST", f"/api/v1/providers/{created['id']}/test"))
        self.assertTrue(tested["ok"])
        self.assertTrue(self.data(self.call("DELETE", f"/api/v1/providers/{created['id']}"))["deleted"])

    def test_readyz_and_metrics(self):
        self.assertEqual(self.call("GET", "/api/v1/healthz").status, 200)
        self.assertEqual(self.call("GET", "/api/v1/readyz").status, 200)
        metrics = self.data(self.call("GET", "/api/v1/metrics"))
        self.assertIn("runs", metrics)

    def test_recover_marks_orphans_interrupted(self):
        run = self.index.create_run("orphan.com")
        self.index.update_run(run["id"], status="running")
        recovered = self.jobs.recover()
        self.assertEqual(recovered, 1)
        self.assertEqual(self.index.get_run(run["id"])["status"], "interrupted")

    def test_summary_counts_the_whole_index(self):
        run_id = self.data(self.call("POST", "/api/v1/runs", body={"target": "s.com"}))["id"]
        self.wait(run_id)
        summary = self.data(self.call("GET", "/api/v1/summary"))
        self.assertGreaterEqual(summary["runs"], 1)
        self.assertGreaterEqual(summary["findings"], 1)
        self.assertEqual(summary["triage"].get("new"), 1)
        self.assertEqual(summary["last_run"]["target"], "s.com")


class DashboardAppTests(unittest.TestCase):
    """The built SPA as the server actually serves it."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        base = Path(self.tmp.name)
        self.index = Index(base / "netcast3r.db")
        self.bus = EventBus()
        self.keys = KeyStore(base)
        self.jobs = JobManager(self.index, self.bus, fake_runner, workers=1)
        self.server = Server(self.index, self.bus, self.jobs, self.keys, token=TOKEN)

    def tearDown(self):
        self.jobs.shutdown()
        self.index.close()
        self.tmp.cleanup()

    def call(self, method, path, body=None, query=None, token=TOKEN, extra_headers=None):
        headers = {"host": "127.0.0.1:7857", **(extra_headers or {})}
        if token:
            headers["x-netcast3r-token"] = token
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, query or {}, headers, payload)

    @requires_app
    def test_root_serves_the_built_dashboard(self):
        response = self.call("GET", "/")
        self.assertEqual(response.status, 200)
        body = response.body.decode()
        self.assertIn('<div id="app">', body)
        self.assertIn("NetCast3r", body)
        self.assertIn("text/html", response.content_type)

    @requires_app
    def test_csp_hashes_every_inline_script(self):
        response = self.call("GET", "/")
        body = response.body.decode()
        header = response.headers["Content-Security-Policy"]
        scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", body, flags=re.S | re.I)
        self.assertTrue(scripts, "expected an inlined bundle")
        for script in scripts:
            if not script.strip():
                continue
            digest = hashlib.sha256(script.encode("utf-8")).digest()
            expected = "'sha256-" + base64.b64encode(digest).decode() + "'"
            self.assertIn(expected, header)
        self.assertIn("script-src 'self' 'sha256-", header)

    @requires_app
    def test_the_bundle_loads_nothing_from_the_network(self):
        body = self.call("GET", "/").body.decode()
        self.assertNotIn('src="http', body)
        self.assertNotIn('href="http', body)
        self.assertNotIn("<script src=", body)

    def test_the_shell_is_public_but_the_api_is_not(self):
        self.assertEqual(self.call("GET", "/", token=None).status, 200)
        self.assertEqual(self.call("GET", "/api/v1/meta", token=None).status, 401)
        self.assertEqual(self.call("POST", "/api/v1/session", body={"token": "x"},
                                   token=None).status, 401)

    def test_a_valid_link_token_sets_an_httponly_cookie(self):
        response = self.call("GET", "/", query={"token": TOKEN}, token=None)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("netcast3r_token=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        bad = self.call("GET", "/", query={"token": "wrong"}, token=None)
        self.assertNotIn("Set-Cookie", bad.headers)

    def test_the_cookie_authenticates_api_calls(self):
        headers = {"host": "127.0.0.1:7857", "cookie": f"netcast3r_token={TOKEN}"}
        response = self.server.route("GET", "/api/v1/meta", {}, headers, b"")
        self.assertEqual(response.status, 200)

    def test_session_endpoint_issues_a_cookie(self):
        good = self.call("POST", "/api/v1/session", body={"token": TOKEN}, token=None)
        self.assertEqual(good.status, 200)
        self.assertIn("netcast3r_token=", good.headers["Set-Cookie"])

    def test_static_dir_still_wins(self):
        override = Path(self.tmp.name) / "static"
        override.mkdir()
        (override / "index.html").write_text("<html><body>override</body></html>")
        server = Server(self.index, self.bus, self.jobs, self.keys, token=TOKEN,
                        static_dir=override)
        response = server.route("GET", "/", {}, {"host": "127.0.0.1:7857"}, b"")
        self.assertEqual(response.body, b"<html><body>override</body></html>")
        # still locked down: no inline script is allowed through
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)


class EventConsoleTests(unittest.TestCase):
    """The console adapter must accept everything the orchestrator can print."""

    def test_raw_output_becomes_a_log_event(self):
        from netcast3r.server.events import Event
        from netcast3r.server.runner import EventConsole

        seen: list[Event] = []
        console = EventConsole(seen.append, "run_1")
        console._emit("  bar  4/4 (100%)")
        console._emit("\x1b[38;2;76;35;119m[\x1b[0m====\x1b[0m]")
        console._emit("")
        logs = [event for event in seen if event.type == "log"]
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0].agent, "run")
        self.assertEqual(logs[0].payload["text"], "bar  4/4 (100%)")
        self.assertNotIn("\x1b", logs[1].payload["text"])


class KeyStoreTests(unittest.TestCase):
    def test_mask_and_redact(self):
        self.assertEqual(mask(""), "")
        self.assertEqual(mask("short"), "*****")
        self.assertTrue(mask("sk-abcdefghijklmnop").startswith("sk-a"))
        text = redact("token is sk-proj-abcdefghijklmnopqrstuvwxyz here")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", text)

    def test_store_roundtrip_and_permissions(self):
        with TemporaryDirectory() as tmp:
            store = KeyStore(Path(tmp))
            store.set("openai", "sk-abcdefghijklmnop")
            self.assertEqual(store.get("openai"), "sk-abcdefghijklmnop")
            self.assertTrue(store.delete("openai"))
            self.assertEqual(store.get("openai"), "")


if __name__ == "__main__":
    unittest.main()
