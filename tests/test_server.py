import json
import os
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
