import base64
import hashlib
import json
import os
import re
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

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

    def test_create_run_records_its_results_dir_before_work_starts(self):
        response = self.call("POST", "/api/v1/runs", body={"target": "example.com"})
        run = self.data(response)
        self.assertEqual(run["results_dir"], f"results/{run['id']}")
        self.wait(run["id"])
        self.assertEqual(self.index.get_run(run["id"])["results_dir"],
                         f"results/{run['id']}")

    def test_rerun_starts_fresh_without_resume_state(self):
        parent = self.index.create_run("https://a.example", {
            "resume": True, "resume_from": "run_old", "results_dir": "old", "depth": 3,
        })
        self.index.update_run(parent["id"], status="stopped")
        response = self.call("POST", f"/api/v1/runs/{parent['id']}/rerun")
        self.assertEqual(response.status, 201)
        child = self.data(response)
        self.assertEqual(child["parent_run_id"], parent["id"])
        self.assertNotIn("resume", child["options"])
        self.assertNotIn("resume_from", child["options"])
        self.assertEqual(child["options"]["depth"], 3)
        self.assertEqual(child["options"]["results_dir"], "results")
        self.assertEqual(child["results_dir"], f"results/{child['id']}")
        self.wait(child["id"])

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

    def test_create_finding_route_records_explicit_finding(self):
        response = self.call("POST", "/api/v1/findings", body={
            "title": "2FA bypass via email code", "severity": "high",
            "impact": "full session without a TOTP challenge",
            "evidence": "findings/bambu-2fa-email-code-bypass.md",
            "source": "manual", "tags": ["auth", "2fa"],
            "value": "not-a-real-secret-value", "confidence": 0.95})
        self.assertEqual(response.status, 201)
        finding = self.data(response)
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["triage_status"], "new")
        self.assertEqual(finding["tags"], ["auth", "2fa"])
        self.assertNotIn("not-a-real-secret-value", finding["value"])
        self.assertIn("...", finding["value"])

        for body in ({"title": "x", "severity": "nope"},
                     {"severity": "high"},
                     {"title": "x", "severity": "high", "run_id": "run_missing"},
                     {"title": "x", "severity": "high", "confidence": 2}):
            self.assertEqual(self.call("POST", "/api/v1/findings", body=body).status, 400)

    def test_finding_artifacts_round_trip(self):
        finding = self.data(self.call("POST", "/api/v1/findings", body={
            "title": "artifact test", "severity": "medium"}))
        response = self.call("POST", f"/api/v1/findings/{finding['id']}/artifacts",
                             body={"name": "../../poc.log", "content": "line one\nline two\n",
                                   "content_type": "text/plain"})
        self.assertEqual(response.status, 201)
        artifact = self.data(response)
        self.assertEqual(artifact["name"], "poc.log")
        self.assertEqual(artifact["bytes"], len("line one\nline two\n"))
        self.assertTrue(artifact["sha256"])
        self.assertNotIn("..", artifact["path"])

        listing = self.data(self.call(
            "GET", f"/api/v1/findings/{finding['id']}/artifacts"))
        self.assertEqual(listing["total"], 1)

        content = self.data(self.call(
            "GET", f"/api/v1/findings/{finding['id']}/artifacts/{artifact['id']}",
            query={"content": "1"}))
        self.assertEqual(content["encoding"], "text")
        self.assertIn("line two", content["content"])

        download = self.call(
            "GET", f"/api/v1/findings/{finding['id']}/artifacts/{artifact['id']}",
            query={"download": "1"})
        self.assertEqual(download.status, 200)
        self.assertEqual(download.body, b"line one\nline two\n")
        self.assertIn("attachment", download.headers.get("Content-Disposition", ""))

        binary = self.data(self.call(
            "POST", f"/api/v1/findings/{finding['id']}/artifacts",
            body={"name": "blob.bin", "encoding": "base64", "content": "AAECAw=="}))
        raw = self.data(self.call(
            "GET", f"/api/v1/findings/{finding['id']}/artifacts/{binary['id']}",
            query={"content": "1"}))
        self.assertEqual(raw["encoding"], "base64")
        self.assertEqual(raw["content"], "AAECAw==")

        self.assertEqual(self.call(
            "POST", f"/api/v1/findings/{finding['id']}/artifacts",
            body={"name": "empty", "content": ""}).status, 400)
        self.assertEqual(self.call(
            "POST", "/api/v1/findings/fnd_missing/artifacts",
            body={"name": "x", "content": "y"}).status, 404)
        self.assertEqual(self.call(
            "DELETE", f"/api/v1/findings/{finding['id']}/artifacts/{artifact['id']}").status, 200)
        self.assertEqual(self.data(self.call(
            "GET", f"/api/v1/findings/{finding['id']}/artifacts"))["total"], 1)

    def test_reveng_routes_analyze_a_local_source_tree(self):
        root = Path(self.tmp.name) / "artifact"
        root.mkdir()
        (root / "app.js").write_text(
            'const key = "AKIAIOSFODNN7EXAMPLE";\n'
            'el.innerHTML = input;\n'
            'fetch("/api/v1/orders");\n')
        kinds = self.data(self.call("GET", "/api/v1/reveng/kinds"))
        self.assertIn("source", kinds["kinds"])
        self.assertIn("jadx", kinds["decompilers"])

        response = self.call("POST", "/api/v1/reveng/analyze",
                             body={"kind": "source", "path": str(root), "markdown": True})
        self.assertEqual(response.status, 200)
        result = self.data(response)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["summary"]["observations"], 2)
        self.assertIn("report_markdown", result)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(result["secrets"]))

        self.assertEqual(self.call("POST", "/api/v1/reveng/analyze",
                                   body={"path": ""}).status, 400)
        self.assertEqual(self.call("POST", "/api/v1/reveng/analyze",
                                   body={"path": str(root), "kind": "nope"}).status, 400)

    def test_submission_ledger_routes(self):
        mission = self.data(self.call("POST", "/api/v1/missions", body={
            "title": "Operation Ledger", "target": "example.com"}))
        response = self.call("POST", "/api/v1/submissions", body={
            "title": "Stored XSS in admin console", "platform": "hackerone",
            "program": "acme", "target": "app.example.com", "severity": "high",
            "mission_id": mission["id"], "notes": "drafting"})
        self.assertEqual(response.status, 201)
        submission = self.data(response)
        self.assertEqual(submission["mission_id"], mission["id"])
        self.assertEqual(submission["mission_title"], "Operation Ledger")

        listing = self.data(self.call("GET", "/api/v1/submissions",
                                      query={"platform": "hackerone"}))
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["id"], submission["id"])

        patched = self.data(self.call("PATCH", f"/api/v1/submissions/{submission['id']}",
                                      body={"status": "submitted", "url": "https://hackerone.com/reports/1"}))
        self.assertEqual(patched["status"], "submitted")
        self.assertIsNotNone(patched["submitted_at"])

        summary = self.data(self.call("GET", "/api/v1/submissions/summary"))
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["awaiting"], 1)

        bad = self.call("POST", "/api/v1/submissions", body={
            "title": "Bad link", "platform": "hackerone", "url": "javascript:alert(1)"})
        self.assertEqual(bad.status, 400)

        deleted = self.data(self.call("DELETE", f"/api/v1/submissions/{submission['id']}"))
        self.assertTrue(deleted["deleted"])
        self.assertEqual(self.call("GET", f"/api/v1/submissions/{submission['id']}").status, 404)

    def test_fingerprints_do_not_collide_when_tokens_share_a_prefix(self):
        prefix = "same-header-" + "x" * 80
        first = self.index.create_run("https://one.example")
        second = self.index.create_run("https://two.example")
        self.index.add_findings(first["id"], [{
            "title": "token one", "severity": "high", "secret_type": "jwt",
            "value": prefix + "-one", "status": "verified",
        }])
        one = self.index.list_findings(run_id=first["id"])[0][0]
        self.index.patch_finding(one["id"], status="confirmed")
        self.index.add_findings(second["id"], [{
            "title": "token two", "severity": "high", "secret_type": "jwt",
            "value": prefix + "-two", "status": "verified",
        }])
        two = self.index.list_findings(run_id=second["id"])[0][0]
        self.assertNotEqual(one["fingerprint"], two["fingerprint"])
        self.assertEqual(two["triage_status"], "new")

    def test_an_unknown_triage_status_is_refused(self):
        run_id = self.data(self.call("POST", "/api/v1/runs", body={"target": "b.com"}))["id"]
        self.wait(run_id)
        finding = self.data(self.call("GET", "/api/v1/findings",
                                      query={"run_id": run_id}))["items"][0]
        response = self.call("PATCH", f"/api/v1/findings/{finding['id']}",
                             body={"status": "pwned"})
        self.assertEqual(response.status, 400)
        self.assertEqual(self.index.get_finding(finding["id"])["triage_status"], "new")

    def test_notes_can_be_cleared_and_survive_other_patches(self):
        run_id = self.data(self.call("POST", "/api/v1/runs", body={"target": "b.com"}))["id"]
        self.wait(run_id)
        finding = self.data(self.call("GET", "/api/v1/findings",
                                      query={"run_id": run_id}))["items"][0]
        patched = self.data(self.call("PATCH", f"/api/v1/findings/{finding['id']}",
                                      body={"notes": "looked at it"}))
        self.assertEqual(patched["notes"], "looked at it")
        kept = self.data(self.call("PATCH", f"/api/v1/findings/{finding['id']}",
                                   body={"tags": ["aws"]}))
        self.assertEqual(kept["notes"], "looked at it")
        cleared = self.data(self.call("PATCH", f"/api/v1/findings/{finding['id']}",
                                      body={"notes": ""}))
        self.assertEqual(cleared["notes"], "")

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

    def test_provider_key_without_a_key_name_is_stored_by_provider_id(self):
        created = self.data(self.call("POST", "/api/v1/providers", body={
            "name": "local", "kind": "openai", "base_url": "http://127.0.0.1:11434/v1",
            "api_key": "sk-local-abcdefghij"}))
        self.assertEqual(self.keys.get(created["id"]), "sk-local-abcdefghij")
        listing = self.data(self.call("GET", "/api/v1/providers"))["items"]
        self.assertTrue(listing[0]["masked"].endswith("ghij"))

    def test_provider_key_moves_when_the_key_name_changes(self):
        created = self.data(self.call("POST", "/api/v1/providers", body={
            "name": "custom", "kind": "openai", "base_url": "https://api.example/v1",
            "key_name": "old-key", "api_key": "sk-move-abcdefghij"}))
        patched = self.data(self.call(
            "PATCH", f"/api/v1/providers/{created['id']}", body={"key_name": "new-key"}))
        self.assertEqual(self.keys.get("old-key"), "")
        self.assertEqual(self.keys.get("new-key"), "sk-move-abcdefghij")
        self.assertTrue(patched["masked"].endswith("ghij"))

        cleared = self.data(self.call(
            "PATCH", f"/api/v1/providers/{created['id']}", body={"key_name": ""}))
        self.assertEqual(self.keys.get("new-key"), "")
        self.assertEqual(self.keys.get(created["id"]), "sk-move-abcdefghij")
        self.assertTrue(cleared["masked"].endswith("ghij"))

    def test_renaming_keeps_a_key_already_written_under_the_new_name(self):
        created = self.data(self.call("POST", "/api/v1/providers", body={
            "name": "custom", "kind": "openai", "base_url": "https://api.example/v1",
            "key_name": "old-key", "api_key": "sk-old-abcdefghij"}))
        self.keys.set("new-key", "sk-new-abcdefghij")
        patched = self.data(self.call(
            "PATCH", f"/api/v1/providers/{created['id']}", body={"key_name": "new-key"}))
        self.assertEqual(self.keys.get("new-key"), "sk-new-abcdefghij")
        self.assertEqual(self.keys.get("old-key"), "")
        self.assertTrue(patched["masked"].endswith("ghij"))

    def test_deleting_a_provider_keeps_a_key_another_provider_still_uses(self):
        first = self.data(self.call("POST", "/api/v1/providers", body={
            "name": "one", "kind": "openai", "base_url": "https://one.example/v1",
            "key_name": "shared", "api_key": "sk-shared-abcdefghij"}))
        second = self.data(self.call("POST", "/api/v1/providers", body={
            "name": "two", "kind": "openai", "base_url": "https://two.example/v1",
            "key_name": "shared", "api_key": "sk-shared-abcdefghij"}))
        self.assertTrue(self.data(self.call(
            "DELETE", f"/api/v1/providers/{first['id']}"))["deleted"])
        self.assertEqual(self.keys.get("shared"), "sk-shared-abcdefghij")
        removed = self.data(self.call("DELETE", f"/api/v1/providers/{second['id']}"))
        self.assertTrue(removed["deleted"])
        self.assertTrue(removed["key_removed"])
        self.assertEqual(self.keys.get("shared"), "")

    def test_deleting_a_provider_removes_a_legacy_key_stored_by_name(self):
        provider = self.data(self.call("POST", "/api/v1/providers", body={
            "name": "legacy", "kind": "openai", "base_url": "https://legacy.example/v1"}))
        self.keys.set("legacy", "sk-legacy-abcdefghij")
        removed = self.data(self.call("DELETE", f"/api/v1/providers/{provider['id']}"))
        self.assertTrue(removed["key_removed"])
        self.assertEqual(self.keys.get("legacy"), "")

    def test_delete_run_removes_its_evidence_directory(self):
        base = Path(self.tmp.name)
        run_dir = base / "runs" / "run_evidence"
        run_dir.mkdir(parents=True)
        (run_dir / "netcast3r.db").write_text("evidence")
        run = self.index.create_run("https://delete.example", results_dir=str(run_dir))
        self.index.update_run(run["id"], status="done")
        self.index.add_findings(run["id"], [{
            "title": "t", "severity": "high", "secret_type": "x",
            "value": "a-long-secret-value", "status": "verified",
        }])
        server = Server(self.index, self.bus, self.jobs, self.keys,
                        config=SimpleNamespace(results_dir=str(base / "runs")),
                        token=TOKEN)
        response = server.route(
            "DELETE", f"/api/v1/runs/{run['id']}", {},
            {"host": "127.0.0.1", "x-netcast3r-token": TOKEN}, b"")
        body = json.loads(response.body.decode())
        self.assertTrue(body["deleted"])
        self.assertTrue(body["files_removed"])
        self.assertFalse(run_dir.exists())
        self.assertIsNone(self.index.get_run(run["id"]))
        self.assertEqual(self.index.list_findings(run_id=run["id"])[1], 0)

    def test_delete_run_keeps_a_shared_evidence_directory(self):
        base = Path(self.tmp.name)
        run_dir = base / "runs" / "run_shared"
        run_dir.mkdir(parents=True)
        first = self.index.create_run("https://one.example", results_dir=str(run_dir))
        second = self.index.create_run("https://two.example", results_dir=str(run_dir))
        self.index.update_run(first["id"], status="done")
        self.index.update_run(second["id"], status="done")
        server = Server(self.index, self.bus, self.jobs, self.keys,
                        config=SimpleNamespace(results_dir=str(base / "runs")),
                        token=TOKEN)
        response = server.route(
            "DELETE", f"/api/v1/runs/{first['id']}", {},
            {"host": "127.0.0.1", "x-netcast3r-token": TOKEN}, b"")
        self.assertFalse(json.loads(response.body.decode())["files_removed"])
        self.assertTrue(run_dir.exists())
        response = server.route(
            "DELETE", f"/api/v1/runs/{second['id']}", {},
            {"host": "127.0.0.1", "x-netcast3r-token": TOKEN}, b"")
        self.assertTrue(json.loads(response.body.decode())["files_removed"])
        self.assertFalse(run_dir.exists())

    def test_delete_run_never_removes_a_directory_outside_the_results_root(self):
        base = Path(self.tmp.name)
        outside = base / "outside" / "run_outside"
        outside.mkdir(parents=True)
        run = self.index.create_run("https://outside.example", results_dir=str(outside))
        self.index.update_run(run["id"], status="done")
        server = Server(self.index, self.bus, self.jobs, self.keys,
                        config=SimpleNamespace(results_dir=str(base / "runs")),
                        token=TOKEN)
        response = server.route(
            "DELETE", f"/api/v1/runs/{run['id']}", {},
            {"host": "127.0.0.1", "x-netcast3r-token": TOKEN}, b"")
        body = json.loads(response.body.decode())
        self.assertTrue(body["deleted"])
        self.assertFalse(body["files_removed"])
        self.assertTrue(outside.exists())

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

    def test_inventory_reads_a_runs_store(self):
        from netcast3r.store import Store

        run_id = self.data(self.call("POST", "/api/v1/runs", body={"target": "s.com"}))["id"]
        run = self.wait(run_id)
        out = Path(self.tmp.name) / "results" / run_id
        out.mkdir(parents=True, exist_ok=True)
        store = Store(out / "netcast3r.db")
        store.add_subdomain("api.example.com")
        store.add_endpoint("https://api.example.com/v1/users", "js")
        store.add_finding("AWS key", "high", "aws", "AKIAEXAMPLE", "impact", "proof")
        store.stage_end("crawl", detail="4 pages")
        store.close()
        # Live runs have no counts yet; the inspector must use the directory
        # recorded when the run was created.
        self.index.update_run(run["id"], results_dir=str(out))

        response = self.call("GET", f"/api/v1/runs/{run_id}/inventory", query={"kind": "findings"})
        self.assertEqual(response.status, 200)
        data = self.data(response)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["secret_type"], "aws")

        subdomains = self.data(self.call(
            "GET", f"/api/v1/runs/{run_id}/inventory", query={"kind": "subdomains"}))
        self.assertEqual(subdomains["items"][0]["host"], "api.example.com")

        stages = self.data(self.call(
            "GET", f"/api/v1/runs/{run_id}/inventory", query={"kind": "stages"}))
        self.assertEqual(stages["items"][0]["status"], "done")

    def test_inventory_of_an_unknown_run_is_a_404(self):
        response = self.call("GET", "/api/v1/runs/run_missing/inventory", query={"kind": "pages"})
        self.assertEqual(response.status, 404)

    def test_resume_creates_a_child_run_with_resume_options(self):
        parent = self.index.create_run("https://a.example")
        self.jobs.submit(parent["id"], "https://a.example", {})
        self.wait(parent["id"])
        response = self.call("POST", f"/api/v1/runs/{parent['id']}/resume")
        self.assertEqual(response.status, 201)
        child = self.data(response)
        self.assertEqual(child["parent_run_id"], parent["id"])
        self.assertTrue(child["options"]["resume"])
        self.assertEqual(child["options"]["resume_from"], parent["id"])
        self.wait(child["id"])

    def test_resume_refuses_an_active_run(self):
        run = self.index.create_run("https://a.example")
        response = self.call("POST", f"/api/v1/runs/{run['id']}/resume")
        self.assertEqual(response.status, 409)


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

    def test_reasoning_chunks_are_forwarded_verbatim(self):
        # Provider deltas are arbitrary fragments. Splitting them into "lines"
        # here used to strip the boundary spaces, and the coalescer re-joined
        # the fragments with newlines - words split across chunks came out
        # mangled. One event per chunk keeps the text whole end to end.
        from netcast3r.server.events import Event
        from netcast3r.server.runner import EventConsole

        seen: list[Event] = []
        console = EventConsole(seen.append, "run_1")
        console.reasoning("prospector", "checking value\n\n  ranking candidates  ")
        reasons = [event for event in seen if event.type == "reasoning"]
        self.assertEqual([event.payload["text"] for event in reasons],
                         ["checking value\n\n  ranking candidates  "])
        self.assertTrue(all(event.agent == "prospector" and event.run_id == "run_1"
                            for event in reasons))
        self.assertEqual([row["kind"] for row in console.events[-1:]], ["reason"])

    def test_model_calls_are_streamed_with_provider_and_latency(self):
        from netcast3r.server.events import Event
        from netcast3r.server.runner import EventConsole

        seen: list[Event] = []
        console = EventConsole(seen.append, "run_1")
        console.model_call({"kind": "call", "agent": "classifier",
                            "provider": "nvidia", "model": "nemotron"})
        console.model_call({"kind": "done", "agent": "classifier", "provider": "nvidia",
                            "model": "nemotron", "ok": True, "ms": 420})
        models = [event for event in seen if event.type == "model"]
        self.assertEqual(len(models), 2)
        self.assertEqual(models[1].payload["ms"], 420)
        self.assertIn("nvidia/nemotron ok 420ms", console.events[-1]["text"])


class ProviderPoolTests(unittest.TestCase):
    """Providers configured on the dashboard carry models, priority, and an on switch."""

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

    def call(self, method, path, body=None, token=TOKEN):
        headers = {"host": "127.0.0.1:7857"}
        if token:
            headers["x-netcast3r-token"] = token
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_patch_updates_models_priority_and_enabled(self):
        created = self.data(self.call("POST", "/api/v1/providers", body={
            "name": "nvidia", "base_url": "https://integrate.api.nvidia.com/v1",
            "key_name": "nvidia", "models": ["nvidia/llama-3.1-8b"], "priority": 10}))
        patched = self.data(self.call(
            "PATCH", f"/api/v1/providers/{created['id']}",
            body={"models": ["nvidia/nemotron-3-500e", "nvidia/llama-3.3-70b"],
                  "priority": 5, "enabled": False}))
        self.assertEqual(patched["models"], ["nvidia/nemotron-3-500e", "nvidia/llama-3.3-70b"])
        self.assertEqual(patched["model"], "nvidia/nemotron-3-500e")
        self.assertEqual(patched["priority"], 5)
        self.assertEqual(patched["enabled"], 0)
        listed = self.data(self.call("GET", "/api/v1/providers"))["items"]
        self.assertEqual(listed[0]["id"], created["id"])
        self.assertFalse(listed[0]["enabled"])

    def test_patch_rejects_an_unknown_provider(self):
        response = self.call("PATCH", "/api/v1/providers/prv_missing", body={"priority": 1})
        self.assertEqual(response.status, 404)


class DashboardBridgeTests(unittest.TestCase):
    """A scan must see what the Providers screen is configured with."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        base = Path(self.tmp.name)
        self.index = Index(base / "netcast3r.db")
        self.keys = KeyStore(base)

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_bridge_merges_dashboard_providers_into_the_run_config(self):
        from netcast3r.config import Config, ProviderConfig, default_config
        from netcast3r.server.runner import DashboardBridge

        self.keys.set("nvidia", "nvapi-secret")
        self.index.add_provider(name="nvidia", base_url="https://integrate.api.nvidia.com/v1",
                                key_name="nvidia", models=["nemotron-3-500e"], priority=5)
        self.index.add_provider(name="openrouter", base_url="https://openrouter.ai/api/v1",
                                key_name="openrouter", models=["qwen:free"], priority=10)
        self.index.add_provider(name="off", base_url="https://off.example/v1",
                                key_name="off", models=["x"], enabled=0)
        config = default_config()
        applied = DashboardBridge(self.index, self.keys).apply(config)
        self.assertEqual(applied, 2)
        nvidia = config.provider("nvidia")
        self.assertIsNotNone(nvidia)
        self.assertEqual(nvidia.api_key, "nvapi-secret")
        self.assertEqual(nvidia.models, ["nemotron-3-500e"])
        self.assertEqual(nvidia.priority, 5)
        self.assertEqual(config.provider("off"), None)
        # a configured name wins field by field over the config file default
        openrouter = config.provider("openrouter")
        self.assertEqual(openrouter.base_url, "https://openrouter.ai/api/v1")
        self.assertEqual(openrouter.models, ["qwen:free"])
        # ollama from the defaults survives untouched
        self.assertIsNotNone(config.provider("ollama"))
        self.assertEqual([p.name for p in config.ordered_providers()[:2]],
                         ["nvidia", "openrouter"])

    def test_bridge_resolves_keys_from_the_store_by_name(self):
        from netcast3r.config import default_config
        from netcast3r.server.runner import DashboardBridge

        self.keys.set("groq", "gsk_secret")
        self.index.add_provider(name="groq", base_url="https://api.groq.com/openai/v1",
                                key_name="groq", models=["llama-3.1-8b"])
        config = default_config()
        DashboardBridge(self.index, self.keys).apply(config)
        self.assertEqual(config.provider("groq").resolve_key(), "gsk_secret")

    def test_bridge_resolves_a_key_stored_under_the_provider_id(self):
        from netcast3r.config import default_config
        from netcast3r.server.runner import DashboardBridge

        provider = self.index.add_provider(
            name="custom", base_url="https://custom.example/v1", models=["m"])
        self.keys.set(provider["id"], "custom-secret")
        config = default_config()
        DashboardBridge(self.index, self.keys).apply(config)
        self.assertEqual(config.provider("custom").resolve_key(), "custom-secret")


class KeyStoreTests(unittest.TestCase):
    def test_mask_and_redact(self):
        self.assertEqual(mask(""), "")
        self.assertEqual(mask("short"), "*****")
        self.assertTrue(mask("sk-abcdefghijklmnop").startswith("sk-a"))
        text = redact("token is sk-proj-abcdefghijklmnopqrstuvwxyz here")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", text)
        nv = redact("key nvapi-abcdefghijklmnopqrstuvwxyz0123456789 here")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz0123456789", nv)

    def test_store_roundtrip_and_permissions(self):
        with TemporaryDirectory() as tmp:
            store = KeyStore(Path(tmp))
            store.set("openai", "sk-abcdefghijklmnop")
            self.assertEqual(store.get("openai"), "sk-abcdefghijklmnop")
            self.assertTrue(store.delete("openai"))
            self.assertEqual(store.get("openai"), "")


if __name__ == "__main__":
    unittest.main()
