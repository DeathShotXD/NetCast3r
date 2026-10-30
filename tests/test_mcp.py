import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.mcp import protocol
from netcast3r.mcp.plane import EmbeddedPlane
from netcast3r.mcp.server import MCPServer
from netcast3r.mcp.tools import (
    DEFAULT_POLICY,
    ToolContext,
    ToolRegistry,
    _HANDLERS,
    _TOOL_MAP,
    catalog,
    mcp_tools,
)
from netcast3r.server.events import Event


def fake_runner(run_id, target, options, emit, should_stop):
    from netcast3r.store import Store

    emit(Event(type="log", agent="recon", payload={"text": "crawling"}))
    out = Path(str(options.get("results_dir") or "results")) / run_id
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text("# NetCast3r test report\n\n- target: " + target + "\n")
    store = Store(out / "netcast3r.db")
    store.add_endpoint("https://example.com/api/v1", "js")
    store.close()
    return {
        "target": target, "pages": 2, "js_files": 1, "endpoints": 3,
        "candidates": 1, "verified": 0, "findings": 0,
        "report": "results/report.md",
        "findings_list": [{
            "title": "Test key", "severity": "medium", "secret_type": "generic",
            "value": "not-a-real-secret-value", "status": "unverified",
            "evidence": "pattern only", "source": "https://example.com/app.js",
        }],
    }


class MCPIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.plane = EmbeddedPlane(base=self.tmp, results_dir=str(self.tmp / "results"),
                                   runner=fake_runner)
        self.ctx = ToolContext(plane=self.plane, policy="supervised", base=self.tmp)
        self.registry = ToolRegistry(self.ctx)

    def tearDown(self):
        self.plane.close()

    def call(self, name, **args):
        payload, is_error = self.registry.call(name, args, actor="test/1")
        return payload, is_error

    def create_mission(self, **extra):
        body = {"title": "Operation Test", "target": "example.com",
                "scope": ["example.com", "!admin.example.com"]}
        body.update(extra)
        payload, is_error = self.call("missions_create", **body)
        self.assertFalse(is_error, payload)
        return payload

    def wait_for_run(self, run_id, timeout=8.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            run = self.plane.request("GET", f"/api/v1/runs/{run_id}")
            if run["status"] not in ("queued", "running"):
                return run
            time.sleep(0.05)
        self.fail(f"run {run_id} did not finish")

    # -- registry ---------------------------------------------------------
    def test_catalog_and_handlers_are_consistent(self):
        self.assertEqual(len(catalog()), len(mcp_tools()))
        for tool in _TOOL_MAP.values():
            self.assertIn(tool.handler_name, _HANDLERS, tool.name)
            self.assertEqual(tool.input_schema["type"], "object")
            self.assertIn(tool.risk, {"low", "medium", "high"})

    def test_status_reports_real_plane_and_audits(self):
        payload, is_error = self.call("status")
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["plane"], "embedded")
        self.assertEqual(payload["policy"], "supervised")
        self.assertIn("summary", payload)

        audit = self.plane.request("GET", "/api/v1/tool-calls")
        self.assertEqual(audit["total"], 1)
        self.assertEqual(audit["items"][0]["tool"], "status")
        self.assertEqual(audit["items"][0]["actor"], "test/1")
        self.assertEqual(audit["items"][0]["status"], "ok")

    def test_readonly_denies_mutation_but_allows_reads(self):
        ctx = ToolContext(plane=self.plane, policy="readonly", base=self.tmp)
        registry = ToolRegistry(ctx)
        payload, is_error = registry.call("missions_list", {}, actor="test")
        self.assertFalse(is_error, payload)
        payload, is_error = registry.call(
            "missions_create", {"title": "Nope", "target": "example.com"}, actor="test")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "policy_denied")
        audit = self.plane.request("GET", "/api/v1/tool-calls")["items"]
        denied = [item for item in audit if item["tool"] == "missions_create"]
        self.assertEqual(denied[0]["status"], "denied")

    def test_schema_rejects_unknown_arguments(self):
        payload, is_error = self.call("status", surprise=True)
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "invalid_arguments")

    # -- scope ------------------------------------------------------------
    def test_scope_check_and_scan_refuse_out_of_scope_targets(self):
        mission = self.create_mission()
        inside = self.call("scope_check", target="api.example.com", mission_id=mission["id"])[0]
        self.assertTrue(inside["in_scope"])
        excluded = self.call("scope_check", target="admin.example.com",
                             mission_id=mission["id"])[0]
        self.assertFalse(excluded["in_scope"])

        payload, is_error = self.call("scan_start", target="evil.test",
                                      mission_id=mission["id"])
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "scope_denied")

    def test_scan_requires_scope_and_links_to_mission(self):
        payload, is_error = self.call("scan_start", target="example.com")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "scope_denied")

        mission = self.create_mission()
        payload, is_error = self.call("scan_start", target="example.com",
                                      mission_id=mission["id"])
        self.assertFalse(is_error, payload)
        run = payload["run"]
        self.assertEqual(payload["mission_id"], mission["id"])
        finished = self.wait_for_run(run["id"])
        self.assertEqual(finished["status"], "done")
        linked = self.plane.request("GET", f"/api/v1/missions/{mission['id']}")
        self.assertEqual(linked["run_count"], 1)
        self.assertEqual(linked["runs"][0]["id"], run["id"])

    def test_probe_refuses_metadata_even_when_scoped(self):
        payload, is_error = self.call(
            "http_probe", target="http://169.254.169.254/latest/meta-data",
            scope=["169.254.169.254"])
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "scope_denied")

    # -- runs and findings -------------------------------------------------
    def test_run_tools_read_and_triage_real_data(self):
        mission = self.create_mission()
        run = self.call("mission_start_run", mission_id=mission["id"])[0]["run"]
        self.wait_for_run(run["id"])

        events = self.call("runs_events", run_id=run["id"])[0]
        self.assertGreaterEqual(len(events["items"]), 1)
        findings = self.call("findings_list", run_id=run["id"])[0]
        self.assertEqual(findings["total"], 1)
        finding = findings["items"][0]
        self.assertEqual(finding["value"], "not-...alue")

        triaged = self.call("finding_triage", finding_id=finding["id"],
                            status="in_progress", notes="needs a live check")[0]
        self.assertEqual(triaged["triage_status"], "in_progress")
        summary = self.call("findings_summary", run_id=run["id"])[0]
        self.assertEqual(summary["summary"]["triage"]["in_progress"], 1)

        report = self.call("runs_report", run_id=run["id"])[0]
        self.assertIn("# NetCast3r test report", report["report"])
        inventory = self.call("runs_inventory", run_id=run["id"],
                              kind="endpoints")[0]
        self.assertEqual(inventory["total"], 1)
        self.assertEqual(inventory["items"][0]["url"], "https://example.com/api/v1")

    def test_findings_create_records_validated_finding(self):
        payload, is_error = self.call(
            "findings_create", title="2FA bypass via email code", severity="high",
            impact="full session without a TOTP challenge",
            evidence="findings/bambu-2fa-email-code-bypass.md", source="manual",
            tags=["auth", "2fa"], value="not-a-real-secret-value", confidence=0.95)
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["severity"], "high")
        self.assertEqual(payload["triage_status"], "new")
        self.assertEqual(payload["tags"], ["auth", "2fa"])
        self.assertNotIn("not-a-real-secret-value", payload["value"])

        fetched = self.call("findings_get", finding_id=payload["id"])[0]
        self.assertEqual(fetched["title"], "2FA bypass via email code")

        bad, is_error = self.call("findings_create", title="x", severity="nope")
        self.assertTrue(is_error)

    def test_learning_tools_round_trip(self):
        mission = self.create_mission()
        lesson = self.call("lessons_record", title="Path variants",
                           lesson="Encoded variants skip route-level gates.",
                           technique="http_path_diff", outcome="success",
                           tags=["encoding"], mission_id=mission["id"])[0]
        listing = self.call("lessons_list", q="encoded", limit=10)[0]
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["id"], lesson["id"])

        skill = self.registry.call("skills_upsert", {
            "name": "authz-matrix", "body": "# Authz\n\nTest each role.",
            "tags": ["authz"]}, actor="test/1")[0]
        self.assertEqual(skill["version"], 1)
        fetched = self.registry.call("skills_get", {"name": "authz-matrix"}, actor="test/1")[0]
        self.assertIn("each role", fetched["body"])

        actions = self.call("next_actions", mission_id=mission["id"])[0]
        self.assertEqual(actions["mission_id"], mission["id"])
        self.assertTrue(actions["actions"])


        finding = self.call("findings_create", title="artifact finding",
                            severity="high")[0]
        artifact = self.registry.call("finding_artifact_add", {
            "finding_id": finding["id"], "name": "poc.txt",
            "content": "request\nresponse\n", "content_type": "text/plain",
        }, actor="test/1")[0]
        self.assertEqual(artifact["name"], "poc.txt")
        self.assertEqual(artifact["bytes"], len("request\nresponse\n"))

        listing = self.call("finding_artifact_list", finding_id=finding["id"])[0]
        self.assertEqual(listing["total"], 1)

        fetched = self.call("finding_artifact_get", finding_id=finding["id"],
                            artifact_id=artifact["id"])[0]
        self.assertEqual(fetched["encoding"], "text")
        self.assertIn("response", fetched["content"])

    def test_submission_ledger_tools_record_real_rows(self):
        mission = self.create_mission()
        payload, is_error = self.call(
            "submissions_create", title="IDOR in invoice export",
            platform="hackerone", program="acme", target="example.com",
            severity="high", mission_id=mission["id"], bounty_cents=50000)
        self.assertFalse(is_error, payload)
        submission = payload
        self.assertEqual(submission["mission_id"], mission["id"])
        self.assertEqual(submission["bounty_cents"], 50000)

        listed = self.call("submissions_list", mission_id=mission["id"])[0]
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["items"][0]["id"], submission["id"])

        updated = self.call("submissions_update", submission_id=submission["id"],
                            status="paid")[0]
        self.assertEqual(updated["status"], "paid")
        self.assertIsNotNone(updated["paid_at"])

        summary = self.call("submissions_summary")[0]
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["paid"], 1)
        self.assertEqual(summary["by_currency"]["USD"]["paid_cents"], 50000)

        refused, is_error = self.call("submissions_delete", submission_id=submission["id"])
        self.assertTrue(is_error)
        self.assertEqual(refused["error"]["code"], "approval_required")

        full = ToolRegistry(ToolContext(plane=self.plane, policy="full", base=self.tmp))
        deleted, is_error = full.call(
            "submissions_delete", {"submission_id": submission["id"], "confirm": True},
            actor="test/1")
        self.assertFalse(is_error, deleted)
        self.assertTrue(deleted["deleted"])
        self.assertEqual(self.call("submissions_get", submission_id=submission["id"])[1], True)

    def test_delete_requires_approved_bound_approval_and_is_single_use(self):
        mission = self.create_mission()
        run = self.call("mission_start_run", mission_id=mission["id"])[0]["run"]
        self.wait_for_run(run["id"])

        payload, is_error = self.call("runs_delete", run_id=run["id"])
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "approval_required")

        arguments = {"run_id": run["id"]}
        approval = self.call("approval_request", mission_id=mission["id"],
                             action="Delete a completed test run",
                             risk="high", tool="runs_delete",
                             arguments=arguments)[0]
        self.assertEqual(approval["status"], "pending")

        # A human decides in the UI/API; the MCP client cannot approve itself.
        self.plane.server.index.decide_approval(approval["id"], "approved",
                                                decided_by="operator")
        payload, is_error = self.call("runs_delete", run_id=run["id"],
                                      approval_id=approval["id"])
        self.assertFalse(is_error, payload)
        self.assertTrue(payload["deleted"])

        # The approval was spent and the run is gone.
        payload, is_error = self.call("runs_delete", run_id=run["id"],
                                      approval_id=approval["id"])
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "approval_required")

    def test_approval_is_bound_to_arguments(self):
        mission = self.create_mission()
        first = self.call("mission_start_run", mission_id=mission["id"])[0]["run"]
        second = self.call("mission_start_run", mission_id=mission["id"])[0]["run"]
        self.wait_for_run(first["id"])
        self.wait_for_run(second["id"])

        approval = self.call("approval_request", mission_id=mission["id"],
                             action="Delete one run", risk="high", tool="runs_delete",
                             arguments={"run_id": first["id"]})[0]
        self.plane.server.index.decide_approval(approval["id"], "approved")
        payload, is_error = self.call("runs_delete", run_id=second["id"],
                                      approval_id=approval["id"])
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "approval_required")
        self.assertIn("different arguments", payload["error"]["message"])

    def test_operator_only_approval_in_supervised_mode(self):
        mission = self.create_mission()
        approval = self.call("approval_request", mission_id=mission["id"],
                             action="Synthetic", risk="high",
                             tool="missions_delete",
                             arguments={"mission_id": mission["id"]})[0]
        payload, is_error = self.call("approval_decide", approval_id=approval["id"],
                                      decision="approved")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "policy_denied")

    def test_full_policy_requires_confirm(self):
        ctx = ToolContext(plane=self.plane, policy="full", base=self.tmp)
        registry = ToolRegistry(ctx)
        mission = self.create_mission()
        payload, is_error = registry.call("missions_delete",
                                         {"mission_id": mission["id"]}, actor="test")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "confirm_required")
        payload, is_error = registry.call(
            "missions_delete", {"mission_id": mission["id"], "confirm": True}, actor="test")
        self.assertFalse(is_error, payload)

    def test_full_policy_can_decide_an_approval_with_confirmation(self):
        ctx = ToolContext(plane=self.plane, policy="full", base=self.tmp)
        registry = ToolRegistry(ctx)
        mission = self.create_mission()
        approval = registry.call("approval_request", {
            "mission_id": mission["id"], "action": "Delete the mission", "risk": "high",
            "tool": "missions_delete", "arguments": {"mission_id": mission["id"]},
        }, actor="test")[0]
        payload, is_error = registry.call(
            "approval_decide", {"approval_id": approval["id"], "decision": "approved"},
            actor="test")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "confirm_required")
        payload, is_error = registry.call(
            "approval_decide", {"approval_id": approval["id"], "decision": "approved",
                                "confirm": True}, actor="test")
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["status"], "approved")

    def test_http_probe_reaches_an_in_scope_local_server(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"probe-ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            mission = self.create_mission(target=f"http://127.0.0.1:{httpd.server_port}/")
            payload, is_error = self.call(
                "http_probe", target=f"http://127.0.0.1:{httpd.server_port}/",
                mission_id=mission["id"])
            self.assertFalse(is_error, payload)
            self.assertEqual(payload["status"], 200)
            self.assertEqual(payload["body"], "probe-ok")
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_http_request_uses_auth_profile_and_redirect_checks(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/echo")
                    self.end_headers()
                    return
                if self.path.startswith("/offsite"):
                    self.send_response(302)
                    self.send_header("Location", "http://localhost:9/echo")
                    self.end_headers()
                    return
                self._echo(b"")

            def do_POST(self):
                length = int(self.headers.get("content-length") or 0)
                self._echo(self.rfile.read(length))

            def _echo(self, body):
                payload = json.dumps({
                    "method": self.command, "path": self.path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                    "body": body.decode("utf-8", "replace"),
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Set-Cookie", "seen=1; Secure")
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{httpd.server_port}"
            mission = self.create_mission(target=base + "/")
            profile, is_error = self.registry.call(
                "auth_profile_set",
                {"name": "test-session",
                 "cookies": {"sid": "top-secret-cookie"},
                 "headers": {"X-CSRF": "csrf-value"}}, actor="test")
            self.assertFalse(is_error, profile)

            payload, is_error = self.call(
                "http_request", target=f"{base}/echo", mission_id=mission["id"],
                method="POST", auth_profile="test-session", json={"hello": "world"})
            self.assertFalse(is_error, payload)
            self.assertEqual(payload["status"], 200)
            self.assertEqual(payload["set_cookie"], ["seen=1; Secure"])
            echoed = json.loads(payload["body"])
            self.assertEqual(echoed["method"], "POST")
            self.assertEqual(echoed["headers"]["cookie"], "sid=top-secret-cookie")
            self.assertEqual(echoed["headers"]["x-csrf"], "csrf-value")
            self.assertEqual(echoed["body"], '{"hello": "world"}')

            override, is_error = self.call(
                "http_request", target=f"{base}/echo", mission_id=mission["id"],
                auth_profile="test-session", headers={"Cookie": "manual=1"})
            self.assertFalse(is_error, override)
            manual = json.loads(override["body"])
            self.assertEqual(manual["headers"]["cookie"], "manual=1")

            follow, is_error = self.call(
                "http_request", target=f"{base}/redirect", mission_id=mission["id"],
                follow_redirects=True)
            self.assertFalse(is_error, follow)
            self.assertEqual(follow["status"], 200)
            self.assertEqual(len(follow["redirects"]), 1)

            blocked, is_error = self.call(
                "http_request", target=f"{base}/offsite", mission_id=mission["id"],
                follow_redirects=True)
            self.assertFalse(is_error, blocked)
            self.assertEqual(blocked["status"], 302)
            self.assertIn("outside the declared scope", blocked["blocked_redirect"])

            audit = self.plane.request("GET", "/api/v1/tool-calls")
            serialized = json.dumps(audit)
            self.assertNotIn("top-secret-cookie", serialized)
            self.assertNotIn("csrf-value", serialized)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_readonly_denies_http_request(self):
        ctx = ToolContext(plane=self.plane, policy="readonly", base=self.tmp)
        registry = ToolRegistry(ctx)
        payload, is_error = registry.call(
            "http_request", {"target": "https://example.com/"}, actor="test")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "policy_denied")

    def test_identity_tools_are_masked_and_registered(self):
        from unittest.mock import patch

        from netcast3r import oast, tempmail

        box = tempmail.Mailbox(id="box-1", address="box@maxxspace.com",
                               password="pw", token="tok", created_at=1.0)
        with patch.object(tempmail, "create_mailbox", return_value=box):
            payload, is_error = self.call("inbox_create")
            self.assertFalse(is_error, payload)
            self.assertEqual(payload["mailbox"]["address"], "box@maxxspace.com")
            self.assertNotIn("token", payload["mailbox"])
            self.assertNotIn("password", payload["mailbox"])

        session = oast.OastSession(id="tok-1", provider="webhook.site", token="tok-1",
                                   url="https://webhook.site/tok-1", created_at=1.0)
        with patch.object(oast, "create_session", return_value=session):
            payload, is_error = self.call("oast_create", label="ssrf")
            self.assertFalse(is_error, payload)
            self.assertEqual(payload["session"]["url"], "https://webhook.site/tok-1")
            self.assertNotIn("token", payload["session"])



    # -- protocol ----------------------------------------------------------
    def test_protocol_initialize_tools_resources_and_prompts(self):
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        init = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18",
                       "clientInfo": {"name": "opencode", "version": "2.1.4"}},
        })["result"]
        self.assertEqual(init["protocolVersion"], "2025-06-18")
        self.assertEqual(init["serverInfo"]["name"], "netcast3r")
        self.assertIn("tools", init["capabilities"])
        self.assertIn("approval", init["instructions"].lower())

        listing = server.handle({"jsonrpc": "2.0", "id": 2,
                                 "method": "tools/list"})["result"]
        self.assertEqual(len(listing["tools"]), len(catalog()))
        names = {tool["name"] for tool in listing["tools"]}
        self.assertIn("scan_start", names)
        self.assertIn("approval_request", names)

        resources = server.handle({"jsonrpc": "2.0", "id": 3,
                                   "method": "resources/list"})["result"]
        self.assertEqual(len(resources["resources"]), 8)
        read = server.handle({"jsonrpc": "2.0", "id": 4, "method": "resources/read",
                              "params": {"uri": "netcast3r://policy"}})["result"]
        policy = json.loads(read["contents"][0]["text"])
        self.assertEqual(policy["policy"], DEFAULT_POLICY)

        prompts = server.handle({"jsonrpc": "2.0", "id": 5,
                                 "method": "prompts/list"})["result"]
        self.assertEqual(len(prompts["prompts"]), 4)

        prompt_args = {
            "recon-mission": {"mission_id": "msn_test"},
            "triage-findings": {"mission_id": "msn_test"},
            "write-report": {"run_id": "run_test"},
            "review-approval": {"approval_id": "apr_test"},
        }
        for index, name in enumerate(prompt_args, start=20):
            got = server.handle({"jsonrpc": "2.0", "id": index, "method": "prompts/get",
                                 "params": {"name": name,
                                            "arguments": prompt_args[name]}})["result"]
            self.assertEqual(got["messages"][0]["role"], "user")
            self.assertTrue(got["messages"][0]["content"]["text"])

        for index, uri in enumerate((
                "netcast3r://status", "netcast3r://missions", "netcast3r://runs",
                "netcast3r://findings", "netcast3r://approvals",
                "netcast3r://tool-calls", "netcast3r://policy"), start=30):
            got = server.handle({"jsonrpc": "2.0", "id": index, "method": "resources/read",
                                 "params": {"uri": uri}})["result"]
            self.assertTrue(got["contents"][0]["text"])

        notifications = server.handle({
            "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        self.assertIsNone(notifications)

        unknown = server.handle({"jsonrpc": "2.0", "id": 6, "method": "nope"})
        self.assertEqual(unknown["error"]["code"], protocol.METHOD_NOT_FOUND)
        server.close()

    def test_stdio_newline_and_content_length_framing(self):
        newline = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        self.assertEqual(protocol.read_message(newline)["method"], "ping")
        body = b'{"jsonrpc":"2.0","id":2,"method":"ping"}'
        framed = io.BytesIO(b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        self.assertEqual(protocol.read_message(framed)["id"], 2)
        with self.assertRaises(protocol.ParseError):
            protocol.read_message(io.BytesIO(b"not json\n"))

    def test_stdio_loop_writes_responses_and_closes_state(self):
        stdin = io.BytesIO(
            b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"test"}}}\n'
            b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
            b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{}}}\n'
        )
        stdout = io.BytesIO()
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        server.run(stdin=stdin, stdout=stdout)
        lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["id"], 1)
        self.assertEqual(lines[1]["id"], 2)
        self.assertFalse(lines[1]["result"]["isError"])
        self.assertFalse((self.tmp / "mcp-state.json").exists())

    def test_mcp_heartbeat_is_visible_without_secrets(self):
        server = MCPServer(plane=self.plane, policy="supervised", base=self.tmp)
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18",
                                  "clientInfo": {"name": "opencode", "version": "2.1.4"}}})
        info = self.plane.request("GET", "/api/v1/mcp")
        self.assertTrue(info["connected"])
        self.assertEqual(info["server"]["policy"], "supervised")
        self.assertEqual(info["server"]["client"]["name"], "opencode")
        self.assertEqual(len(info["tools"]), len(catalog()))
        self.assertNotIn("token", info["server"])
        server.close()
        info = self.plane.request("GET", "/api/v1/mcp")
        self.assertIsNone(info["server"])

    def test_cli_print_config_is_an_mcp_servers_block(self):
        from contextlib import redirect_stdout
        from types import SimpleNamespace

        from netcast3r.cli import cmd_mcp

        buffer = io.StringIO()
        args = SimpleNamespace(policy="supervised", backend="auto", out=str(self.tmp / "results"),
                               base=str(self.tmp), api_url="", print_config=True)
        with redirect_stdout(buffer):
            self.assertEqual(cmd_mcp(args), 0)
        block = json.loads(buffer.getvalue())
        server = block["mcp"]["servers"]["netcast3r"]
        self.assertEqual(server["type"], "local")
        self.assertIn("mcp", server["command"])
        self.assertEqual(server["environment"]["NETCAST3R_MCP_POLICY"], "supervised")
        self.assertNotIn("enabled", server)

    def test_ui_restart_reuses_token_and_api_plane_refreshes(self):
        from netcast3r import control
        from netcast3r.mcp.plane import ApiPlane
        from netcast3r.server import _restore_session_token

        url = "http://127.0.0.1:7857"
        control.write_control_plane(self.tmp, {"pid": 999999, "url": url,
                                               "token": "old-token"})
        self.plane.server.token = "new-token"  # codeaudit: ignore py-hardcoded-secret -- test token
        self.assertTrue(_restore_session_token(self.plane.server))
        self.assertEqual(self.plane.server.token, "old-token")

        plane = ApiPlane(url, "new-token", base=self.tmp)
        control.write_control_plane(self.tmp, {"pid": 1, "url": url, "token": "fresh-token"})
        self.assertTrue(plane._refresh_token())
        self.assertEqual(plane.token, "fresh-token")
        plane.close()




if __name__ == "__main__":
    unittest.main()
