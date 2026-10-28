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
    emit(Event(type="log", agent="recon", payload={"text": "crawling"}))
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
                             action="Synthetic", risk="high")[0]
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
        self.assertEqual(len(resources["resources"]), 7)
        read = server.handle({"jsonrpc": "2.0", "id": 4, "method": "resources/read",
                              "params": {"uri": "netcast3r://policy"}})["result"]
        policy = json.loads(read["contents"][0]["text"])
        self.assertEqual(policy["policy"], DEFAULT_POLICY)

        prompts = server.handle({"jsonrpc": "2.0", "id": 5,
                                 "method": "prompts/list"})["result"]
        self.assertEqual(len(prompts["prompts"]), 4)

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



if __name__ == "__main__":
    unittest.main()
