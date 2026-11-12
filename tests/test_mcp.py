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
    POLICIES,
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

    def test_readonly_allows_medium_reads_and_denies_destructive_writes(self):
        ctx = ToolContext(plane=self.plane, policy="readonly", base=self.tmp)
        registry = ToolRegistry(ctx)
        payload, is_error = registry.call("missions_list", {}, actor="test")
        self.assertFalse(is_error, payload)
        # Medium, non-destructive reads are now allowed under readonly.
        payload, is_error = registry.call(
            "missions_create", {"title": "Readonly", "target": "example.com"},
            actor="test")
        self.assertFalse(is_error, payload)
        # A high-risk destructive delete is still refused.
        payload, is_error = registry.call(
            "missions_delete", {"mission_id": "msn_missing"}, actor="test")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "policy_denied")
        audit = self.plane.request("GET", "/api/v1/tool-calls")["items"]
        denied = [item for item in audit if item["tool"] == "missions_delete"]
        self.assertEqual(denied[0]["status"], "denied")

    def test_schema_rejects_unknown_arguments(self):
        payload, is_error = self.call("status", surprise=True)
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "invalid_arguments")

    # -- autonomy spine ----------------------------------------------------
    def test_every_result_carries_provenance_and_audit_id(self):
        payload, is_error = self.call("status")
        self.assertFalse(is_error, payload)
        meta = payload["meta"]
        self.assertEqual(meta["tool"], "status")
        self.assertEqual(meta["category"], "workspace")
        self.assertEqual(meta["risk"], "low")
        self.assertEqual(meta["policy"], "supervised")
        self.assertEqual(meta["actor"], "test/1")
        self.assertEqual(meta["status"], "ok")
        self.assertGreaterEqual(meta["duration_ms"], 0)
        audit = self.plane.request("GET", "/api/v1/tool-calls")["items"][0]
        self.assertEqual(meta["audit_id"], audit["id"])
        audit_link = next(link for link in meta["links"] if link["rel"] == "audit")
        self.assertEqual(audit_link["uri"],
                         f"netcast3r://tool-calls/{meta['audit_id']}")

        # A failure carries the same provenance plus a retryable flag and hint.
        payload, is_error = self.call("status", surprise=True)
        self.assertTrue(is_error)
        self.assertFalse(payload["error"]["retryable"])
        self.assertIn("tool_describe", payload["error"]["hint"])
        self.assertEqual(payload["meta"]["status"], "error")
        self.assertEqual(payload["meta"]["tool"], "status")

    def test_list_meta_describes_pagination(self):
        self.create_mission()
        self.create_mission(title="Second")
        payload, is_error = self.call("missions_list", limit=1, page=1)
        self.assertFalse(is_error, payload)
        meta = payload["meta"]["pagination"]
        self.assertEqual(meta["returned"], 1)
        self.assertEqual(meta["total"], 2)
        self.assertEqual(meta["page"], 1)
        self.assertEqual(meta["page_size"], 1)
        self.assertTrue(meta["has_more"])

    def test_tool_search_ranks_exact_prefix_and_filters(self):
        payload, is_error = self.call("tool_search", query="missions_list")
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["items"][0]["name"], "missions_list")
        self.assertIn("exact name", payload["items"][0]["why"])
        self.assertEqual(payload["items"][0]["requires"], "none")

        payload, _ = self.call("tool_search", query="mission", read_only=True, limit=100)
        self.assertTrue(payload["items"])
        self.assertTrue(all(item["read_only"] for item in payload["items"]))
        self.assertTrue(any(item["name"] == "missions_list"
                            for item in payload["items"]))

        payload, _ = self.call("tool_search", category="missions", risk="high")
        self.assertTrue(payload["items"])
        self.assertTrue(all(item["category"] == "missions" for item in payload["items"]))
        self.assertTrue(all(item["risk"] == "high" for item in payload["items"]))
        self.assertIn("missions", payload["categories"])

    def test_tool_describe_is_the_authoritative_contract(self):
        payload, is_error = self.registry.call(
            "tool_describe", {"name": "approval_request"}, actor="test/1")
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["name"], "approval_request")
        self.assertIn("action", payload["required_arguments"])
        self.assertIn("arguments", payload["optional_arguments"])
        self.assertTrue(payload["example_arguments"]["action"].startswith("<"))
        self.assertIn(payload["policy"]["requires"], {"none", "approval"})
        self.assertTrue(payload["resource_templates"])

        payload, is_error = self.registry.call(
            "tool_describe", {"name": "not_a_tool"}, actor="test/1")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "not_found")
        self.assertIn("tool_search", payload["error"]["hint"])

    def test_tool_batch_stays_read_only_and_reuses_registry_gates(self):
        mission = self.create_mission()
        before = self.plane.request("GET", "/api/v1/tool-calls")["items"]
        before_creates = [row for row in before if row["tool"] == "missions_create"]
        payload, is_error = self.call("tool_batch", calls=[
            {"tool": "status", "arguments": {}},
            {"tool": "missions_list", "arguments": {}},
            {"tool": "missions_create",
             "arguments": {"title": "smuggled", "target": "example.com"}},
            {"tool": "tool_batch", "arguments": {"calls": []}},
            {"tool": "http_probe", "arguments": {"target": "example.com"}},
        ])
        self.assertFalse(is_error, payload)
        summary = payload["summary"]
        self.assertEqual(summary["requested"], 5)
        self.assertEqual(summary["succeeded"], 2)
        self.assertEqual(summary["failed"], 3)
        results = {item["index"]: item for item in payload["results"]}
        self.assertTrue(results[0]["ok"])
        self.assertEqual(results[2]["error"]["code"], "policy_denied")
        self.assertIn("state change", results[2]["error"]["detail"])
        self.assertIn("nested", results[3]["error"]["message"])
        self.assertEqual(results[4]["error"]["code"], "policy_denied")
        self.assertIn("context mode", results[4]["error"]["message"])
        # The mutation never reached the ledger or the database.
        self.assertEqual(
            self.plane.request("GET", "/api/v1/missions")["total"], 1)

        # Context mode refuses open-world tools, but read_only mode allows a
        # scoped probe through the same scope gate as a direct call.
        payload, is_error = self.call(
            "tool_batch", mode="read_only",
            calls=[{"tool": "scope_check",
                    "arguments": {"target": "example.com",
                                  "mission_id": mission["id"]}}])
        self.assertFalse(is_error, payload)
        self.assertTrue(payload["results"][0]["result"]["in_scope"])

        # Every sub-call left its own audit row, and the denied mutation left
        # none beyond the mission this test legitimately created.
        rows = self.plane.request("GET", "/api/v1/tool-calls")["items"]
        tools = [row["tool"] for row in rows]
        self.assertEqual(tools.count("status"), 1)
        self.assertEqual(tools.count("missions_list"), 1)
        after_creates = [row for row in rows if row["tool"] == "missions_create"]
        self.assertEqual(len(after_creates), len(before_creates))

    def test_tool_batch_rejects_oversized_and_empty_batches(self):
        for arguments in ({"calls": []},
                          {"calls": [{"tool": "status"}] * 13}):
            payload, is_error = self.call("tool_batch", **arguments)
            self.assertTrue(is_error)
            self.assertEqual(payload["error"]["code"], "invalid_arguments")
            self.assertFalse(payload["error"]["retryable"])

    def test_workspace_brief_reports_live_and_unavailable_sections(self):
        mission = self.create_mission()
        run = self.call("mission_start_run", mission_id=mission["id"])[0]["run"]
        self.wait_for_run(run["id"])
        payload, is_error = self.call("workspace_brief", mission_id=mission["id"])
        self.assertFalse(is_error, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["policy"], "supervised")
        self.assertEqual(payload["focus"]["mission"]["id"], mission["id"])
        self.assertIn("summary", payload["workspace"])
        self.assertIn("pending_approvals", payload)
        self.assertIn("publish_gate", payload)
        for item in payload["recommended_calls"]:
            self.assertIn(item["tool"], _TOOL_MAP)
            self.assertIn(item["requires"],
                          {"none", "approval", "confirm", "operator_only",
                           "policy_denied"})
            self.assertIsInstance(item["arguments"], dict)

    def test_run_watch_accumulates_until_terminal(self):
        mission = self.create_mission()
        run = self.call("mission_start_run", mission_id=mission["id"])[0]["run"]
        payload, is_error = self.call(
            "run_watch", run_id=run["id"], until="terminal", timeout=10)
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["stop_reason"], "terminal")
        self.assertTrue(payload["terminal"])
        self.assertIn(payload["run_status"], {"done", "failed", "stopped"})
        self.assertGreaterEqual(len(payload["events"]), 1)
        self.assertGreater(payload["next_since"], 0)
        self.assertEqual(payload["events"][-1]["seq"], payload["next_since"])

        # Watching a finished run returns the tail immediately.
        again, is_error = self.call("run_watch", run_id=run["id"], timeout=0)
        self.assertFalse(is_error, again)
        self.assertTrue(again["terminal"])
        self.assertIn(again["stop_reason"], {"events", "terminal"})

        # An unknown run surfaces the control plane's not_found, not a fake run.
        missing, is_error = self.call("run_watch", run_id="run_missing", timeout=0)
        self.assertTrue(is_error)
        self.assertEqual(missing["error"]["code"], "not_found")

    def test_tool_health_reports_catalog_and_runtime(self):
        payload, is_error = self.call("tool_health")
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["catalog"]["tools"], len(catalog()))
        self.assertIn("workspace", payload["catalog"]["categories"])
        self.assertIn(payload["policy"], POLICIES)
        names = {check["name"] for check in payload["checks"]}
        for expected in ("catalog", "policy", "runtime", "providers", "approvals"):
            self.assertIn(expected, names)
        self.assertEqual(payload["runtime"]["integrity"], "ok")

    def test_tools_resource_and_approval_templates_resolve(self):
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        catalog_read = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "resources/read",
            "params": {"uri": "netcast3r://tools"}})
        payload = json.loads(catalog_read["result"]["contents"][0]["text"])
        self.assertEqual(payload["total"], len(catalog()))
        self.assertEqual(sum(payload["categories"].values()), len(catalog()))
        names = {item["name"] for item in payload["tools"]}
        self.assertIn("tool_health", names)
        self.assertTrue(any(item["requires"] == "approval"
                            for item in payload["tools"]))

        mission = self.create_mission()
        approval = self.call("approval_request", mission_id=mission["id"],
                             action="Delete a run", risk="high", tool="runs_delete",
                             arguments={"run_id": "run_x"})[0]
        got = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "resources/read",
            "params": {"uri": f"netcast3r://approvals/{approval['id']}"}})
        self.assertEqual(json.loads(got["result"]["contents"][0]["text"])["id"],
                         approval["id"])

        completion = server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "completion/complete",
            "params": {"ref": {"type": "ref/resource",
                               "uri": "netcast3r://approvals/{approval_id}"},
                       "argument": {"name": "approval_id", "value": "apr_"}}})
        self.assertIn(approval["id"],
                      completion["result"]["completion"]["values"])

        # A tool call's meta.audit_id resolves to its own audit row.
        called, _ = self.call("status")
        audit_uri = f"netcast3r://tool-calls/{called['meta']['audit_id']}"
        got = server.handle({"jsonrpc": "2.0", "id": 4, "method": "resources/read",
                             "params": {"uri": audit_uri}})
        row = json.loads(got["result"]["contents"][0]["text"])
        self.assertEqual(row["id"], called["meta"]["audit_id"])
        self.assertEqual(row["tool"], "status")
        self.assertNotIn("token", json.dumps(row).lower())
        server.close()

    def test_tool_batch_isolates_an_unexpected_handler_crash(self):
        from netcast3r.mcp import tools as tools_module

        original = tools_module._HANDLERS["status"]

        def boom(_ctx, _args):
            raise RuntimeError("synthetic crash")

        tools_module._HANDLERS["status"] = boom
        try:
            payload, is_error = self.call("tool_batch", calls=[
                {"tool": "status", "arguments": {}},
                {"tool": "missions_list", "arguments": {}}])
        finally:
            tools_module._HANDLERS["status"] = original
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["summary"]["failed"], 1)
        self.assertEqual(payload["summary"]["succeeded"], 1)
        self.assertIn("synthetic crash", payload["results"][0]["error"]["message"])
        self.assertIn("tool_health", payload["results"][0]["error"]["hint"])
        crashes = [row for row in
                   self.plane.request("GET", "/api/v1/tool-calls")["items"]
                   if row["tool"] == "status"]
        self.assertEqual(crashes[0]["status"], "error")
        self.assertIn("RuntimeError", crashes[0]["error"])

    def test_workspace_brief_tolerates_a_stale_focus_mission(self):
        payload, is_error = self.call("workspace_brief", mission_id="msn_missing")
        self.assertFalse(is_error, payload)
        self.assertIsNone(payload["focus"]["mission"])
        self.assertEqual(payload["focus"]["error"]["code"], "not_found")
        self.assertIn("summary", payload["workspace"])
        self.assertIsNone(payload["focus"]["latest_run"])
        self.assertEqual(payload["focus"]["open_hypotheses"]["items"], [])

    def test_pure_read_handlers_are_read_only_and_batchable(self):
        pure_reads = {
            "brain_context", "brain_journal", "campaign_status", "candidates_list",
            "checklist_catalog", "coverage_get", "directions_list", "director_log",
            "director_status", "chain_templates", "exploit_catalog", "exploit_search",
            "mission_graph", "paths_list", "host_capabilities", "host_find",
            "host_list", "host_processes", "host_stat", "host_read",
            "toolbox_catalog", "toolbox_processes", "evolve_ledger", "evolve_status",
            "kb_digest", "kb_search", "kb_stats", "postex_plan",
            "taxii_collections", "taxii_poll",
        }
        self.assertEqual(
            sorted(name for name in pure_reads if name not in _TOOL_MAP), [])
        self.assertEqual(
            sorted(name for name in pure_reads if not _TOOL_MAP[name].read_only), [])
        # Open-world reads stay out of context-mode batches by design; pure
        # local reads do not.
        self.assertTrue(_TOOL_MAP["taxii_poll"].open_world)
        self.assertFalse(_TOOL_MAP["coverage_get"].open_world)

        mission = self.create_mission()
        payload, is_error = self.call("tool_batch", calls=[
            {"tool": "coverage_get", "arguments": {"mission_id": mission["id"]}},
            {"tool": "director_status", "arguments": {}},
            {"tool": "kb_stats", "arguments": {}},
        ])
        self.assertFalse(is_error, payload)
        self.assertEqual(payload["summary"]["succeeded"], 3)
        self.assertTrue(all(item["ok"] for item in payload["results"]))
        self.assertIn("counts", payload["results"][0]["result"])

    def test_workspace_brief_surfaces_directive_dead_ends_and_activity(self):
        mission = self.create_mission(status="active")
        self.call("hypothesis_create", mission_id=mission["id"],
                  title="DEAD-END: .git HEAD metadata", technique="GET /.git/HEAD")
        self.call("hypothesis_create", mission_id=mission["id"],
                  title="Dashboard redirect can be bypassed",
                  technique="GET /index.php/Dashboard")
        hypotheses = self.call(
            "hypothesis_list", mission_id=mission["id"])[0]["items"]
        dead = next(item for item in hypotheses
                    if item["title"].startswith("DEAD-END"))
        live = next(item for item in hypotheses if item["id"] != dead["id"])
        self.call("agent_notes_write", mission_id=mission["id"],
                  kind="observation", title="Two endpoints allowed",
                  body="Stay inside the operator directive.")

        goal = ("FORBIDDEN: /dashboard. ALLOWED: /api/profile and "
                "/index.php/Dashboard only.")
        created = self.plane.request(
            "POST", f"/api/v1/missions/{mission['id']}/runs",
            body={"target": mission["target"],
                  "options": {"goal": goal, "mode": "swarm", "endless": True}})
        run_id = created["run"]["id"]
        self.wait_for_run(run_id)

        payload, is_error = self.call("workspace_brief", mission_id=mission["id"])
        self.assertFalse(is_error, payload)
        latest = payload["focus"]["latest_run"]
        self.assertEqual(latest["id"], run_id)
        self.assertEqual(latest["operator_directive"], goal)
        self.assertFalse(latest["operator_directive_truncated"])
        self.assertEqual(latest["mode"], "swarm")

        opened = payload["focus"]["open_hypotheses"]
        self.assertEqual(opened["total"], 2)
        self.assertEqual(opened["actionable"], 1)
        self.assertEqual(opened["dead_ends"], 1)
        self.assertEqual(payload["avoid"][0]["hypothesis_id"], dead["id"])
        self.assertIn("dead end", payload["avoid"][0]["reason"])
        for item in payload["recommended_calls"]:
            if item["tool"].startswith("hypothesis_"):
                self.assertNotEqual(item["arguments"].get("hypothesis_id"),
                                    dead["id"])
        self.assertIn(live["id"],
                      [item["arguments"].get("hypothesis_id")
                       for item in payload["recommended_calls"]
                       if item["tool"] == "hypothesis_evidence"])

        notes = payload["focus"]["recent_notes"]["items"]
        self.assertEqual(notes[0]["title"], "Two endpoints allowed")
        self.assertEqual(notes[0]["kind"], "observation")
        calls = payload["focus"]["recent_tool_calls"]["items"]
        self.assertIn("agent_notes_write", [item["tool"] for item in calls])
        self.assertIn("counts", payload["focus"]["coverage"])

    def test_workspace_brief_flags_a_stalled_active_mission(self):
        from netcast3r.mcp import tools as tools_module

        mission = self.create_mission(status="active")
        created = self.plane.request(
            "POST", f"/api/v1/missions/{mission['id']}/runs",
            body={"target": mission["target"], "options": {"mode": "swarm"}})
        self.wait_for_run(created["run"]["id"])

        original = tools_module._age_seconds
        tools_module._age_seconds = lambda _stamp: 1000
        try:
            payload, is_error = self.call("workspace_brief",
                                          mission_id=mission["id"])
        finally:
            tools_module._age_seconds = original
        self.assertFalse(is_error, payload)
        self.assertTrue(payload["focus"]["stalled"])
        self.assertGreaterEqual(payload["focus"]["idle_seconds"], 900)
        stalled = [item for item in payload["blocked"]
                   if item.get("kind") == "stalled_mission"]
        self.assertEqual(len(stalled), 1)
        self.assertEqual(stalled[0]["requires"], "human_decision")

    def test_progress_notifications_flow_from_tool_context(self):
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        events = []
        server.set_notifier(events.append)
        got = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "tool_batch", "arguments": {"calls": [
                {"tool": "status", "arguments": {}},
                {"tool": "missions_list", "arguments": {}}]},
                "_meta": {"progressToken": "tok-1"}}})
        self.assertFalse(got["result"]["isError"])
        progress = [event for event in events
                    if event["method"] == "notifications/progress"]
        self.assertGreaterEqual(len(progress), 4)
        self.assertTrue(all(event["params"]["progressToken"] == "tok-1"
                            for event in progress))
        values = [event["params"]["progress"] for event in progress]
        totals = {event["params"]["total"] for event in progress}
        self.assertEqual(totals, {100})
        self.assertEqual(values[0], 0)
        self.assertEqual(values[-1], 100)
        self.assertEqual(values, sorted(values))
        self.assertGreater(len(set(values)), 2)
        self.assertIsNone(server.registry.ctx.progress)
        server.close()

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

        bare, is_error = self.call(
            "findings_create", title="no proof yet", severity="high")
        self.assertTrue(is_error, bare)
        self.assertIn("evidence", str(bare).lower())

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


        finding = self.call(
            "findings_create", title="artifact finding", severity="high",
            evidence="GET /api/item/1 returned another user's object with 200.")[0]
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

    def test_helix_toolsmith_scripts_write_read_and_run(self):
        mission = self.create_mission()
        written = self.registry.call("helix_script_write", {
            "name": "probe-echo", "content": 'print("helix-ok")\n',
            "purpose": "round-trip", "language": "python",
            "tags": ["smoke"], "mission_id": mission["id"]}, actor="test/1")[0]
        self.assertEqual(written["name"], "probe-echo")
        self.assertEqual(written["language"], "python")

        listing = self.call("helix_scripts_list", q="probe", limit=10)[0]
        self.assertEqual(len(listing["items"]), 1)
        self.assertEqual(listing["items"][0]["id"], written["id"])

        fetched = self.call("helix_script_get", script_id=written["id"])[0]
        self.assertIn("helix-ok", fetched["content"])

        # Supervised policy: running code is high risk, so it is held for an approval.
        payload, is_error = self.call("helix_script_run", script_id=written["id"])
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "approval_required")

        # A full-policy registry still needs an explicit confirm.
        ctx = ToolContext(plane=self.plane, policy="full", base=self.tmp)
        registry = ToolRegistry(ctx)
        payload, is_error = registry.call(
            "helix_script_run", {"script_id": written["id"]}, actor="test")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "confirm_required")
        result = registry.call(
            "helix_script_run", {"script_id": written["id"], "confirm": True},
            actor="test")[0]
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("helix-ok", result["stdout"])

        catalogue = self.call("helix_tools", q="curl")[0]
        self.assertIn("capabilities", catalogue)

    def test_second_brain_tools_expose_peer_role_without_authorization(self):
        status = self.call("second_brain_status")[0]
        self.assertIn("helix_role", status)
        self.assertFalse(status["can_apply_code"])

        synced = self.call(
            "second_brain_sync", peer_note="Parser differential beat the route gate.",
            peer_name="opencode")[0]
        self.assertIn("learned", synced)
        self.assertTrue(synced.get("peer_lesson"))

        upgrade = self.call(
            "second_brain_upgrade", title="Add a parser probe",
            rationale="A peer needs a reusable parser-differential check.",
            body="def probe():\n    pass\n", apply_code=True,
            filename="parser_probe.py")[0]
        self.assertTrue(upgrade["written"]["quarantined"])
        self.assertFalse(upgrade["can_self_upgrade"])
        self.assertTrue(upgrade["written"]["path"].endswith("parser_probe.py"))

    def test_brain_session_tools_round_trip(self):
        created = self.call("brain_session_create", title="Operator thread")[0]
        self.assertEqual(created["title"], "Operator thread")
        session_id = created["id"]
        self.assertEqual(self.call("brain_session_get", session_id=session_id)[0]["id"],
                         session_id)

        renamed = self.call("brain_session_update", session_id=session_id,
                            title="Renamed")[0]
        self.assertEqual(renamed["title"], "Renamed")

        forked = self.call("brain_session_fork", session_id=session_id,
                           title="Branch")[0]
        self.assertNotEqual(forked["id"], session_id)

        listing = self.call("brain_sessions_list", limit=20)[0]
        self.assertIn(session_id, [row["id"] for row in listing["items"]])

        messages = self.call("brain_session_messages", session_id=session_id)[0]
        self.assertEqual(messages["items"], [])

        # Delete is high risk, so supervised policy holds it for an approval.
        payload, is_error = self.call("brain_session_delete", session_id=session_id)
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "approval_required")

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

    def test_readonly_allows_http_request_and_denies_high_risk(self):
        ctx = ToolContext(plane=self.plane, policy="readonly", base=self.tmp)
        registry = ToolRegistry(ctx)
        payload, is_error = registry.call(
            "http_request", {"target": "https://example.com/",
                             "scope": ["example.com"]}, actor="test")
        self.assertFalse(is_error, payload)
        payload, is_error = registry.call(
            "host_shell", {"command": "true"}, actor="test")
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
        uris = {item["uri"] for item in resources["resources"]}
        self.assertGreaterEqual(len(uris), 8)
        for expected in ("netcast3r://status", "netcast3r://providers",
                         "netcast3r://director", "netcast3r://brain",
                         "netcast3r://checklists"):
            self.assertIn(expected, uris)

        templates = server.handle({"jsonrpc": "2.0", "id": 13,
                                   "method": "resources/templates/list"})["result"]
        template_uris = {item["uriTemplate"] for item in templates["resourceTemplates"]}
        self.assertIn("netcast3r://missions/{mission_id}", template_uris)
        self.assertIn("netcast3r://runs/{run_id}/events", template_uris)
        self.assertIn("netcast3r://findings/{finding_id}", template_uris)

        completion = server.handle({
            "jsonrpc": "2.0", "id": 14, "method": "completion/complete",
            "params": {"ref": {"type": "ref/prompt", "name": "recon-mission"},
                       "argument": {"name": "mission_id", "value": ""}},
        })["result"]
        self.assertIn("completion", completion)
        self.assertIsInstance(completion["completion"]["values"], list)

        read = server.handle({"jsonrpc": "2.0", "id": 4, "method": "resources/read",
                              "params": {"uri": "netcast3r://policy"}})["result"]
        policy = json.loads(read["contents"][0]["text"])
        self.assertEqual(policy["policy"], DEFAULT_POLICY)

        prompts = server.handle({"jsonrpc": "2.0", "id": 5,
                                 "method": "prompts/list"})["result"]
        prompt_names = {item["name"] for item in prompts["prompts"]}
        for expected in ("recon-mission", "write-report", "choose-next-action",
                         "autonomy-brief", "watch-run", "recover-tool-call"):
            self.assertIn(expected, prompt_names)

        prompt_args = {
            "recon-mission": {"mission_id": "msn_test"},
            "triage-findings": {"mission_id": "msn_test"},
            "write-report": {"run_id": "run_test"},
            "review-approval": {"approval_id": "apr_test"},
            "choose-next-action": {"mission_id": "msn_test"},
            "autonomy-brief": {"mission_id": "msn_test"},
            "watch-run": {"run_id": "run_test"},
            "recover-tool-call": {"tool": "scope_check"},
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

    def test_resource_templates_read_live_entities(self):
        mission = self.create_mission()
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        got = server.handle({"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                             "params": {"uri": f"netcast3r://missions/{mission['id']}"}})
        self.assertIn("result", got, got)
        payload = json.loads(got["result"]["contents"][0]["text"])
        self.assertTrue(payload)

        bad = server.handle({"jsonrpc": "2.0", "id": 2, "method": "resources/read",
                             "params": {"uri": "netcast3r://nope/xyz"}})
        self.assertEqual(bad["error"]["code"], protocol.INVALID_PARAMS)

        # Helix scripts are resources too, and completion offers their ids.
        script = self.registry.call("helix_script_write", {
            "name": "probe-one", "content": "print('x')\n"}, actor="test/1")[0]
        listing = server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "resources/read",
            "params": {"uri": "netcast3r://helix/scripts"}})
        items = json.loads(listing["result"]["contents"][0]["text"])["items"]
        self.assertIn(script["id"], [row["id"] for row in items])

        one = server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "resources/read",
            "params": {"uri": f"netcast3r://helix/scripts/{script['id']}"}})
        self.assertIn("print", json.loads(one["result"]["contents"][0]["text"])["content"])

        completion = server.handle({
            "jsonrpc": "2.0", "id": 5, "method": "completion/complete",
            "params": {"ref": {"type": "ref/resource",
                               "uri": "netcast3r://helix/scripts/{script_id}"},
                       "argument": {"name": "script_id", "value": "probe"}}})
        self.assertIn(script["id"],
                      completion["result"]["completion"]["values"])
        server.close()

    def test_continuity_resource_reads_the_live_boot(self):
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        got = server.handle({"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                             "params": {"uri": "netcast3r://continuity"}})
        self.assertIn("result", got, got)
        payload = json.loads(got["result"]["contents"][0]["text"])
        self.assertIn("current", payload)
        self.assertIn("run_counts", payload)
        server.close()

    def test_resource_subscription_validates_and_tracks(self):
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        ok = server.handle({"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe",
                            "params": {"uri": "netcast3r://status"}})
        self.assertIn("result", ok, ok)
        self.assertIn("netcast3r://status", server._subs)
        gone = server.handle({"jsonrpc": "2.0", "id": 2, "method": "resources/unsubscribe",
                              "params": {"uri": "netcast3r://status"}})
        self.assertIn("result", gone)
        self.assertNotIn("netcast3r://status", server._subs)
        bad = server.handle({"jsonrpc": "2.0", "id": 3, "method": "resources/subscribe",
                             "params": {"uri": "netcast3r://nope/xyz"}})
        self.assertEqual(bad["error"]["code"], protocol.INVALID_PARAMS)
        server.close()

    def test_watcher_emits_resource_updated_on_change(self):
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        events: list[dict] = []
        server.set_notifier(lambda message: events.append(message))
        # A stale cached state makes the first poll a change on purpose.
        server._subs["netcast3r://status"] = "stale-state"
        server._ensure_watcher()
        deadline = time.time() + 7
        while time.time() < deadline and not events:
            time.sleep(0.2)
        server._stop.set()
        updated = [e for e in events
                   if e["method"] == "notifications/resources/updated"
                   and e["params"]["uri"] == "netcast3r://status"]
        self.assertTrue(updated, events)
        server.close()

    def test_logging_level_gates_notifications(self):
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        events: list[dict] = []
        server.set_notifier(lambda message: events.append(message))
        bad = server.handle({"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel",
                             "params": {"level": "nonsense"}})
        self.assertEqual(bad["error"]["code"], protocol.INVALID_PARAMS)

        server.handle({"jsonrpc": "2.0", "id": 2, "method": "logging/setLevel",
                       "params": {"level": "warning"}})
        server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "missions_get", "arguments": {}}})
        warned = [e for e in events if e["method"] == "notifications/message"]
        self.assertTrue(warned, events)
        self.assertEqual(warned[-1]["params"]["level"], "warning")

        events.clear()
        server.handle({"jsonrpc": "2.0", "id": 4, "method": "logging/setLevel",
                       "params": {"level": "critical"}})
        server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                       "params": {"name": "missions_get", "arguments": {}}})
        self.assertEqual(
            [e for e in events if e["method"] == "notifications/message"], [])
        server.close()

    def test_sampling_and_roots_round_trip_with_the_client(self):
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18",
                        "clientInfo": {"name": "fake", "version": "1"},
                        "capabilities": {"sampling": {},
                                         "roots": {"listChanged": True}}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "sampling_complete",
                        "arguments": {"prompt": "hi"}}},
            {"jsonrpc": "2.0", "id": "srv-1",
             "result": {"model": "client-model",
                        "content": {"type": "text", "text": "hello from the client"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "client_roots", "arguments": {}}},
            {"jsonrpc": "2.0", "id": "srv-2",
             "result": {"roots": [{"uri": "file:///work", "name": "work"}]}},
        ]
        stdin = io.BytesIO(
            "".join(json.dumps(line) + "\n" for line in lines).encode())
        stdout = io.BytesIO()
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        server.run(stdin=stdin, stdout=stdout)
        out = [json.loads(line) for line in
               stdout.getvalue().decode("utf-8").splitlines() if line.strip()]
        by_id = {item.get("id"): item for item in out}
        sampling = by_id[2]["result"]["structuredContent"]
        self.assertEqual(sampling["text"], "hello from the client")
        self.assertEqual(sampling["model"], "client-model")
        roots = by_id[3]["result"]["structuredContent"]
        self.assertEqual(roots["roots"][0]["uri"], "file:///work")
        methods = [item.get("method") for item in out if item.get("method")]
        self.assertIn("sampling/createMessage", methods)
        self.assertIn("roots/list", methods)

    def test_sampling_without_client_capability_is_refused(self):
        server = MCPServer(plane=self.plane, policy=DEFAULT_POLICY, base=self.tmp)
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18",
                                  "clientInfo": {"name": "no-caps"}}})
        # A client that does not advertise the capability is told so, not guessed at.
        got = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                             "params": {"name": "client_roots", "arguments": {}}})
        self.assertTrue(got["result"]["isError"], got)
        self.assertEqual(
            got["result"]["structuredContent"]["error"]["code"], "unsupported")
        server.close()

    def test_host_paths_are_bounded_by_client_roots(self):
        from netcast3r.mcp.tools import ToolContext, ToolError, _require_within_roots

        class _FakeClient:
            def client_roots(self, timeout=20):
                return {"roots": [{"uri": "file:///work"}]}

        ctx = ToolContext(plane=None, client=_FakeClient())
        _require_within_roots(ctx, "/work/report.md")   # inside: allowed
        with self.assertRaises(ToolError) as caught:
            _require_within_roots(ctx, "/etc/passwd")    # outside: refused
        self.assertEqual(caught.exception.code, "outside_roots")

        # A context with no client keeps the unbounded behaviour.
        plain = ToolContext(plane=None)
        _require_within_roots(plain, "/etc/passwd")

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
