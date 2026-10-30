import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.mcp.plane import EmbeddedPlane
from netcast3r.mcp.tools import ToolContext, ToolRegistry, catalog
from netcast3r.providers import Completion, ProviderBus
from netcast3r.server import build_server


class LabHandler(BaseHTTPRequestHandler):
    delay = 0.0

    def do_GET(self):
        if type(self).delay:
            time.sleep(type(self).delay)
        body = ("<html><head><title>Lab target</title></head>"
                "<body>runtime verification</body></html>").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "lab")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class RuntimeHarness:
    """Shared lab target, temp server, and helpers for the runtime tests."""

    delay = 0.0

    def setUp(self):
        LabHandler.delay = self.delay
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]
        self.target = f"http://127.0.0.1:{self.port}/"
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.runtime = self.server._agent()

    def tearDown(self):
        self.runtime.shutdown()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def mission(self, autonomy="supervised", scope=None, budget=None, status="active"):
        return self.server.index.create_mission(
            "Runtime verification", self.target, "Verify the runtime end to end.",
            status=status, autonomy=autonomy, scope=scope if scope is not None else [self.target],
            budget=budget or {})

    def wait(self, mission_id, timeout=20.0):
        deadline = time.time() + timeout
        state = self.runtime.status(mission_id)
        while time.time() < deadline:
            state = self.runtime.status(mission_id)
            if state["status"] in {"done", "error", "stopped"}:
                return state
            time.sleep(0.05)
        self.fail(f"runtime did not finish: {state['status']}")


class RuntimeCases(RuntimeHarness):
    """The behaviour every concrete runtime test class runs."""

    def test_plan_executes_verifies_and_audits_every_task(self):
        mission = self.mission(status="draft")
        started = self.runtime.start(mission["id"], {"max_seconds": 30})
        self.assertIn(started["status"], {"planning", "running"})
        state = self.wait(mission["id"])

        self.assertEqual(state["status"], "done", state["last_error"])
        self.assertIn("created 0 findings", state["summary"])
        self.assertEqual([task["kind"] for task in state["tasks"]],
                         ["scope", "recall", "probe", "inventory", "verify"])
        for task in state["tasks"]:
            self.assertEqual(task["status"], "verified", task)
        probe = next(task for task in state["tasks"] if task["kind"] == "probe")
        self.assertEqual(probe["evidence"]["status"], 200)
        self.assertEqual(probe["evidence"]["title"], "Lab target")
        self.assertIn("reachability, not a finding", probe["verifier_notes"])
        self.assertEqual(state["usage"]["tasks_done"], 5)
        self.assertEqual(state["usage"]["calls"], 0)
        self.assertFalse(state["usage"]["cost_reported"])

        calls, total = self.server.index.list_tool_calls(mission_id=mission["id"], limit=50)
        self.assertEqual(total, 9)
        self.assertEqual({call["tool"] for call in calls},
                         {"scope_check", "http_probe", "missions_get",
                          "runs_list", "findings_summary", "lessons_list", "skills_list"})
        self.assertTrue(all(call["actor"] == "agent:runtime" for call in calls))
        self.assertTrue(all(call["status"] == "ok" for call in calls))
        self.assertEqual(self.server.index.list_findings(limit=10)[1], 0)
        self.assertEqual(self.server.index.get_mission(mission["id"])["status"], "active")

    def test_training_mission_plans_instead_of_crawling(self):
        mission = self.mission(status="draft")
        self.server.index.patch_mission(
            mission["id"], title="Training lab session",
            objective="Practice the next labs and record a lesson.")
        self.runtime.start(mission["id"], {"max_seconds": 30})
        state = self.wait(mission["id"])

        self.assertEqual(state["status"], "done", state["last_error"])
        self.assertEqual(state["role"], "training")
        kinds = [task["kind"] for task in state["tasks"]]
        self.assertIn("training_plan", kinds)
        self.assertIn("training_research", kinds)
        self.assertIn("training_gaps", kinds)
        self.assertIn("verify", kinds)
        self.assertIn("training lab(s) selected", state["summary"])
        calls, _ = self.server.index.list_tool_calls(
            mission_id=mission["id"], limit=50)
        tools = {call["tool"] for call in calls}
        self.assertIn("training_plan", tools)
        self.assertIn("technique_plan", tools)
        self.assertIn("selfmodel_gaps", tools)
        self.assertNotIn("run_create", tools)

    def test_scope_exclusion_stops_before_the_probe(self):
        mission = self.mission(scope=["!127.0.0.1"])
        self.runtime.start(mission["id"], {"max_seconds": 30})
        state = self.wait(mission["id"])

        self.assertEqual(state["status"], "error")
        self.assertIn("outside the declared scope", state["last_error"])
        self.assertEqual(state["tasks"][0]["status"], "failed")
        self.assertEqual(state["tasks"][1]["status"], "skipped")
        probe_calls = [call for call in self.server.index.list_tool_calls(
            mission_id=mission["id"], limit=50)[0] if call["tool"] == "http_probe"]
        self.assertEqual(probe_calls, [])

    def test_manual_autonomy_needs_an_explicit_opt_in(self):
        mission = self.mission(autonomy="manual")
        with self.assertRaises(ValueError) as caught:
            self.runtime.start(mission["id"])
        self.assertIn("manual", str(caught.exception))
        state = self.runtime.start(mission["id"], {"allow_manual": True, "max_seconds": 30})
        self.assertIn(state["status"], {"planning", "running"})
        self.wait(mission["id"])

    def test_model_analysis_is_advisory_and_usage_is_recorded(self):
        original = ProviderBus.complete

        def fake_complete(self, agent, messages, timeout=45.0, exclude_providers=None):
            return Completion(
                text="The evidence shows only that the target answered. Nothing is proven.",
                provider="fake", model="fake-analyst",
                usage={"prompt_tokens": 120, "completion_tokens": 24, "cost_usd": 0.0021},
                duration_ms=9)

        ProviderBus.complete = fake_complete
        try:
            mission = self.mission(autonomy="autonomous")
            self.runtime.start(mission["id"], {"use_model": True, "max_seconds": 30})
            state = self.wait(mission["id"])
        finally:
            ProviderBus.complete = original

        self.assertEqual(state["status"], "done")
        analysis = next(task for task in state["tasks"] if task["kind"] == "analysis")
        self.assertEqual(analysis["status"], "unverified")
        self.assertEqual(analysis["verification"], "advisory")
        self.assertIn("not evidence", analysis["verifier_notes"])
        self.assertEqual(state["usage"]["calls"], 1)
        self.assertEqual(state["usage"]["prompt_tokens"], 120)
        self.assertEqual(state["usage"]["completion_tokens"], 24)
        self.assertAlmostEqual(state["usage"]["cost_cents"], 0.21)
        self.assertTrue(state["usage"]["cost_reported"])
        self.assertEqual(self.server.index.list_findings(limit=10)[1], 0)

    def test_orphaned_active_state_is_reported_interrupted(self):
        mission = self.mission()
        self.server.index.ensure_agent_state(mission["id"])
        self.server.index.patch_agent_state(mission["id"], status="running")
        state = self.runtime.status(mission["id"])
        self.assertEqual(state["status"], "interrupted")
        self.assertTrue(state["stale"])
        with self.assertRaises(ValueError):
            self.runtime.start(mission["id"])
        self.runtime.start(mission["id"], {"restart": True, "max_seconds": 30})
        self.wait(mission["id"])


class AgentRuntimeTests(RuntimeCases, unittest.TestCase):
    pass


class AgentRuntimePauseTests(RuntimeHarness, unittest.TestCase):
    delay = 0.9

    def test_pause_resume_and_stop(self):
        mission = self.mission()
        self.runtime.start(mission["id"], {"max_seconds": 30})
        time.sleep(0.15)

        paused = self.runtime.pause(mission["id"])
        self.assertEqual(paused["status"], "paused")
        time.sleep(0.3)
        self.assertEqual(self.runtime.status(mission["id"])["status"], "paused")

        resumed = self.runtime.resume(mission["id"])
        self.assertIn(resumed["status"], {"running", "planning"})
        done = self.wait(mission["id"])
        self.assertEqual(done["status"], "done")

        second = self.mission()
        self.runtime.start(second["id"], {"max_seconds": 30})
        time.sleep(0.15)
        stopping = self.runtime.stop(second["id"])
        self.assertEqual(stopping["status"], "stopping")
        stopped = self.wait(second["id"])
        self.assertEqual(stopped["status"], "stopped")
        self.assertTrue(any(task["status"] == "skipped" for task in stopped["tasks"]))


class AgentMCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.plane = EmbeddedPlane(base=self.tmp, results_dir=str(self.tmp / "results"),
                                   runner=None)
        self.ctx = ToolContext(plane=self.plane, policy="supervised", base=self.tmp)
        self.registry = ToolRegistry(self.ctx)

    def tearDown(self):
        self.plane.close()

    def call(self, name, **args):
        return self.registry.call(name, args, actor="test/agent")

    def test_agent_tools_are_published_and_drive_the_runtime(self):
        names = {tool["name"] for tool in catalog()}
        self.assertTrue({"agent_status", "agent_start", "agent_pause",
                         "agent_resume", "agent_stop"} <= names)

        payload, is_error = self.call(
            "missions_create", title="MCP runtime", target="https://runtime.example.test",
            status="active", autonomy="supervised",
            scope=["https://runtime.example.test"])
        self.assertFalse(is_error, payload)
        mission_id = payload["id"]

        status, is_error = self.call("agent_status", mission_id=mission_id)
        self.assertFalse(is_error, status)
        self.assertEqual(status["status"], "idle")
        self.assertEqual(status["tasks"], [])

        # A closed port is a real failed probe, not a fabricated finding. The
        # runtime must record the failure and stop the plan.
        started, is_error = self.call(
            "agent_start", mission_id=mission_id, max_seconds=30)
        self.assertFalse(is_error, started)
        deadline = time.time() + 30
        while time.time() < deadline:
            status, is_error = self.call("agent_status", mission_id=mission_id)
            self.assertFalse(is_error, status)
            if status["status"] in {"done", "error", "stopped"}:
                break
            time.sleep(0.1)
        self.assertEqual(status["status"], "error")
        self.assertEqual(status["tasks"][0]["status"], "verified")
        probe_task = next(task for task in status["tasks"] if task["kind"] == "probe")
        self.assertEqual(probe_task["status"], "failed")
        self.assertIn("probe", status["last_error"])

        audit, is_error = self.call("tool_calls_list", mission_id=mission_id, limit=50)
        self.assertFalse(is_error, audit)
        audited = {item["tool"] for item in audit["items"]}
        self.assertIn("agent_start", audited)
        self.assertIn("http_probe", audited)

    def test_agent_role_builds_a_role_specific_plan(self):
        payload, is_error = self.call(
            "missions_create", title="Role plan", target="https://runtime.example.test",
            status="active", autonomy="supervised",
            scope=["https://runtime.example.test"])
        self.assertFalse(is_error, payload)
        mission_id = payload["id"]
        started, is_error = self.call(
            "agent_start", mission_id=mission_id, role="auth", max_seconds=30)
        self.assertFalse(is_error, started)
        self.assertEqual(started["role"], "auth")
        status, is_error = self.call("agent_status", mission_id=mission_id)
        self.assertFalse(is_error, status)
        kinds = [task["kind"] for task in status["tasks"]]
        self.assertIn("auth_inventory", kinds)
        self.assertIn("verify", kinds)
        self.call("agent_stop", mission_id=mission_id)

    def test_agent_start_refuses_an_out_of_scope_target(self):
        payload, is_error = self.call(
            "missions_create", title="Scope gate", target="https://outside.example.test",
            status="active", autonomy="supervised", scope=["!outside.example.test"])
        self.assertFalse(is_error, payload)
        denied, is_error = self.call("agent_start", mission_id=payload["id"])
        self.assertTrue(is_error)
        self.assertEqual(denied["error"]["code"], "scope_denied")
