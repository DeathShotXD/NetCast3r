import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.mcp.plane import EmbeddedPlane
from netcast3r.mcp.tools import ToolContext, ToolRegistry, _guard_local_path
from netcast3r.scope import ScopeManager
from netcast3r.server.events import Event
from netcast3r.server.index import Index
from netcast3r.server.jobs import JobManager
from netcast3r.server.keys import KeyStore
from netcast3r.server import Server
from netcast3r.server.events import EventBus


def _runner(run_id, target, options, emit, should_stop):
    emit(Event(type="log", payload={"text": "work"}))
    return {"target": target, "pages": 1, "findings": 0}


class ApprovalBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.plane = EmbeddedPlane(base=self.tmp, results_dir=str(self.tmp / "results"),
                                   runner=_runner)
        self.registry = ToolRegistry(ToolContext(
            plane=self.plane, policy="supervised", base=self.tmp))
        self.index = self.plane.server.index
        self.mission = self.index.create_mission(
            "Binding", "example.com", status="active", scope=["example.com"])

    def tearDown(self):
        self.plane.close()

    def test_unbound_approval_cannot_open_a_high_risk_tool(self):
        approval = self.index.create_approval(
            self.mission["id"], "vague request", risk="high", payload={})
        self.index.decide_approval(approval["id"], "approved", decided_by="operator")
        payload, is_error = self.registry.call(
            "missions_delete",
            {"mission_id": self.mission["id"], "approval_id": approval["id"]},
            actor="test")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "approval_required")
        self.assertIn("not bound", payload["error"]["message"])
        # The mission must still exist after the refused call.
        self.assertIsNotNone(self.index.get_mission(self.mission["id"]))

    def test_approval_request_requires_the_exact_tool(self):
        payload, is_error = self.registry.call(
            "approval_request",
            {"mission_id": self.mission["id"], "action": "please approve",
             "risk": "high"}, actor="test")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "invalid_arguments")


class ScopeWideningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.plane = EmbeddedPlane(base=self.tmp, results_dir=str(self.tmp / "results"),
                                   runner=_runner)
        self.registry = ToolRegistry(ToolContext(
            plane=self.plane, policy="supervised", base=self.tmp))
        self.index = self.plane.server.index
        self.mission = self.index.create_mission(
            "Boundary", "example.com", status="active", scope=["example.com"])

    def tearDown(self):
        self.plane.close()

    def test_caller_scope_cannot_widen_a_mission(self):
        payload, is_error = self.registry.call(
            "http_probe",
            {"target": "http://evil.example/", "mission_id": self.mission["id"],
             "scope": ["evil.example"]}, actor="test")
        self.assertTrue(is_error, payload)
        self.assertEqual(payload["error"]["code"], "scope_denied")

    def test_scheme_less_userinfo_resolves_to_the_dialled_host(self):
        manager = ScopeManager(in_scope=["example.com"])
        self.assertTrue(manager.is_in_scope("example.com"))
        self.assertFalse(manager.is_in_scope("example.com@evil.example"))

    def test_ports_do_not_hide_the_host(self):
        manager = ScopeManager(in_scope=["example.com"])
        self.assertTrue(manager.is_in_scope("example.com:8443"))
        self.assertTrue(manager.is_in_scope("https://example.com:8443/path"))
        with_port = ScopeManager(in_scope=["example.com:8443"])
        self.assertTrue(with_port.is_in_scope("example.com:8443"))


class LocalPathGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ctx = ToolContext(plane=None, policy="supervised", base=self.tmp)
        (self.tmp / "control-plane.json").write_text("{}")
        (self.tmp / "artifacts").mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_secret_state_is_refused(self):
        from netcast3r.mcp.tools import ToolError
        with self.assertRaises(ToolError) as caught:
            _guard_local_path(self.ctx, str(self.tmp / "control-plane.json"))
        self.assertEqual(caught.exception.code, "scope_denied")

    def test_artifact_directory_is_allowed(self):
        target = self.tmp / "artifacts" / "sample.bin"
        target.write_bytes(b"\x00\x01")
        self.assertEqual(_guard_local_path(self.ctx, str(target)), str(target.resolve()))

    def test_ssh_directory_is_refused(self):
        from netcast3r.mcp.tools import ToolError
        home = Path.home()
        with self.assertRaises(ToolError):
            _guard_local_path(self.ctx, str(home / ".ssh" / "id_rsa"))


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.index = Index(base / "netcast3r.db")
        self.bus = EventBus()
        self.keys = KeyStore(base)
        self.jobs = JobManager(self.index, self.bus, _runner, workers=1)
        self.server = Server(self.index, self.bus, self.jobs, self.keys,
                             token="test-token")

    def tearDown(self):
        self.jobs.shutdown()
        self.index.close()
        self.tmp.cleanup()

    def call(self, method, path):
        headers = {"host": "127.0.0.1:7857", "x-netcast3r-token": "test-token"}
        return self.server.route(method, path, {}, headers, b"")

    def test_head_uses_the_get_route(self):
        response = self.call("HEAD", "/api/v1/meta")
        self.assertEqual(response.status, 200)

    def test_finished_jobs_are_not_retained(self):
        run = self.index.create_run("example.com", {})
        self.jobs.submit(run["id"], "example.com", {})
        deadline = time.time() + 5
        while time.time() < deadline:
            if run["id"] not in self.jobs._handles:
                break
            time.sleep(0.02)
        self.assertNotIn(run["id"], self.jobs._handles)


if __name__ == "__main__":
    unittest.main()