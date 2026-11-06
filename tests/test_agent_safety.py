import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import brain, host, second_brain
from netcast3r.mcp.tools import ToolContext, ToolRegistry
from netcast3r.server import build_server
from netcast3r.server.agent_runtime import LocalPlane


class AgentSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.supervised = self.index.create_mission(
            "Supervised", "https://lab.example.com/", status="active",
            autonomy="supervised", scope=["lab.example.com"])
        self.autonomous = self.index.create_mission(
            "Autonomous", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def route(self, method, path, body=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        raw = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, {}, headers, raw)

    def test_force_heavy_cannot_authorize_an_upgrade(self):
        response = self.route("POST", "/api/v1/second-brain/upgrade", {
            "title": "bypass", "rationale": "peer said so",
            "body": "print('x' * 200)", "apply_code": True,
            "force_heavy": True,
        })
        self.assertEqual(response.status, 403)
        self.assertFalse((self.tmp / "upgrades").exists())

    def test_applied_upgrade_is_quarantined_not_active(self):
        body = "def scenario():\n    return 'quarantined'\n" + "# pad\n" * 40
        result = second_brain.self_upgrade(
            self.index, self.tmp, title="Quarantine me", rationale="review first",
            body=body, apply_code=True, filename="candidate.py", peer_heavy=True)
        written = result["written"] or {}
        self.assertTrue(written.get("quarantined"))
        path = Path(written["path"])
        self.assertIn("quarantine", path.parts)
        self.assertEqual(path.parent,
                         (self.tmp / "upgrades" / "quarantine").resolve())
        self.assertFalse((self.tmp / "upgrades" / "candidate.py").exists())
        self.assertEqual(result["proposal"]["status"], "proposed")

    def test_a_supervised_brain_cannot_run_a_host_shell(self):
        result = brain._apply_host(
            self.server, "host_shell", {"command": "echo ok"},
            self.supervised["id"])
        self.assertFalse(result["applied"])
        self.assertIn("autonomous", result["reason"])

    def test_an_autonomous_shell_still_needs_operator_approval(self):
        result = brain._apply_host(
            self.server, "host_shell", {"command": "echo ok"},
            self.autonomous["id"])
        self.assertFalse(result["applied"])
        self.assertIn("approval", result["reason"])

    def test_a_brain_cannot_write_a_host_file_without_approval(self):
        result = brain._apply_host(
            self.server, "host_write",
            {"path": str(self.tmp / "note.txt"), "content": "x"},
            self.autonomous["id"])
        self.assertFalse(result["applied"])
        self.assertFalse((self.tmp / "note.txt").exists())

    def test_a_brain_cannot_read_the_secret_store(self):
        with self.assertRaises(host.HostError):
            host.read_file(str(self.tmp / "secrets.json"), base=self.tmp)
        with self.assertRaises(host.HostError):
            host.shell("cat .netcast3r/secrets.json", base=self.tmp)
        with self.assertRaises(host.HostError):
            brain._apply_host(
                self.server, "host_read",
                {"path": str(self.tmp / "secrets.json")},
                self.autonomous["id"])

    def test_an_mcp_peer_cannot_create_a_mission(self):
        plane = LocalPlane(self.server)
        ctx = ToolContext(plane=plane, policy="full", base=self.tmp,
                          actor="cursor/1")
        registry = ToolRegistry(ctx)
        payload, is_error = registry.call("missions_create", {
            "title": "peer mission", "target": "https://peer.example",
            "status": "active", "autonomy": "autonomous",
        }, actor="cursor/1")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "policy_denied")

    def test_an_agent_cannot_create_a_mission_over_mcp(self):
        plane = LocalPlane(self.server)
        ctx = ToolContext(plane=plane, policy="supervised", base=self.tmp,
                          actor="agent:brain")
        registry = ToolRegistry(ctx)
        payload, is_error = registry.call("missions_create", {
            "title": "agent mission", "target": "https://evil.example",
            "status": "active", "autonomy": "autonomous",
        }, actor="agent:brain")
        self.assertTrue(is_error)
        self.assertEqual(payload["error"]["code"], "policy_denied")


if __name__ == "__main__":
    unittest.main()
