import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import control, second_brain
from netcast3r.server import build_server


class SecondBrainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index

    def tearDown(self):
        self.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_status_without_peer_is_primary(self):
        status = second_brain.status(self.index, self.tmp)
        self.assertEqual(status["helix_role"], "primary")
        self.assertFalse(status["peer"]["connected"])
        self.assertFalse(status["can_self_upgrade"])

    def test_heavy_peer_flips_helix_to_second_brain(self):
        control.write_mcp_state(self.tmp, {
            "schema": 1, "pid": os.getpid(), "client": {
                "name": "opencode", "version": "2.0"},
            "calls": 3, "initialized": True,
        })
        status = second_brain.status(self.index, self.tmp)
        self.assertEqual(status["helix_role"], "second")
        self.assertTrue(status["peer"]["heavy"])
        self.assertTrue(status["can_self_upgrade"])

    def test_a_heavy_peer_upgrade_is_quarantined_for_review(self):
        control.write_mcp_state(self.tmp, {
            "schema": 1, "pid": os.getpid(),
            "client": {"name": "cursor", "version": "1"},
        })
        body = (
            "def probe_idor(session, object_id):\n"
            "    '''Minimal IDOR delta for a second-brain upgrade.'''\n"
            "    return session.get(f'/api/orders/{object_id}')\n"
        ) * 3
        result = second_brain.self_upgrade(
            self.index, self.tmp, title="IDOR order probe",
            rationale="Chain authenticated IDOR into other-user order read",
            body=body, apply_code=True, peer_heavy=True,
            filename="idor_order_probe.py")
        self.assertTrue(result["written"])
        self.assertTrue(result["written"].get("quarantined"))
        path = Path(result["written"]["path"])
        self.assertTrue(path.is_file())
        self.assertIn("quarantine", path.parts)
        self.assertIn("probe_idor", path.read_text())
        self.assertEqual((result.get("proposal") or {}).get("status"), "proposed")

    def test_brain_context_exposes_second_brain_and_moe(self):
        from netcast3r import brain

        snapshot = brain.context(self.index, self.server._director())
        self.assertIn("second_brain", snapshot)
        self.assertIn("moe", snapshot)
        self.assertTrue(snapshot["moe"].get("available", True))

    def test_mcp_heartbeats_are_per_process(self):
        # Two MCP clients at once: each keeps its own heartbeat, and one
        # exiting must not hide the other.
        control.write_mcp_state(self.tmp, {
            "schema": 1, "pid": 1, "client": {"name": "other"},
            "last_call_at": "2026-01-01T00:00:00Z"})
        control.write_mcp_state(self.tmp, {
            "schema": 1, "pid": os.getpid(), "client": {"name": "me"},
            "last_call_at": "2026-02-01T00:00:00Z"})
        self.assertEqual(control.read_mcp_state(self.tmp)["client"]["name"], "me")

        control.remove_mcp_state(self.tmp, pid=os.getpid())
        state = control.read_mcp_state(self.tmp)
        self.assertIsNotNone(state)
        self.assertEqual(state["client"]["name"], "other")
