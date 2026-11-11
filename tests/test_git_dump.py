"""The git_dump tool is registered, scoped, and refuses out-of-scope targets."""

import tempfile
import unittest
from pathlib import Path

from netcast3r.mcp.tools import ToolContext, ToolError, ToolRegistry, _TOOL_MAP, git_dump
from netcast3r.server import build_server
from netcast3r.server.agent_runtime import LocalPlane


class GitDumpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Git dump", "https://bca.example/", status="active",
            autonomy="autonomous", scope=["bca.example"])
        self.ctx = ToolContext(plane=LocalPlane(self.server), policy="full",
                               base=self.tmp, actor="agent:helix",
                               mission_id=self.mission["id"], authorized=True)

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_tool_is_registered(self):
        self.assertIn("git_dump", _TOOL_MAP)

    def test_out_of_scope_target_is_refused(self):
        with self.assertRaises(ToolError) as caught:
            git_dump(self.ctx, {
                "target": "http://127.0.0.1:9/",
                "mission_id": self.mission["id"],
            })
        self.assertIn(caught.exception.code, {"scope_denied", "not_exposed"})

    def test_registry_exposes_the_tool(self):
        registry = ToolRegistry(self.ctx)
        payload, is_error = registry.call("git_dump", {
            "target": "http://127.0.0.1:9/",
            "mission_id": self.mission["id"],
        })
        self.assertTrue(is_error)
        self.assertFalse(payload.get("ok"))


if __name__ == "__main__":
    unittest.main()
