"""Typed chain workflow and JWT forging."""

import base64
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from netcast3r import authstore, chain_workflow
from netcast3r.mcp.tools import ToolContext, ToolRegistry
from netcast3r.server import build_server
from netcast3r.server.agent_runtime import LocalPlane


class ChainWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Chain", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_jwt_forge_signs_the_claims(self):
        ctx = ToolContext(plane=LocalPlane(self.server), policy="full",
                          base=self.tmp, actor="agent:test",
                          mission_id=self.mission["id"], authorized=True)
        payload, is_error = ToolRegistry(ctx).call(
            "jwt_forge", {"key": "test-key",
                          "claims": {"user_id": 7}, "algorithm": "HS256"})
        self.assertFalse(is_error, payload)
        token = payload["token"]
        head, body, signature = token.split(".")
        decoded = json.loads(base64.urlsafe_b64decode(
            body + "=" * (-len(body) % 4)))
        self.assertEqual(decoded["user_id"], 7)
        expected = base64.urlsafe_b64encode(hmac.new(
            b"test-key", f"{head}.{body}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        self.assertEqual(signature.rstrip("="), expected.rstrip("="))

    def test_chain_binds_tool_output_into_an_auth_profile(self):
        steps = [
            {"kind": "tool", "tool": "jwt_forge",
             "args": {"key": "chain-key", "claims": {"user_id": 9}}},
            {"kind": "extract", "from": "last.token", "regex": "^(.+)$",
             "name": "token", "secret": True},
            {"kind": "auth_profile", "name": "chain-test",
             "headers": {"Authorization": "{{token}}"}},
            {"kind": "assert", "var": "token"},
        ]
        result = chain_workflow.execute(self.server, self.mission["id"], steps)
        self.assertEqual(result["status"], "ok", result)
        self.assertIn("token", result["vars"])
        self.assertNotIn("chain-key", result["vars"]["token"])
        profile = authstore.get_profile("chain-test", base=self.tmp)
        self.assertTrue(profile)
        stored = profile.headers.get("Authorization", "")
        self.assertEqual(stored.count("."), 2, stored)
        self.assertNotEqual(stored, "last.token")

    def test_dry_run_does_not_execute(self):
        result = chain_workflow.execute(
            self.server, self.mission["id"],
            [{"kind": "tool", "tool": "jwt_forge",
              "args": {"key": "{{key}}", "claims": {"user_id": 1}}}],
            dry_run=True, variables={"key": "abc"})
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["steps"][0]["planned"]["key"] == "abc")

    def test_templates_are_listed(self):
        names = {item["name"] for item in chain_workflow.list_templates()}
        self.assertIn("jwt-forge-to-auth-profile", names)
        self.assertIn("git-to-source-audit", names)


if __name__ == "__main__":
    unittest.main()
