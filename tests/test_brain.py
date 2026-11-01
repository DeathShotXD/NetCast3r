import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import brain
from netcast3r.server import build_server


def reply(payload):
    return {"text": json.dumps(payload), "provider": "fake", "model": "free"}


class BrainContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Hunt", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])

    def tearDown(self):
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_context_has_the_whole_plane(self):
        snapshot = brain.context(self.index, self.server._director(),
                                 mission_id=self.mission["id"])
        for key in ("missions", "runs", "tool_calls", "knowledge", "open_leads",
                    "candidates", "director", "host", "mcp", "focus_mission"):
            self.assertIn(key, snapshot)
        self.assertEqual(snapshot["focus_mission"]["id"], self.mission["id"])
        self.assertIn("tools", snapshot["host"])


class BrainChatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Hunt", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])
        self.director = self.server._director()

    def tearDown(self):
        self.director.shutdown()
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_a_directive_is_queued(self):
        def complete(messages):
            return reply({"reply": "try the order API", "focus": "IDOR",
                          "actions": [{"kind": "directive",
                                       "mission_id": self.mission["id"],
                                       "body": "test @lead:hyp_1 on the order API"}]})

        result = brain.chat(self.server, self.index, self.director, "what next?",
                            complete=complete)
        self.assertIn("order API", result["reply"])
        self.assertEqual(result["actions"][0]["applied"], True)
        queued = self.index.list_directions(self.mission["id"], status="queued")
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["mentions"][0]["id"], "hyp_1")

    def test_engage_pause_and_unknown_actions(self):
        def complete(messages):
            return reply({"reply": "ok", "actions": [
                {"kind": "pause"}, {"kind": "teleport"}]})

        result = brain.chat(self.server, self.index, self.director, "pause it",
                            complete=complete)
        kinds = {a["kind"]: a["applied"] for a in result["actions"]}
        self.assertTrue(kinds.get("pause"))
        self.assertFalse(kinds.get("teleport", True))

    def test_the_brain_creates_no_finding(self):
        def complete(messages):
            return reply({"reply": "done", "actions": [
                {"kind": "directive", "mission_id": self.mission["id"],
                 "body": "look at /admin"}]})

        brain.chat(self.server, self.index, self.director, "go", complete=complete)
        self.assertEqual(self.index.totals().get("findings", 0), 0)

    def test_act_false_does_not_apply(self):
        def complete(messages):
            return reply({"reply": "planned", "actions": [
                {"kind": "pause"}]})

        result = brain.chat(self.server, self.index, self.director, "plan",
                            complete=complete, act=False)
        self.assertEqual(result["actions"], [])


class CampaignStartTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_only_a_domain_is_required(self):
        result = brain.start_campaign(self.server, self.server.index,
                                      "lab.example.com")
        mission = result["mission"]
        self.assertEqual(mission["autonomy"], "autonomous")
        self.assertEqual(mission["status"], "active")
        self.assertEqual(mission["target"], "https://lab.example.com")
        self.assertIn("lab.example.com", mission["scope"])
        self.assertTrue(result["director"]["engaged"])
        self.assertEqual(self.server.index.totals().get("findings", 0), 0)

    def test_a_blank_target_is_refused(self):
        with self.assertRaises(ValueError):
            brain.start_campaign(self.server, self.server.index, "   ")

    def test_routes(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        body = json.dumps({"target": "lab.example.com"}).encode()
        response = self.server.route("POST", "/api/v1/campaigns", {}, headers, body)
        self.assertEqual(response.status, 200)
        payload = json.loads(response.body.decode())
        self.assertIn("mission", payload)
        context = self.server.route("GET", "/api/v1/brain/context", {},
                                    headers, b"")
        self.assertEqual(context.status, 200)
        self.assertIn("missions", json.loads(context.body.decode()))

    def test_the_brain_and_campaign_tools_are_catalogued(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        names = [tool["name"] for tool in catalog()]
        for name in ("brain_chat", "brain_context", "campaign_start"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)


if __name__ == "__main__":
    unittest.main()
