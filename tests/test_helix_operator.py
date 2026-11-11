"""Helix as a full operator: own API calls, any tool, light chat lane."""

import json
import tempfile
import unittest
from pathlib import Path

from netcast3r import brain
from netcast3r.server import build_server


def reply(payload, provider="bai", model="deepseek-v4.1-flash"):
    return {"text": json.dumps(payload), "provider": provider, "model": model}


class HelixOperatorTests(unittest.TestCase):
    def test_plain_reply_never_leaks_model_json(self):
        self.assertEqual(brain._plain_reply('{"reply":"real answer","actions":[]}'),
                         "real answer")
        self.assertEqual(
            brain._plain_reply('```json\n{"reply":"fenced answer"}\n```'),
            "fenced answer")
        self.assertEqual(brain._plain_reply("plain answer"), "plain answer")
        self.assertEqual(brain._plain_reply('{"not_reply":"x"}'), "")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.director = self.server._director()
        self.mission = self.index.create_mission(
            "Helix operator", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])

    def tearDown(self):
        self.director.shutdown()
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_api_call_reads_the_real_plane(self):
        out = brain._apply(self.index, self.director, {
            "kind": "api_call", "method": "GET", "path": "/api/v1/meta",
            "mission_id": self.mission["id"]}, self.mission["id"])
        self.assertTrue(out["applied"], out)
        result = out["result"]
        self.assertEqual(result.get("name"), "netcast3r")

    def test_api_call_can_write_then_read(self):
        out = brain._apply(self.index, self.director, {
            "kind": "api_call", "method": "POST",
            "path": f"/api/v1/missions/{self.mission['id']}/notes",
            "body": {"kind": "note", "title": "helix note",
                     "body": "helix wrote this"},
            "mission_id": self.mission["id"]}, self.mission["id"])
        self.assertTrue(out["applied"], out)

    def test_api_call_refuses_recursion_and_external_urls(self):
        for path in ("/api/v1/brain/chat", "https://evil.example/api/v1/meta"):
            out = brain._apply(self.index, self.director, {
                "kind": "api_call", "method": "GET", "path": path,
                "mission_id": self.mission["id"]}, self.mission["id"])
            self.assertFalse(out["applied"], path)

    def test_api_call_requires_an_autonomous_mission(self):
        supervised = self.index.create_mission(
            "Supervised", "https://lab.example.com/", status="active",
            autonomy="supervised", scope=["lab.example.com"])
        out = brain._apply(self.index, self.director, {
            "kind": "api_call", "method": "GET", "path": "/api/v1/meta",
            "mission_id": supervised["id"]}, supervised["id"])
        self.assertFalse(out["applied"])
        self.assertIn("autonomous", out["reason"])

    def test_tool_call_runs_any_registered_tool(self):
        out = brain._apply(self.index, self.director, {
            "kind": "tool_call", "tool": "host_shell",
            "args": {"command": "printf helix-tool-ok"},
            "mission_id": self.mission["id"]}, self.mission["id"])
        self.assertTrue(out["applied"], out)
        self.assertIn("helix-tool-ok", json.dumps(out["result"]))

    def test_tool_call_reports_unknown_tool(self):
        out = brain._apply(self.index, self.director, {
            "kind": "tool_call", "tool": "not_a_real_tool",
            "args": {}, "mission_id": self.mission["id"]}, self.mission["id"])
        self.assertFalse(out["applied"])

    def test_chat_sessions_roundtrip_fork_and_delete(self):
        session = self.index.create_brain_session(
            "Chat", mission_id=self.mission["id"])
        self.index.add_brain_turn("operator", "hello", mission_id=self.mission["id"],
                                  session_id=session["id"])
        self.index.add_brain_turn("brain", "hi", mission_id=self.mission["id"],
                                  session_id=session["id"])
        messages = self.index.list_brain_messages(session["id"])
        self.assertEqual([row["role"] for row in messages],
                         ["operator", "brain"])
        listed = self.index.list_brain_sessions(mission_id=self.mission["id"])
        self.assertTrue(any(row["id"] == session["id"] for row in listed))

        forked = self.index.fork_brain_session(session["id"])
        self.assertIsNotNone(forked)
        self.assertEqual(len(self.index.list_brain_messages(forked["id"])), 2)

        renamed = self.index.patch_brain_session(session["id"], title="Renamed")
        self.assertEqual(renamed["title"], "Renamed")

        self.assertTrue(self.index.delete_brain_session(session["id"]))
        self.assertEqual(self.index.list_brain_messages(session["id"]), [])

    def test_session_routes_are_live(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        created = self.server.route(
            "POST", "/api/v1/brain/sessions", {}, headers,
            json.dumps({"title": "Route chat",
                        "mission_id": self.mission["id"]}).encode())
        self.assertEqual(created.status, 201)
        session = json.loads(created.body)
        listing = self.server.route(
            "GET", "/api/v1/brain/sessions", {}, headers, b"")
        self.assertEqual(listing.status, 200)
        self.assertTrue(any(row["id"] == session["id"]
                            for row in json.loads(listing.body)["items"]))
        messages = self.server.route(
            "GET", f"/api/v1/brain/sessions/{session['id']}/messages",
            {}, headers, b"")
        self.assertEqual(messages.status, 200)

    def test_simple_chat_stays_on_the_light_lane(self):
        calls = []

        def complete(messages):
            calls.append(messages)
            return {"text": "hi - standing by.", "provider": "nvidia",
                    "model": "nemotron-3.5-lightning"}

        result = brain.chat(self.server, self.index, self.director, "hello",
                            act=False, complete=complete)
        self.assertEqual(result["reply"], "hi - standing by.")
        self.assertFalse(result["reasoning"])
        self.assertEqual(result["chat_model"], "nemotron-3.5-lightning")
        self.assertEqual(result["actions"], [])
        self.assertEqual(len(calls), 1)

    def test_reasoning_chat_uses_deepseek_plan_and_light_voice(self):
        calls = []

        def complete(messages):
            calls.append(messages)
            if len(calls) == 1:
                return reply({"reply": "DeepSeek plan", "focus": "replay .git",
                              "actions": []})
            return {"text": "Plan is a .git replay; 0 confirmed.",
                    "provider": "nvidia", "model": "nemotron-light"}

        result = brain.chat(self.server, self.index, self.director,
                            "what is next on the hunt?", act=True,
                            complete=complete)
        self.assertEqual(result["reply"], "Plan is a .git replay; 0 confirmed.")
        self.assertEqual(result["provider"], "bai")
        self.assertEqual(result["model"], "deepseek-v4.1-flash")
        self.assertEqual(result["chat_model"], "nemotron-light")
        self.assertTrue(result["reasoning"])
        self.assertEqual(len(calls), 2)

        rows = self.index.list_brain_log(limit=2, mission_id=self.mission["id"])
        brain_row = next(row for row in rows if row["role"] == "brain")
        self.assertEqual(brain_row["chat_model"], "nemotron-light")


if __name__ == "__main__":
    unittest.main()
