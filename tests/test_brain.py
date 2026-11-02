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
                    "candidates", "director", "host", "mcp", "focus_mission",
                    "plane"):
            self.assertIn(key, snapshot)
        self.assertEqual(snapshot["focus_mission"]["id"], self.mission["id"])
        self.assertIn("recent_events", snapshot["focus_mission"])
        self.assertIn("tools", snapshot["host"])
        self.assertEqual(snapshot["plane"]["actually_running"], 0)
        self.assertIn("running_ids", snapshot["plane"])


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

    def test_helix_can_start_campaign_and_host_shell(self):
        def complete(messages):
            return reply({"reply": "scanning example.com", "actions": [
                {"kind": "start_campaign", "target": "lab.example.com"},
                {"kind": "host_shell", "command": "echo helix-ok"}]})

        result = brain.chat(self.server, self.index, self.director,
                            "hunt lab.example.com and echo helix-ok",
                            complete=complete)
        by_kind = {a["kind"]: a for a in result["actions"]}
        self.assertTrue(by_kind["start_campaign"]["applied"])
        self.assertTrue(by_kind["host_shell"]["applied"])
        self.assertEqual(by_kind["host_shell"].get("exit_code"), 0)
        self.assertIn("helix-ok", by_kind["host_shell"].get("stdout", ""))
        missions, _ = self.index.list_missions(limit=10)
        self.assertTrue(any("lab.example.com" in str(m.get("target") or "")
                            for m in missions))

    def test_context_does_not_claim_interrupted_scans_are_live(self):
        run = self.index.create_run("https://lab.example.com/", {"mode": "hunt"})
        self.index.update_run(run["id"], status="running")
        state = self.index.ensure_director_state()
        active = dict(state.get("active") or {})
        active["runs"] = {run["id"]: {"mission_id": self.mission["id"],
                                      "mode": "hunt", "runner": "hunt",
                                      "started": 0.0, "started_at": ""}}
        self.index.patch_director_state(active=active, engaged=1)
        self.index.update_run(run["id"], status="interrupted",
                              error="server restarted")
        snapshot = brain.context(self.index, self.director,
                                 mission_id=self.mission["id"])
        self.assertEqual(snapshot["plane"]["actually_running"], 0)
        self.assertEqual(snapshot["director"].get("in_flight"), [])
        self.assertTrue(any(r["id"] == run["id"] and r["status"] == "interrupted"
                            for r in snapshot["runs"]))

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

    def test_a_repeated_direction_is_not_queued_twice(self):
        def complete(messages):
            return reply({"reply": "same", "actions": [
                {"kind": "directive", "mission_id": self.mission["id"],
                 "body": "probe the export endpoint"}]})

        first = brain.chat(self.server, self.index, self.director, "go",
                           complete=complete)
        second = brain.chat(self.server, self.index, self.director, "go",
                            complete=complete)
        self.assertTrue(first["actions"][0]["applied"])
        self.assertFalse(second["actions"][0]["applied"])
        self.assertEqual(len(self.index.list_directions(
            self.mission["id"], status="queued")), 1)


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
        for name in ("brain_chat", "brain_context", "campaign_start",
                     "brain_journal", "brain_loop", "instruct"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)

    def test_instruct_queues_director_without_brain(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        mission = self.server.index.create_mission(
            "Instruct", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])
        body = json.dumps({
            "message": "focus staging auth, skip CDN",
            "mission_id": mission["id"],
            "target": "director",
        }).encode()
        response = self.server.route("POST", "/api/v1/instruct", {},
                                     headers, body)
        self.assertEqual(response.status, 200)
        payload = json.loads(response.body.decode())
        self.assertEqual(payload["target"], "director")
        self.assertIn("direction", payload)
        queued = self.server.index.list_directions(
            mission["id"], status="queued")
        self.assertEqual(len(queued), 1)
        self.assertIn("staging auth", queued[0]["body"])

    def test_instruct_requires_mission_for_director(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        body = json.dumps({
            "message": "pivot east",
            "target": "director",
        }).encode()
        response = self.server.route("POST", "/api/v1/instruct", {},
                                     headers, body)
        self.assertEqual(response.status, 400)


class CognitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Hunt", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        if getattr(self.server, "brain_loop", None) is not None:
            self.server.brain_loop.shutdown()
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_an_autonomous_turn_steers_and_journals(self):
        def complete(messages):
            return reply({"reply": "push the order API", "reasoning": "IDOR shape",
                          "focus": "order API IDOR",
                          "actions": [{"kind": "directive",
                                       "mission_id": self.mission["id"],
                                       "body": "test order ids @lead:hyp_2"}]})

        result = brain.cognition(self.server, self.index, self.server._director(),
                                 complete=complete)
        self.assertEqual(result["mission_id"], self.mission["id"])
        self.assertEqual(result["actions"][0]["applied"], True)
        queued = self.index.list_directions(self.mission["id"], status="queued")
        self.assertEqual(len(queued), 1)
        turns = self.index.list_brain_log(limit=10, mission_id=self.mission["id"])
        self.assertEqual(turns[0]["role"], "auto")
        self.assertIn("order API", turns[0]["text"])
        self.assertEqual(self.index.totals().get("findings", 0), 0)

    def test_a_supervised_mission_blocks_run_module(self):
        supervised = self.index.create_mission(
            "Careful", "https://lab.example.com/", status="active",
            autonomy="supervised", scope=["lab.example.com"])

        def complete(messages):
            return reply({"reply": "run the login module", "actions": [
                {"kind": "run_module", "mission_id": supervised["id"],
                 "module_id": "auth-sqli-login-bypass"}]})

        result = brain.cognition(self.server, self.index, self.server._director(),
                                 mission_id=supervised["id"], complete=complete)
        self.assertEqual(result["actions"][0]["applied"], False)
        self.assertIn("autonomous", result["actions"][0]["reason"])

    def test_the_autonomy_loop_cannot_pause_the_hunt(self):
        director = self.server._director()
        director.engage()

        def complete(messages):
            return reply({"reply": "stop everything", "actions": [
                {"kind": "pause"}]})

        result = brain.cognition(self.server, self.index, director,
                                 mission_id=self.mission["id"], complete=complete)
        self.assertEqual(result["actions"][0]["applied"], False)
        self.assertFalse(bool(director.status().get("paused")))

    def test_context_carries_traffic_logs_and_mcp(self):
        snapshot = brain.context(self.index, self.server._director(),
                                 mission_id=self.mission["id"])
        for key in ("traffic", "logs", "mcp", "mcp_servers", "training"):
            self.assertIn(key, snapshot)

    def test_a_coverage_mark_is_applied(self):
        result = brain._apply(
            self.index, self.server._director(),
            {"kind": "mark_coverage", "mission_id": self.mission["id"],
             "item_id": "wstg-authz-01", "status": "in_progress",
             "evidence": "two identities queued"}, self.mission["id"])
        self.assertTrue(result["applied"])
        rows = {row["item_id"]: row for row in
                self.index.list_coverage(self.mission["id"])}
        self.assertEqual(rows["wstg-authz-01"]["status"], "in_progress")

    def test_a_lesson_is_written(self):
        result = brain._apply(
            self.index, self.server._director(),
            {"kind": "record_lesson",
             "title": "OAuth state is not bound to the session",
             "lesson": "The callback accepted a state minted for another session, "
                       "so the login CSRF path reached an account-swap.",
             "technique": "oauth", "outcome": "success"},
            self.mission["id"])
        self.assertTrue(result["applied"])
        lesson = self.index.get_lesson(result["lesson_id"])
        self.assertIn("OAuth", lesson["title"])
        self.assertEqual(lesson["source"], "agent:brain")

    def test_an_unknown_lab_is_refused(self):
        result = brain._apply(
            self.index, self.server._director(),
            {"kind": "run_lab", "slug": "definitely-not-a-lab"},
            self.mission["id"])
        self.assertFalse(result["applied"])

    def test_an_unknown_module_is_refused_before_a_run_starts(self):
        result = brain._apply(
            self.index, self.server._director(),
            {"kind": "run_module", "mission_id": self.mission["id"],
             "module_id": "not-a-real-module"},
            self.mission["id"])
        self.assertFalse(result["applied"])
        self.assertIn("unknown module", result["reason"])

    def test_an_unknown_lab_solve_is_refused(self):
        result = brain._apply(
            self.index, self.server._director(),
            {"kind": "solve_lab", "slug": "no-such-lab"},
            self.mission["id"])
        self.assertFalse(result["applied"])
        self.assertIn("unknown lab", result["reason"])

    def test_a_hard_failed_provider_is_rested(self):
        brain._PROVIDER_FAILS.clear()
        try:
            brain._ask(self.server, self.index, [],
                       complete=lambda m: {"text": "", "provider": "tokenharbor",
                                           "error": "tokenharbor returned 402"})
            self.assertIn("tokenharbor", brain._excluded_providers())
        finally:
            brain._PROVIDER_FAILS.clear()

    def test_focus_prefers_an_autonomous_mission(self):
        self.index.create_mission("Supervised", "https://a.example.com/",
                                  status="active", autonomy="supervised",
                                  scope=["a.example.com"])
        self.assertEqual(brain.focus_mission_id(self.index), self.mission["id"])

    def test_focus_keeps_labs_out_of_the_top_slot(self):
        self.index.create_mission(
            "Real", "https://app.example.org/", status="active",
            autonomy="supervised", scope=["app.example.org"])
        lab = self.index.create_mission(
            "Lab", "http://127.0.0.1:3000/", status="active",
            autonomy="autonomous", scope=["127.0.0.1"])
        chosen = brain.focus_mission_id(self.index)
        self.assertNotEqual(chosen, lab["id"])
        mission = self.index.get_mission(chosen) or {}
        self.assertFalse(brain._is_local_target(mission.get("target")))

    def test_chat_journals_both_turns(self):
        def complete(messages):
            return reply({"reply": "on it", "focus": "surface map",
                          "actions": []})

        brain.chat(self.server, self.index, self.server._director(), "status?",
                   complete=complete)
        roles = [t["role"] for t in
                 self.index.list_brain_log(limit=10, mission_id=self.mission["id"])]
        self.assertIn("operator", roles)
        self.assertIn("brain", roles)

    def test_chat_records_who_sent_it(self):
        def complete(messages):
            return reply({"reply": "ack", "actions": []})

        brain.chat(self.server, self.index, self.server._director(), "hello",
                   complete=complete, source="mcp")
        rows = self.index.list_brain_log(limit=2, mission_id=self.mission["id"])
        self.assertTrue(all(row["source"] == "mcp" for row in rows))

    def test_journal_and_loop_routes(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        journal = self.server.route("GET", "/api/v1/brain/journal", {}, headers, b"")
        self.assertEqual(journal.status, 200)
        payload = json.loads(journal.body.decode())
        self.assertIn("items", payload)
        self.assertIn("running", payload["loop"])
        paused = self.server.route(
            "POST", "/api/v1/brain/loop", {}, headers,
            json.dumps({"action": "pause"}).encode())
        self.assertEqual(paused.status, 200)
        self.assertTrue(json.loads(paused.body.decode())["paused"])


class BrainLoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Hunt", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.brain_loop = None
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_tick_thinks_and_journals(self):
        loop = brain.BrainLoop(self.server, interval=45, complete=lambda m: reply(
            {"reply": "pivot to the admin API", "focus": "admin API",
             "actions": [{"kind": "directive", "mission_id": self.mission["id"],
                          "body": "probe /api/admin as a reader"}]}))
        result = loop.tick()
        self.assertEqual(result["mission_id"], self.mission["id"])
        self.assertEqual(loop.status()["turns"], 1)
        self.assertIn("admin API", loop.status()["last_focus"])
        log = self.index.list_brain_log(limit=5, mission_id=self.mission["id"])
        self.assertEqual(log[0]["role"], "auto")

    def test_a_turn_with_no_model_answer_is_retried_not_journaled(self):
        loop = brain.BrainLoop(
            self.server, interval=45,
            complete=lambda m: {"text": "", "error": "rate_limit_exceeded"})
        result = loop.tick()
        self.assertEqual(result.get("reply"), "")
        status = loop.status()
        self.assertEqual(status["turns"], 0)
        self.assertEqual(status["errors"], 1)
        self.assertIn("rate_limit", status["last_error"])
        self.assertEqual(self.index.list_brain_log(limit=5), [])

    def test_start_prunes_empty_auto_turns(self):
        self.index.add_brain_turn("auto", "", mission_id=self.mission["id"])
        self.index.add_brain_turn("auto", "real turn",
                                  mission_id=self.mission["id"])
        self.assertEqual(self.index.prune_brain_log(), 1)
        rows = self.index.list_brain_log(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["text"], "real turn")

    def test_pause_and_engage_persist(self):
        loop = brain.BrainLoop(self.server, interval=45, complete=lambda m: reply(
            {"reply": "x", "actions": []}))
        self.assertFalse(loop.status()["paused"])
        loop.pause()
        self.assertTrue(loop.status()["paused"])
        # A fresh loop object reads the persisted state.
        self.assertTrue(brain.BrainLoop(self.server).status()["paused"])
        loop.engage()
        self.assertFalse(loop.status()["paused"])

    def test_tick_without_a_mission_is_skipped(self):
        empty = Path(tempfile.mkdtemp())
        server = build_server(results_dir=str(empty / "results"), base=empty,
                              recover=False)
        try:
            loop = brain.BrainLoop(server, complete=lambda m: reply({"reply": "x"}))
            self.assertIn("skipped", loop.tick())
        finally:
            server.index.close()
            server.jobs.shutdown(wait=False)


if __name__ == "__main__":
    unittest.main()
