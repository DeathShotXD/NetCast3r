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
                    "plane", "mesh_chat", "model_traffic", "helix_journal",
                    "logs"):
            self.assertIn(key, snapshot)
        self.assertEqual(snapshot["focus_mission"]["id"], self.mission["id"])
        self.assertIn("recent_events", snapshot["focus_mission"])
        self.assertIn("tools", snapshot["host"])
        self.assertEqual(snapshot["plane"]["actually_running"], 0)
        self.assertIn("running_ids", snapshot["plane"])

    def test_live_feed_merges_channels(self):
        self.index.add_brain_turn("auto", "watching the plane",
                                  mission_id=self.mission["id"],
                                  provider="fake", model="free")
        self.index.add_director_log("control", "engaged",
                                    mission_id=self.mission["id"])
        task = self.index.create_agent_task(
            self.mission["id"], seq=1, kind="analysis", title="probe auth",
            tool="model")
        self.index.patch_agent_task(
            task["id"], status="verified",
            result={"advisory": "session cookie looks forgeable",
                    "provider": "fake", "model": "free", "agent": "auth"})
        feed = brain.live_feed(self.index, self.server._director(),
                               mission_id=self.mission["id"], limit=40)
        for key in ("items", "logs", "mesh", "model_calls", "thoughts",
                    "timeline", "loop"):
            self.assertIn(key, feed)
        channels = {row["channel"] for row in feed["timeline"]}
        self.assertIn("journal", channels)
        self.assertIn("log", channels)
        self.assertIn("mesh", channels)
        self.assertTrue(any("forgeable" in (row.get("text") or "")
                            for row in feed["mesh"]))


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

    def test_chat_answers_from_the_ledger_when_every_model_fails(self):
        self.index.create_hypothesis(
            "Reset token leaks in the referer",
            target="https://lab.example.com/reset",
            mission_id=self.mission["id"], technique="ato")

        def complete(messages):
            return {"text": "", "provider": "th-hunt-3",
                    "error": "th-hunt-3 returned 429", "failed": []}

        result = brain.chat(self.server, self.index, self.director,
                            "What are the current leads?", complete=complete)
        self.assertIn("cooling down", result["reply"])
        self.assertIn("Open leads", result["reply"])
        self.assertIn("Reset token leaks in the referer", result["reply"])
        self.assertEqual(result["actions"], [])

    def test_obvious_operator_commands_apply_when_models_fail(self):
        self.director.engage()

        def complete(messages):
            return {"text": "", "provider": "th-hunt-3",
                    "error": "th-hunt-3 returned 429", "failed": []}

        result = brain.chat(self.server, self.index, self.director, "pause",
                            complete=complete)
        self.assertTrue(any(row.get("kind") == "pause" and row.get("applied")
                            for row in result["actions"]))
        self.assertIn("Director paused", result["reply"])

    def test_a_truncated_json_reply_is_salvaged(self):
        def complete(messages):
            return {"text": ('{"reply": "Replaying the blocked proof on the '
                             'right host", "reasoning": "the model hit the token '
                             'cap before closing the object'),
                    "provider": "nvidia", "model": "m"}

        result = brain.chat(self.server, self.index, self.director, "status",
                            complete=complete)
        self.assertEqual(result["reply"],
                         "Replaying the blocked proof on the right host")
        self.assertNotIn('"reply"', result["reply"])

    def test_helix_can_start_campaign_and_host_shell_with_approval(self):
        from netcast3r.mcp.tools import args_digest

        mission = self.index.create_mission(
            "Host work", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])
        approval = self.index.create_approval(
            mission["id"], "host shell proof", risk="high",
            payload={"tool": "host_shell",
                     "args_digest": args_digest("host_shell",
                                                {"command": "echo helix-ok"})})
        self.index.decide_approval(approval["id"], "approved",
                                   decided_by="operator")

        def complete(messages):
            return reply({"reply": "scanning example.com", "actions": [
                {"kind": "start_campaign", "target": "lab.example.com"},
                {"kind": "host_shell", "command": "echo helix-ok",
                 "mission_id": mission["id"], "approval_id": approval["id"]}]})

        result = brain.chat(self.server, self.index, self.director,
                            "hunt lab.example.com and echo helix-ok",
                            mission_id=mission["id"], complete=complete)
        by_kind = {a["kind"]: a for a in result["actions"]}
        self.assertTrue(by_kind["start_campaign"]["applied"])
        self.assertTrue(by_kind["host_shell"]["applied"], by_kind["host_shell"])
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
        self.assertEqual(payload["priority"]["mission_id"], mission["id"])
        self.assertIs(
            self.server.index.get_setting("training_paused_for_priority"), True)

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

    def test_a_quiet_model_reports_hunt_progress_without_repeating(self):
        run = self.index.create_run(
            "https://lab.example.com/", {"mode": "hunt"})
        self.index.add_mission_run(self.mission["id"], run["id"])
        self.index.update_run(run["id"], status="done", counts_json={
            "target": "https://lab.example.com/", "pages": 12, "leads": 3})
        self.index.create_hypothesis(
            "order idor", target="https://lab.example.com/api/orders/7",
            mission_id=self.mission["id"], technique="idor",
            rationale="object id", expected="other user data")
        brain.set_operator_priority(self.index, self.mission["id"])

        def quiet(messages):
            return {"text": "", "provider": "fake", "model": "free"}

        first = brain.cognition(
            self.server, self.index, self.server._director(), complete=quiet)
        self.assertTrue("Hunting" in first["reply"] or "Pass on" in first["reply"])
        self.assertNotIn("Models were quiet", first["reply"])
        self.assertIn("lab.example.com", first["reply"])
        before = len(self.index.list_brain_log(
            limit=50, mission_id=self.mission["id"]))
        second = brain.cognition(
            self.server, self.index, self.server._director(),
            complete=quiet, previous=first)
        after = len(self.index.list_brain_log(
            limit=50, mission_id=self.mission["id"]))
        self.assertEqual(second["reply"], first["reply"])
        self.assertEqual(after, before)

    def test_a_supported_file_read_points_the_next_run_at_chain_run(self):
        lead = self.index.create_hypothesis(
            "file read", target="https://lab.example.com/download?file=x",
            mission_id=self.mission["id"], technique="path-traversal",
            rationale="file parameter", expected="config")
        self.index.patch_hypothesis(
            lead["id"], status="supported",
            test={"steps": [{"url": "https://lab.example.com/download?file=x"}]},
            result={"ok": True})
        directive = brain.critical_ready_directive(
            self.index, self.mission["id"])
        self.assertIsNotNone(directive)
        self.assertIn("chain_run", directive["body"])

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

    def test_a_soft_429_does_not_park_the_provider(self):
        brain._PROVIDER_FAILS.clear()
        try:
            text, provider, _model, error = brain._ask(
                self.server, self.index, [],
                complete=lambda m: {"text": "", "provider": "th-hunt-1",
                                    "error": "th-hunt-1 returned 429",
                                    "failed": ["th-hunt-1", "th-hunt-2"]})
            self.assertEqual(text, "")
            self.assertEqual(provider, "th-hunt-1")
            self.assertIn("429", error)
            self.assertEqual(brain._excluded_providers(), set())
        finally:
            brain._PROVIDER_FAILS.clear()

    def test_priority_lock_refuses_labs_and_steers_critical_ready(self):
        lead = self.index.create_hypothesis(
            "ATO via reset host", target="https://lab.example.com/reset",
            mission_id=self.mission["id"],
            expected="a reset token minted for another account")
        self.index.patch_hypothesis(lead["id"], status="supported")
        brain.set_operator_priority(
            self.index, self.mission["id"], reason="operator lock")

        def complete(messages):
            return reply({"reply": "", "actions": [
                {"kind": "run_lab", "slug": "auto"},
                {"kind": "solve_lab", "slug": "auto"}]})

        brain._PROVIDER_FAILS.clear()
        try:
            result = brain.cognition(
                self.server, self.index, self.server._director(),
                mission_id=self.mission["id"], complete=complete)
        finally:
            brain._PROVIDER_FAILS.clear()
        kinds = [row.get("kind") for row in result["actions"]]
        self.assertIn("run_lab", kinds)
        self.assertIn("solve_lab", kinds)
        self.assertTrue(all(not row.get("applied")
                            for row in result["actions"]
                            if row.get("kind") in {"run_lab", "solve_lab"}))
        queued = self.index.list_directions(self.mission["id"], status="queued")
        self.assertEqual(len(queued), 1)
        self.assertIn("ATO via reset host", queued[0]["body"])
        self.assertIn("Critical-ready", queued[0]["body"])
        self.assertEqual(self.index.totals().get("findings", 0), 0)

    def test_brain_system_locks_priority_and_stale_unreachable_lessons(self):
        text = brain.BRAIN_SYSTEM
        self.assertIn("operator_priority.mission_id", text)
        self.assertIn("exclusive", text)
        self.assertIn("unreachable", text)
        self.assertIn("Contradict that lesson", text)

    def test_priority_lock_pauses_training_until_cleared(self):
        locked = brain.set_operator_priority(
            self.index, self.mission["id"], reason="operator lock")
        self.assertEqual(locked["mission_id"], self.mission["id"])
        self.assertIs(self.index.get_setting("training_paused_for_priority"), True)
        self.assertTrue(brain.training_paused_for_priority(self.index))
        applied = brain._apply(
            self.index, None, {"kind": "clear_priority"}, self.mission["id"])
        self.assertTrue(applied["applied"])
        self.assertIs(self.index.get_setting("training_paused_for_priority"), False)
        self.assertFalse(brain.training_paused_for_priority(self.index))
        self.assertEqual(brain.operator_priority(self.index), {})

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
        # A steward hail may journal a newer helix row; the cognition turn is auto.
        self.assertTrue(any(row.get("role") == "auto" for row in log))

    def test_a_turn_with_no_model_answer_is_retried_not_journaled(self):
        loop = brain.BrainLoop(
            self.server, interval=45,
            complete=lambda m: {"text": "", "error": "rate_limit_exceeded"})
        result = loop.tick()
        status = loop.status()
        # A quiet model no longer leaves the tick empty: the deterministic
        # fallback journals a progress line and a critical-ready directive.
        self.assertTrue(result.get("reply"))
        self.assertTrue(self.index.list_brain_log(limit=5))
        self.assertTrue(status.get("last_error") or status.get("turns"))

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

    def test_snapshot_and_live_feed_surface_contradicted_lessons(self):
        dead = self.index.add_lesson(
            "http_probe: failure",
            "http_probe returned error: ConnectError on lab.example.com",
            technique="http_probe",
            context="lab.example.com",
            outcome="failure",
            mission_id=self.mission["id"],
        )
        self.assertTrue(dead["provisional"])
        self.assertIn("provisional=true", dead["tags"])
        self.index.add_tool_call(
            "http_probe", status="ok", mission_id=self.mission["id"],
            args={"target": "https://lab.example.com/"},
            result={"status": 200, "url": "https://lab.example.com/"},
        )
        snapshot = brain.context(
            self.index, self.server._director(), mission_id=self.mission["id"])
        self.assertGreaterEqual(snapshot["learning"]["contradicted_unreachable"], 1)
        self.assertTrue(any(item["id"] == dead["id"]
                            for item in snapshot["contradicted_lessons"]))
        feed = brain.live_feed(
            self.index, self.server._director(), mission_id=self.mission["id"])
        self.assertGreaterEqual(feed["learning"]["contradicted_unreachable"], 1)
        self.assertTrue(any(item["id"] == dead["id"]
                            for item in feed["contradicted_lessons"]))


if __name__ == "__main__":
    unittest.main()
