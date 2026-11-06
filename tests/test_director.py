import json
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server import build_server
from netcast3r.server.director import Director


class FakeHunts:
    def __init__(self, server):
        self.server = server
        self.started = []
        self.cancelled = []

    def start(self, mission_id):
        run = self.server.index.create_run(
            "http://127.0.0.1:9/", {"mode": "hunt", "mission_id": mission_id})
        self.server.index.add_mission_run(mission_id, run["id"])
        self.started.append(run["id"])
        return run

    def cancel(self, run_id):
        self.cancelled.append(run_id)
        return True


class FakeSolvers(FakeHunts):
    def start(self, mission_id, options=None):
        run = self.server.index.create_run(
            "http://127.0.0.1:9/",
            {"mode": (options or {}).get("mode", "autopilot"),
             "mission_id": mission_id, "goal": (options or {}).get("goal", "")})
        self.server.index.add_mission_run(mission_id, run["id"])
        self.started.append(run["id"])
        self.options = dict(options or {})
        return run


class DirectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.hunts = FakeHunts(self.server)
        self.solvers = FakeSolvers(self.server)
        self.server._hunts = lambda: self.hunts
        self.server._solvers = lambda: self.solvers
        self.director = Director(self.server)
        self.director.tick_seconds = 5

    def tearDown(self):
        self.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def mission(self, title="Auto", autonomy="autonomous", status="active"):
        return self.server.index.create_mission(
            title, "http://127.0.0.1:9/", status=status, autonomy=autonomy,
            scope=["127.0.0.1"])

    def clear_cooldowns(self):
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        for entry in (active.get("missions") or {}).values():
            entry["last_started"] = 0
        self.server.index.patch_director_state(active=active)

    def complete_run(self, run_id, counts=None):
        self.server.index.update_run(run_id, status="done",
                                     counts_json=counts or {"actions": 1})

    # -- eligibility -------------------------------------------------------
    def test_scope_filter_gates_supervised_and_manual(self):
        auto = self.mission("auto", autonomy="autonomous")
        supervised = self.mission("sup", autonomy="supervised")
        manual = self.mission("man", autonomy="manual")
        rows = {row["mission_id"]: row for row in self.director.eligibility()}
        self.assertTrue(rows[auto["id"]]["eligible"])
        self.assertFalse(rows[supervised["id"]]["eligible"])
        self.assertFalse(rows[manual["id"]]["eligible"])
        self.assertIn("scope filter", rows[supervised["id"]]["reason"])
        self.director.tune(scope_filter="all")
        rows = {row["mission_id"]: row for row in self.director.eligibility()}
        self.assertTrue(rows[supervised["id"]]["eligible"])
        self.assertFalse(rows[manual["id"]]["eligible"])
        self.assertIn("manual", rows[manual["id"]]["reason"])

    def test_a_training_mission_is_never_driven(self):
        self.server.index.create_mission(
            "Lab", "https://portswigger.net/", status="active",
            autonomy="autonomous")
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "idle")
        self.assertEqual(self.hunts.started, [])

    # -- tick --------------------------------------------------------------
    def test_a_tick_starts_exactly_one_run_and_respects_concurrency(self):
        mission = self.mission("one")
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["mode"], "hunt")
        self.assertEqual(len(self.hunts.started), 1)
        # Second tick: a run is in flight and max_concurrent is 1.
        again = self.director._tick(force=True)
        self.assertEqual(again["action"], "wait")
        self.assertEqual(len(self.hunts.started), 1)
        self.assertTrue(mission["id"])

    def test_the_director_hands_a_prime_objective_and_policy_to_the_brain(self):
        mission = self.mission("two")
        # A first hunt run makes the mission mature past the hunt stage.
        first = self.director._tick(force=True)
        self.complete_run(first["run_id"])
        self.director._tick(force=True)  # reap
        self.clear_cooldowns()
        self.server.index.create_hypothesis(
            "Test the lead", target="http://127.0.0.1:9/",
            mission_id=mission["id"])
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["mode"], "swarm")
        self.assertEqual(decision["policy"], "full")  # autonomous
        self.assertTrue(self.solvers.options.get("goal"))

    def test_a_supervised_mission_runs_with_the_supervised_policy(self):
        self.director.tune(scope_filter="all")
        self.mission("sup", autonomy="supervised")
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["policy"], "supervised")

    def test_a_paused_director_does_nothing(self):
        self.mission("paused-run")
        self.director.pause()
        decision = self.director._tick()
        self.assertEqual(decision["action"], "idle")
        self.assertEqual(decision["reason"], "paused")
        self.assertEqual(self.hunts.started, [])

    # -- progress and continuous hunt -------------------------------------
    def test_stall_deepens_instead_of_parking(self):
        mission = self.mission("stuck")
        for _ in range(3):
            decision = self.director._tick(force=True)
            if decision["action"] == "start":
                self.complete_run(decision["run_id"], counts={"actions": 0})
            self.director._tick(force=True)  # reap
            self.clear_cooldowns()
        rows = {row["mission_id"]: row for row in self.director.eligibility()}
        self.assertFalse(rows[mission["id"]]["parked"])
        queued = self.server.index.list_directions(
            mission["id"], status="queued")
        self.assertTrue(any("Deepen continuous hunt" in str(d.get("body") or "")
                            for d in queued))
        # Continuous hunt: the mission stays eligible after a stall.
        nxt = self.director._tick(force=True)
        self.assertEqual(nxt["action"], "start")
        self.assertEqual(nxt["mission_id"], mission["id"])

    def test_deepen_direction_forces_raw_capture(self):
        mission = self.mission("deepen-raw")
        self.director._queue_deepen(mission["id"], {})
        queued = self.server.index.list_directions(mission["id"], status="queued")
        body = next(str(d.get("body") or "") for d in queued
                    if "Deepen continuous hunt" in str(d.get("body") or ""))
        self.assertIn("raw request", body.lower())

    def test_spa_shell_signal_steers_deepen_to_the_js_bundle(self):
        mission = self.mission("deepen-spa")
        self.server.index.add_agent_note(
            mission["id"], "hunt.map", "Surface map",
            json.dumps({"seed_host": "apply.example.gov", "spa_shell": True,
                        "shell_bytes": 531}))
        detected, size = self.director._spa_shell_signal(mission["id"])
        self.assertTrue(detected)
        self.assertEqual(size, 531)
        self.director._queue_deepen(mission["id"], {})
        queued = self.server.index.list_directions(mission["id"], status="queued")
        body = next(str(d.get("body") or "") for d in queued
                    if "Deepen continuous hunt" in str(d.get("body") or ""))
        self.assertIn("JS bundle", body)
        self.assertIn("531", body)

    def test_legacy_parks_are_cleared_on_tick(self):
        mission = self.mission("was-parked")
        state = self.server.index.ensure_director_state()
        active = dict(state.get("active") or {})
        missions = dict(active.get("missions") or {})
        missions[mission["id"]] = {
            "parked": True, "parked_at": time.time(), "no_progress": 9}
        active["missions"] = missions
        self.server.index.patch_director_state(active=active)
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        rows = {row["mission_id"]: row for row in self.director.eligibility()}
        self.assertFalse(rows[mission["id"]]["parked"])

    def test_the_scope_filter_is_enforced_at_selection(self):
        auto = self.mission("auto", autonomy="autonomous")
        sup = self.mission("sup", autonomy="supervised")
        # Make the supervised mission rank highest in Prime: give it findings.
        run = self.server.index.create_run("http://127.0.0.1:9/", {"mode": "hunt"})
        self.server.index.add_mission_run(sup["id"], run["id"])
        self.server.index.add_findings(run["id"], [
            {"title": "loud", "severity": "critical", "source": "run"}])
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["mission_id"], auto["id"])
        self.assertEqual(len(self.hunts.started), 1)

    def test_tune_updates_the_running_loop(self):
        self.director.tune(tick_seconds=20, max_concurrent=3)
        self.assertEqual(self.director.tick_seconds, 20)
        self.assertEqual(self.director.max_concurrent, 3)

    def test_start_reads_persisted_tuning(self):
        self.director.tune(tick_seconds=25, max_concurrent=2)
        reborn = Director(self.server)
        self.assertEqual(reborn.tick_seconds, 10)  # constructor default
        reborn.start()
        try:
            self.assertEqual(reborn.tick_seconds, 25)
            self.assertEqual(reborn.max_concurrent, 2)
        finally:
            reborn.shutdown()

    def test_a_mission_that_moves_is_not_parked(self):
        mission = self.mission("moving")
        first = self.director._tick(force=True)
        self.complete_run(first["run_id"], counts={"actions": 3})
        self.server.index.add_agent_note(mission["id"], "note", "moved", "progress")
        self.director._tick(force=True)
        rows = {row["mission_id"]: row for row in self.director.eligibility()}
        self.assertFalse(rows[mission["id"]]["parked"])
        self.assertEqual(rows[mission["id"]]["no_progress"], 0)

    # -- kill switch and durability ---------------------------------------
    def test_kill_cancels_in_flight_and_disengages(self):
        self.mission("killme")
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        state = self.director.kill(all_runs=True, reason="test")
        self.assertEqual(self.hunts.cancelled, [decision["run_id"]])
        self.assertFalse(state["engaged"])
        self.assertTrue(state["paused"])
        self.assertEqual(state["in_flight"], [])
        after = self.director._tick()
        self.assertEqual(after["action"], "idle")

    def test_reconcile_drops_interrupted_ghost_runs(self):
        """After a restart, recover marks runs interrupted; director must not
        still claim they are in flight when Helix asks for status."""
        self.mission("ghost")
        decision = self.director._tick(force=True)
        run_id = decision["run_id"]
        self.assertEqual(len(self.director.status()["in_flight"]), 1)
        self.server.index.update_run(run_id, status="interrupted",
                                     finished_at="2026-01-01T00:00:00Z",
                                     error="server restarted")
        status = self.director.status()
        self.assertEqual(status["in_flight"], [])
        state = self.server.index.ensure_director_state()
        self.assertNotIn(run_id, (state.get("active") or {}).get("runs") or {})

    def test_director_state_is_durable_across_instances(self):
        self.mission("durable")
        self.director._tick(force=True)
        self.director.tune(max_concurrent=2, scope_filter="all")
        reborn = Director(self.server)
        try:
            status = reborn.status()
            self.assertGreaterEqual(status["runs_started"], 1)
            self.assertEqual(status["max_concurrent"], 2)
            self.assertEqual(status["scope_filter"], "all")
        finally:
            reborn.shutdown()

    def test_the_director_creates_no_finding(self):
        self.mission("clean")
        self.director._tick(force=True)
        self.assertEqual(self.server.index.totals().get("findings", 0), 0)

    def test_model_failures_downgrade_a_model_only_brain_to_hunt(self):
        mission = self.mission("gated")
        prior = self.server.index.create_run("http://127.0.0.1:9/", {"mode": "hunt"})
        self.server.index.add_mission_run(mission["id"], prior["id"])
        self.server.index.update_run(prior["id"], status="done", counts_json={"actions": 1})
        for _ in range(8):
            self.server.index.add_director_log(
                "brain-wait", "no model answered: ConnectError")
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["requested_mode"], "autopilot")
        self.assertEqual(decision["mode"], "hunt")
        self.assertIn("model gate", decision["model_gate"])

    def test_the_gate_uses_the_newest_failure_regardless_of_log_order(self):
        # A success between two failure bursts must not keep the gate open.
        now = time.time()

        def at(ago: int) -> str:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - ago))

        rows = [{"ts": at(500), "kind": "brain-wait", "data": {},
                 "message": "no model answered: ConnectError", "run_id": "",
                 "mission_id": ""},
                {"ts": at(300), "kind": "brain", "data": {"model": "m"},
                 "message": "", "run_id": "", "mission_id": ""}]
        rows.extend({"ts": at(200 - index), "kind": "brain-wait", "data": {},
                     "message": "no model answered: ConnectError", "run_id": "",
                     "mission_id": ""} for index in range(8))
        # Ascending in time, which the previous max() selection mishandled.
        self.server.index.list_director_log = lambda limit=250: list(rows)
        health = self.director._model_health()
        self.assertFalse(health["available"])
        self.assertGreaterEqual(health["hard_failures"], 8)

    def test_free_tier_429s_do_not_close_the_moe_gate(self):
        mission = self.mission("soft")
        prior = self.server.index.create_run("http://127.0.0.1:9/", {"mode": "hunt"})
        self.server.index.add_mission_run(mission["id"], prior["id"])
        self.server.index.update_run(prior["id"], status="done", counts_json={"actions": 1})
        for _ in range(12):
            self.server.index.add_director_log(
                "brain-wait", "no model answered: th-hunt-3 returned 429")
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["mode"], "autopilot")
        self.assertFalse(decision.get("model_gate"))
        health = self.director._model_health()
        self.assertTrue(health["available"])
        self.assertGreaterEqual(health.get("soft_failures", 0), 8)

    def test_zero_progress_priority_escalates_without_idling(self):
        from netcast3r import brain as brain_module

        mission = self.mission("priority-lock")
        other = self.mission("other-work")
        brain_module.set_operator_priority(
            self.server.index, mission["id"], reason="operator lock")
        for _ in range(12):
            self.server.index.add_director_log(
                "brain-wait", "no model answered: th-hunt-1 returned 429")

        first = self.director._tick(force=True)
        self.assertEqual(first["action"], "start")
        self.assertEqual(first["mission_id"], mission["id"])
        self.assertEqual(first["mode"], "hunt")
        self.assertFalse(first.get("model_gate"))
        self.assertNotIn(other["id"], self.hunts.started + self.solvers.started)

        self.complete_run(first["run_id"], counts={"actions": 0})
        second = self.director._tick(force=True)
        self.assertEqual(second["action"], "start")
        self.assertEqual(second["mission_id"], mission["id"])
        self.assertEqual(second["mode"], "swarm")
        self.assertFalse(second.get("model_gate"))

        self.complete_run(second["run_id"], counts={"actions": 0})
        third = self.director._tick(force=True)
        self.assertEqual(third["action"], "start")
        self.assertEqual(third["mission_id"], mission["id"])
        self.assertEqual(third["mode"], "hunt")
        directions = (
            self.server.index.list_directions(mission["id"], status="queued")
            + self.server.index.list_directions(mission["id"], status="consumed"))
        self.assertTrue(any("Deepen continuous hunt" in str(row.get("body") or "")
                            for row in directions))
        rows = {row["mission_id"]: row for row in self.director.eligibility()}
        self.assertFalse(rows[mission["id"]]["parked"])
        self.assertNotEqual(third["action"], "idle")

    def test_a_newer_model_answer_reopens_the_gate(self):
        mission = self.mission("recovered")
        prior = self.server.index.create_run("http://127.0.0.1:9/", {"mode": "hunt"})
        self.server.index.add_mission_run(mission["id"], prior["id"])
        self.server.index.update_run(prior["id"], status="done", counts_json={"actions": 1})
        for _ in range(8):
            self.server.index.add_director_log(
                "brain-wait", "no model answered: ConnectError")
        self.server.index.add_director_log(
            "brain", "the model answered", data={"model": "test-model"})
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["mode"], "autopilot")
        self.assertFalse(decision["model_gate"])

    def test_a_finished_run_matures_the_mission(self):
        mission = self.mission("mature")
        run = self.server.index.create_run("http://127.0.0.1:9/", {"mode": "hunt"})
        self.server.index.add_mission_run(mission["id"], run["id"])
        self.server.index.add_tool_call(
            "http_probe", risk="low", status="ok", actor="agent:swarm",
            mission_id=mission["id"], run_id=run["id"],
            args={"target": "http://127.0.0.1:9/api/x"},
            result={"status": 200, "headers": {"server": "nginx"}})
        self.server.index.create_hypothesis(
            "a lead", target="http://127.0.0.1:9/api/x",
            mission_id=mission["id"], technique="idor")
        out = self.director._mature(mission["id"])
        self.assertIn("stage", out)
        self.assertTrue(self.server.index.list_kb_entries(scope="global"))
        self.assertIsNotNone(self.server.index.get_campaign(mission["id"]))
        self.assertTrue(self.server.index.list_graph_nodes(mission["id"]))

    def test_maturing_a_run_surfaces_positive_observations_as_leads(self):
        mission = self.mission("observation")
        self.server.index.add_agent_note(
            mission["id"], "swarm.observation", "Open redirect on callback",
            "GET https://example.com/api/callback?next=https://example.com/x "
            "returned a redirect to the external host.")
        out = self.director._mature(mission["id"])
        self.assertGreaterEqual(out.get("leads_synced", 0), 1)
        leads, total = self.server.index.list_hypotheses(
            mission_id=mission["id"], limit=20)
        self.assertGreaterEqual(total, 1)
        self.assertTrue(any("Open redirect" in lead["title"] for lead in leads))

    def test_a_queued_direction_becomes_the_run_goal(self):
        mission = self.mission("directed")
        prior = self.server.index.create_run("http://127.0.0.1:9/", {"mode": "hunt"})
        self.server.index.add_mission_run(mission["id"], prior["id"])
        self.server.index.create_direction(mission["id"], "focus the order API")
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["mode"], "autopilot")
        self.assertIn("Operator direction: focus the order API",
                      self.solvers.options.get("goal", ""))
        self.assertEqual(self.server.index.list_directions(mission["id"],
                                                           status="queued"), [])
        self.assertEqual(len(self.server.index.list_directions(
            mission["id"], status="consumed")), 1)

    def test_locked_priority_waits_instead_of_scheduling_another_mission(self):
        from netcast3r import brain as brain_module

        other = self.mission("other", autonomy="autonomous")
        locked = self.mission("locked", autonomy="supervised")
        brain_module.set_operator_priority(
            self.server.index, locked["id"], reason="operator lock")
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "wait")
        self.assertIn(locked["id"], decision["reason"])
        self.assertNotIn(other["id"], decision["reason"])
        self.assertEqual(self.hunts.started, [])
        self.assertEqual(self.solvers.started, [])

    def test_locked_ineligible_priority_waits_with_no_other_mission(self):
        from netcast3r import brain as brain_module

        locked = self.mission("manual-lock", autonomy="manual")
        brain_module.set_operator_priority(self.server.index, locked["id"])
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "wait")
        self.assertIn("not eligible", decision["reason"])
        self.assertEqual(self.hunts.started, [])
        self.assertEqual(self.solvers.started, [])

    def test_locked_priority_starts_only_that_mission(self):
        from netcast3r import brain as brain_module

        other = self.mission("other")
        locked = self.mission("locked")
        brain_module.set_operator_priority(self.server.index, locked["id"])
        decision = self.director._tick(force=True)
        self.assertEqual(decision["action"], "start")
        self.assertEqual(decision["mission_id"], locked["id"])
        self.assertNotEqual(decision["mission_id"], other["id"])
        started = self.hunts.started + self.solvers.started
        self.assertEqual(len(started), 1)

    def test_training_tick_skips_while_the_priority_gate_is_set(self):
        import threading

        from netcast3r import brain as brain_module
        from netcast3r.server.training_director import TrainingDirector

        mission = self.mission("focus")
        trainer = TrainingDirector(self.server)
        brain_module.set_operator_priority(self.server.index, mission["id"])
        self.assertIs(
            self.server.index.get_setting("training_paused_for_priority"), True)
        # Flag cleared, but the live mission lock still owns capacity.
        self.server.index.set_setting("training_paused_for_priority", False)
        trainer._tick()
        self.assertEqual(trainer._cycles, 0)
        self.assertEqual(trainer._inflight, 0)

        brain_module.clear_operator_priority(self.server.index)
        self.assertIs(
            self.server.index.get_setting("training_paused_for_priority"), False)
        self.assertEqual(brain_module.operator_priority(self.server.index), {})
        self.server.index.set_setting("training_paused_for_priority", True)
        trainer._tick()
        self.assertEqual(trainer._cycles, 0)

        self.server.index.set_setting("training_paused_for_priority", False)
        done = threading.Event()
        trainer._solve_one = lambda: done.set()
        trainer._tick()
        self.assertTrue(done.wait(2.0))
        self.assertEqual(trainer._cycles, 1)


class DirectorSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.server._hunts = lambda: FakeHunts(self.server)

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def call(self, method, path, body=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_director_routes_read_and_control(self):
        status = self.call("GET", "/api/v1/director")
        self.assertEqual(status.status, 200)
        payload = self.data(status)
        self.assertIn("engaged", payload)
        self.assertIn("scope_filter", payload)

        pause = self.call("POST", "/api/v1/director/control",
                          {"action": "pause"})
        self.assertEqual(pause.status, 200)
        self.assertTrue(self.data(pause)["paused"])

        kill = self.call("POST", "/api/v1/director/kill", {"all": False})
        self.assertEqual(kill.status, 200)
        self.assertFalse(self.data(kill)["engaged"])

        log = self.call("GET", "/api/v1/director/log")
        self.assertEqual(log.status, 200)
        self.assertTrue(self.data(log)["items"])

    def test_the_director_is_a_catalogued_tool_surface(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        names = [tool["name"] for tool in catalog()]
        for name in ("director_status", "director_control", "director_log",
                     "prime_portfolio"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)


class OperatorPriorityLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.hunts = FakeHunts(self.server)
        self.solvers = FakeSolvers(self.server)
        self.server._hunts = lambda: self.hunts
        self.server._solvers = lambda: self.solvers
        self.director = Director(self.server)
        self.director.tick_seconds = 5

    def tearDown(self):
        self.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_priority_hard_locks_other_missions(self):
        from netcast3r import brain

        primary = self.server.index.create_mission(
            "Primary", "http://127.0.0.1:9/", status="active",
            autonomy="autonomous", scope=["127.0.0.1"])
        other = self.server.index.create_mission(
            "Other", "http://127.0.0.1:9/other", status="active",
            autonomy="autonomous", scope=["127.0.0.1"])
        brain.set_operator_priority(self.server.index, primary["id"],
                                    reason="unit lock")
        self.assertTrue(brain.training_paused_for_priority(self.server.index))
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        for entry in (active.get("missions") or {}).values():
            entry["last_started"] = 0
        self.server.index.patch_director_state(active=active, paused=False,
                                               engaged=True)
        first = self.director._tick(force=True)
        self.assertEqual(first.get("mission_id"), primary["id"])
        # While primary is in flight, tick waits instead of scheduling other.
        second = self.director._tick(force=True)
        self.assertEqual(second.get("action"), "wait")
        self.assertNotIn(other["id"], self.solvers.started + self.hunts.started)
        brain.clear_operator_priority(self.server.index)
        self.assertFalse(brain.training_paused_for_priority(self.server.index))


if __name__ == "__main__":
    unittest.main()
