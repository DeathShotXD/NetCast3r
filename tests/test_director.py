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

    # -- progress and parking ---------------------------------------------
    def test_two_no_progress_runs_park_the_mission(self):
        mission = self.mission("stuck")
        first = self.director._tick(force=True)
        self.complete_run(first["run_id"], counts={"actions": 0})
        self.director._tick(force=True)  # reap -> no_progress 1
        self.clear_cooldowns()
        second = self.director._tick(force=True)
        self.assertEqual(second["action"], "start")
        self.complete_run(second["run_id"], counts={"actions": 0})
        self.director._tick(force=True)  # reap -> no_progress 2 -> parked
        rows = {row["mission_id"]: row for row in self.director.eligibility()}
        self.assertTrue(rows[mission["id"]]["parked"])
        self.clear_cooldowns()
        third = self.director._tick(force=True)
        self.assertEqual(third["action"], "idle")
        self.assertIn("parked", third["reason"])

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


if __name__ == "__main__":
    unittest.main()
