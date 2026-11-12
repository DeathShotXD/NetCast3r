"""Durable run resumption: a swarm survives a restart and continues.

The swarm checkpoints its planner state each round. A killed process leaves the
checkpoint behind; boot reloads it and relaunches the same run id, so the live
view shows one continuous hunt rather than a fresh one.
"""

import os
import json
import tempfile
import threading
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server import build_server
from netcast3r.swarm import Swarm


class _RecordingPool:
    """Capture worker submissions without running the model loop."""

    def __init__(self):
        self.calls = []

    def submit(self, fn, *args, **kwargs):
        self.calls.append((fn, args, kwargs))
        return None

    def shutdown(self, wait=False, cancel_futures=False):
        return None


def _noop_runner(run_id, target, options, emit, should_stop):
    """A scan runner that does no network work, for route-level tests."""
    return {"target": target, "pages": 0, "js_files": 0, "endpoints": 0}


class SwarmCheckpointTests(unittest.TestCase):
    def _swarm(self, **extra):
        return Swarm(
            registry=None,
            complete_for=lambda role, messages, exclude=None: {},
            mission={"id": "msn_x", "target": "example.com"},
            run_id="run_x", endless=True, **extra)

    def test_checkpoint_round_trip_preserves_planner_state(self):
        mesh = self._swarm()
        mesh.rounds = 4
        mesh.rotation = 6
        mesh.model_calls = 9
        mesh.hypotheses_recorded = 2
        mesh.corroborated = 1
        mesh.contested = 3
        mesh.role_calls["scout"] = 5
        mesh.role_actions["attacker"] = 7
        mesh.verdicts["supports"] = 2
        mesh._observations = [{"agent": "scout", "action": "http_probe"}]
        mesh._seen = {"http_probe{}", "http_request{\"url\": \"x\"}"}
        mesh._focus = [{"text": "check the admin panel"}]

        state = mesh.checkpoint()
        self.assertEqual(state["rounds"], 4)
        self.assertEqual(state["verdicts"]["supports"], 2)

        clone = self._swarm(resume=state)
        self.assertEqual(clone.rounds, 4)
        self.assertEqual(clone.rotation, 6)
        self.assertEqual(clone.model_calls, 9)
        self.assertEqual(clone.corroborated, 1)
        self.assertEqual(clone.contested, 3)
        self.assertEqual(clone.role_calls["scout"], 5)
        self.assertEqual(clone.role_actions["attacker"], 7)
        self.assertEqual(clone.verdicts["supports"], 2)
        self.assertIn("http_probe{}", clone._seen)
        self.assertEqual(clone._focus[0]["text"], "check the admin panel")

    def test_restore_ignores_garbage(self):
        clone = self._swarm(resume={"rounds": "nope", "role_calls": 5,
                                    "observed": "x", "seen": "not-a-list"})
        self.assertEqual(clone.rounds, 0)
        self.assertEqual(clone._seen, set())


class RunResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, runner=_noop_runner, recover=False)
        self.runner = self.server._solvers()

    def tearDown(self):
        with self.runner._lock:
            self.runner._handles.clear()
        self.runner.shutdown(wait=False)
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def _mission(self):
        return self.server.index.create_mission(
            "Resume", "http://127.0.0.1:9/", status="active",
            scope=["127.0.0.1"], autonomy="autonomous")

    def _run(self, mission_id, **options):
        base = {"mode": "swarm", "mission_id": mission_id}
        base.update(options)
        run = self.server.index.create_run("http://127.0.0.1:9/", base)
        self.server.index.add_mission_run(mission_id, run["id"])
        return run

    def test_resumable_only_matches_endless_swarm(self):
        mission = self._mission()
        endless = self._run(mission["id"], endless=True)
        bounded = self._run(mission["id"])
        self.assertTrue(self.runner.resumable(endless["id"]))
        self.assertFalse(self.runner.resumable(bounded["id"]))

    def test_seed_checkpoint_from_transcript(self):
        mission = self._mission()
        run = self._run(mission["id"], endless=True)
        self.server.index.add_event(run["id"], {
            "type": "log", "stage": "plan",
            "payload": {"agent": "strategist", "round": 3}})
        self.server.index.add_event(run["id"], {
            "type": "log", "stage": "act",
            "payload": {"agent": "scout", "tool": "http_probe",
                        "args": {"url": "https://example.com"}}})
        self.server.index.add_event(run["id"], {
            "type": "log", "stage": "observe",
            "payload": {"agent": "scout", "tool": "http_probe", "ok": True,
                        "verdict": "supports", "result": "200 OK"}})
        self.server.index.add_event(run["id"], {
            "type": "log", "stage": "model",
            "payload": {"agent": "validator", "kind": "done", "ok": True}})
        state = self.runner._seed_checkpoint_from_events(run["id"])
        self.assertIsNotNone(state)
        self.assertEqual(state["rounds"], 3)
        self.assertEqual(state["role_actions"]["scout"], 1)
        self.assertEqual(state["verdicts"]["supports"], 1)
        self.assertEqual(state["model_calls"], 1)
        self.assertTrue(any("http_probe" in row for row in state["seen"]))

    def test_resume_relaunches_the_same_run_id(self):
        mission = self._mission()
        run = self._run(mission["id"], endless=True)
        self.server.index.update_run(run["id"], status="interrupted",
                                     error="server restarted")
        self.server.index.set_run_checkpoint(
            run["id"], {"v": 1, "rounds": 5, "model_calls": 12})

        pool = _RecordingPool()
        self.runner.pool = pool
        row = self.runner.resume(run["id"])
        self.assertIsNotNone(row)
        self.assertEqual(len(pool.calls), 1)
        args = pool.calls[0][1]
        self.assertEqual(args[0], run["id"])            # same run id
        self.assertEqual(args[5], "swarm")              # same mode
        self.assertEqual(args[-1]["rounds"], 5)         # checkpoint restored
        self.assertIn(run["id"], self.runner._handles)
        # No second run row was created: the same row is reclaimed.
        rows, total = self.server.index.list_runs(limit=50)
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["id"], run["id"])

    def test_orphaned_resume_skips_bounded_runs(self):
        mission = self._mission()
        endless = self._run(mission["id"], endless=True)
        bounded = self._run(mission["id"])
        for run in (endless, bounded):
            self.server.index.update_run(run["id"], status="interrupted")
        self.server.orphaned_runs = [endless["id"], bounded["id"]]

        pool = _RecordingPool()
        self.runner.pool = pool
        result = self.server.resume_orphaned_runs()
        self.assertEqual(result["resumed"], [endless["id"]])
        self.assertIn(bounded["id"], result["skipped"])
        self.assertEqual(self.server.orphaned_runs, [])

    def _post(self, path):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        return self.server.route("POST", path, {}, headers, b"")

    def test_resume_route_continues_the_same_swarm_run(self):
        mission = self._mission()
        run = self._run(mission["id"], endless=True)
        self.server.index.update_run(run["id"], status="interrupted")
        self.server.index.set_run_checkpoint(
            run["id"], {"v": 1, "rounds": 8})
        self.runner.pool = _RecordingPool()
        response = self._post(f"/api/v1/runs/{run['id']}/resume")
        self.assertEqual(response.status, 200)
        body = json.loads(response.body.decode())
        # The route returns the same run id, not a derived run.
        self.assertEqual(body["id"], run["id"])

    def test_resume_route_forks_a_bounded_run(self):
        mission = self._mission()
        run = self._run(mission["id"])  # bounded: not a resumable swarm
        self.server.index.update_run(run["id"], status="done")
        response = self._post(f"/api/v1/runs/{run['id']}/resume")
        self.assertEqual(response.status, 201)
        body = json.loads(response.body.decode())
        self.assertNotEqual(body["id"], run["id"])
        self.assertEqual((body.get("options") or {}).get("resume_from"), run["id"])


if __name__ == "__main__":
    unittest.main()