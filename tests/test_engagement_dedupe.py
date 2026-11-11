import os
import tempfile
import threading
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server import build_server


class EngagementDedupeTests(unittest.TestCase):
    """One live run per mission+mode; duplicate starts hand back the live one."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)

    def tearDown(self):
        if self.server.solver_runner is not None:
            self.server.solver_runner.shutdown(wait=True)
        if self.server.hunt_runner is not None:
            self.server.hunt_runner.shutdown(wait=True)
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def _mission(self, title="Dedupe"):
        return self.server.index.create_mission(
            title, "http://127.0.0.1:9/", status="active", scope=["127.0.0.1"])

    def _live_handle(self, mission_id, mode):
        run = self.server.index.create_run(
            "http://127.0.0.1:9/", {"mode": mode, "mission_id": mission_id})
        # A registered handle is what makes a run "live"; do not spawn a worker.
        handle = threading.Event()
        return run, handle

    def test_duplicate_hunt_is_refused(self):
        mission = self._mission("Hunt dedupe")
        runner = self.server._hunts()
        run, handle = self._live_handle(mission["id"], "hunt")
        runner._handles[run["id"]] = handle
        try:
            out = runner.start(mission["id"])
        finally:
            runner._handles.pop(run["id"], None)
        self.assertTrue(out.get("already_running"))
        self.assertEqual(out["id"], run["id"])
        self.assertEqual(len(self.server.index.running_run_ids()), 1)

    def test_duplicate_swarm_is_refused(self):
        mission = self._mission("Swarm dedupe")
        runner = self.server._solvers()
        run, handle = self._live_handle(mission["id"], "swarm")
        runner._handles[run["id"]] = handle
        try:
            out = runner.start(mission["id"], {"mode": "swarm"})
        finally:
            runner._handles.pop(run["id"], None)
        self.assertTrue(out.get("already_running"))
        self.assertEqual(out["id"], run["id"])

    def test_other_modes_stay_allowed(self):
        mission = self._mission("Mode coexistence")
        runner = self.server._solvers()
        run, handle = self._live_handle(mission["id"], "swarm")
        runner._handles[run["id"]] = handle
        try:
            self.assertEqual(runner._live_run_for(mission["id"], "swarm"),
                             runner.server.index.get_run(run["id"]))
            self.assertIsNone(runner._live_run_for(mission["id"], "solve"))
            self.assertIsNone(runner._live_run_for("msn_other", "swarm"))
        finally:
            runner._handles.pop(run["id"], None)


if __name__ == "__main__":
    unittest.main()
