"""State-directory ownership: one live server per base, no cross-process recovery."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netcast3r import control
from netcast3r.server import build_server


class BaseLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nc3r-base-"))
        self.base = self.tmp / "state"

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_lock_is_exclusive_and_released(self):
        first = control.acquire_base_lock(self.base)
        self.assertIsNotNone(first)
        second = control.acquire_base_lock(self.base)
        self.assertIsNone(second)
        control.release_base_lock(first)
        third = control.acquire_base_lock(self.base)
        self.assertIsNotNone(third)
        control.release_base_lock(third)

    def test_live_owner_ignores_dead_pid(self):
        control.write_control_plane(self.base, {
            "pid": 99999999,
            "url": "http://127.0.0.1:1",
            "port": 1,
            "token": "x",
        })
        self.assertIsNone(control.live_owner(self.base))

    def test_live_owner_ignores_recycled_pid(self):
        # This test process is alive but is not a NetCast3r server.
        control.write_control_plane(self.base, {
            "pid": os.getpid(),
            "url": "http://127.0.0.1:1",
            "port": 1,
            "token": "x",
        })
        self.assertIsNone(control.live_owner(self.base, exclude_pid=None))

    def test_live_owner_excludes_self(self):
        control.write_control_plane(self.base, {
            "pid": os.getpid(),
            "url": "http://127.0.0.1:1",
            "port": 1,
            "token": "x",
        })
        self.assertIsNone(control.live_owner(self.base, exclude_pid=os.getpid()))

    def test_build_server_honors_env_base(self):
        with mock.patch.dict(os.environ, {"NETCAST3R_BASE": str(self.base)}):
            server = build_server(results_dir=str(self.tmp / "results"), recover=False)
            try:
                self.assertEqual(server.base, self.base.resolve())
                self.assertTrue((self.base / "netcast3r.db").exists())
            finally:
                server.jobs.shutdown(wait=False)
                server.index.close()

    def test_recovery_skips_base_owned_by_another_live_process(self):
        with mock.patch.object(control, "live_owner",
                               return_value={"pid": 4242, "url": "http://x"}):
            server = build_server(results_dir=str(self.tmp / "results"),
                                  base=self.base, recover=True)
            try:
                self.assertFalse(server.index.running_run_ids())
            finally:
                server.jobs.shutdown(wait=False)
                server.index.close()

    def test_recovery_runs_when_base_is_unowned(self):
        with mock.patch.object(control, "live_owner", return_value=None):
            server = build_server(results_dir=str(self.tmp / "results"),
                                  base=self.base, recover=True)
            try:
                # No rows exist, but the call path must complete without error.
                self.assertEqual(server.index.running_run_ids(), [])
            finally:
                server.jobs.shutdown(wait=False)
                server.index.close()

    def test_stuck_run_is_reconciled_only_when_no_worker_owns_it(self):
        server = build_server(results_dir=str(self.tmp / "results"),
                              base=self.base, recover=False)
        try:
            run = server.index.create_run("https://example.test/", {"mode": "swarm"})
            run_id = run["id"]
            server.index.update_run(
                run_id, status="running", started_at="2020-01-01T00:00:00Z")
            self.assertNotIn(run_id, server._live_worker_ids())
            self.assertTrue(server._reconcile_stuck_run(
                run_id, server.index.get_run(run_id)))
            self.assertEqual(server.index.get_run(run_id)["status"], "interrupted")

            fresh = server.index.create_run("https://example.test/2", {"mode": "swarm"})
            server.index.update_run(fresh["id"], status="running")
            self.assertFalse(server._reconcile_stuck_run(
                fresh["id"], server.index.get_run(fresh["id"])))
            self.assertEqual(server.index.get_run(fresh["id"])["status"], "running")
        finally:
            server.jobs.shutdown(wait=False)
            server.index.close()


if __name__ == "__main__":
    unittest.main()
