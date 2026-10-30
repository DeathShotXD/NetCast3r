import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import model_solver
from netcast3r.server import build_server


class FakeRegistry:
    def __init__(self):
        self.calls = []

    def call(self, name, args, actor=""):
        self.calls.append((name, dict(args)))
        return {"ok": True, "url": args.get("target", ""), "status": 200}, False


def reply(action, args=None, thought="step"):
    import json
    return {"text": json.dumps({"thought": thought, "action": action,
                                "args": args or {}}),
            "provider": "fake", "model": "free"}


def scripted(*replies):
    queue = list(replies)

    def complete(messages):
        return queue.pop(0) if queue else reply("done", {"summary": "empty"})
    return complete


class SolverLoopTests(unittest.TestCase):
    def make(self, complete, steps=3):
        self.registry = FakeRegistry()
        return model_solver.Solver(
            self.registry, complete, "msn_test", "http://127.0.0.1:9/",
            goal="prove a lead", max_steps=steps)

    def test_probe_then_done(self):
        solver = self.make(scripted(
            reply("http_probe", {"target": "http://127.0.0.1:9/"}),
            reply("done", {"summary": "reachable only"}),
        ))
        result = solver.run()
        self.assertEqual(result["stop"], "model finished")
        self.assertEqual(result["actions"], 1)
        self.assertEqual(result["model_calls"], 2)
        self.assertEqual(result["findings"], 0)
        self.assertEqual(self.registry.calls[0][0], "http_probe")
        self.assertEqual(self.registry.calls[0][1]["mission_id"], "msn_test")

    def test_non_allowlisted_action_is_refused(self):
        solver = self.make(scripted(
            reply("runs_delete", {"run_id": "run_x"}),
            reply("runs_delete", {"run_id": "run_x"}),
        ))
        result = solver.run()
        self.assertIn("allow-list", result["stop"])
        self.assertEqual(self.registry.calls, [])
        self.assertEqual(result["findings"], 0)

    def test_invalid_reply_stops_after_two_attempts(self):
        solver = self.make(scripted(
            {"text": "I will poke the target.", "provider": "fake", "model": "free"},
            {"text": "still prose", "provider": "fake", "model": "free"},
        ))
        result = solver.run()
        self.assertIn("action schema", result["stop"])

    def test_repeated_action_stops(self):
        solver = self.make(scripted(
            reply("http_probe", {"target": "http://127.0.0.1:9/"}),
            reply("http_probe", {"target": "http://127.0.0.1:9/"}),
        ))
        result = solver.run()
        self.assertIn("repeated", result["stop"])

    def test_model_failure_is_recorded(self):
        def dead(messages):
            raise RuntimeError("provider down")
        solver = self.make(dead)
        result = solver.run()
        self.assertIn("model unavailable", result["stop"])
        self.assertEqual(result["findings"], 0)

    def test_approval_fields_are_stripped(self):
        solver = self.make(scripted(
            reply("http_probe", {"target": "http://127.0.0.1:9/",
                                 "approval_id": "apr_x", "confirm": True}),
            reply("done"),
        ))
        solver.run()
        args = self.registry.calls[0][1]
        self.assertNotIn("approval_id", args)
        self.assertNotIn("confirm", args)

    def test_target_alias_is_repaired(self):
        solver = self.make(scripted(
            reply("http_probe", {"url": "http://127.0.0.1:9/app"}),
            reply("done"),
        ))
        solver.run()
        self.assertEqual(self.registry.calls[0][1]["target"], "http://127.0.0.1:9/app")

    def test_missing_target_defaults_for_a_probe(self):
        solver = self.make(scripted(
            reply("http_probe", {"method": "GET"}),
            reply("done"),
        ))
        solver.run()
        self.assertEqual(self.registry.calls[0][1]["target"], "http://127.0.0.1:9/")

    def test_missing_target_is_not_invented_for_other_actions(self):
        solver = self.make(scripted(
            reply("scope_check", {}),
            reply("done"),
        ))
        solver.run()
        self.assertNotIn("target", self.registry.calls[0][1])

    def test_compaction_of_a_large_result_does_not_raise(self):
        payload = {"status": 200, "items": [
            {"id": f"item-{index}", "title": "a long title " * 40,
             "meta": {"nested": "value" * 100}} for index in range(50)]}
        compact = model_solver._compact(payload)
        self.assertEqual(compact["items_count"], 50)
        self.assertEqual(len(compact["items_sample"]), 3)
        import json as _json
        _json.dumps(compact)


class SolverHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><title>solver target</title>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SolverRunnerTests(unittest.TestCase):
    def setUp(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), SolverHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.target = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)

    def tearDown(self):
        if self.server.solver_runner is not None:
            self.server.solver_runner.shutdown(wait=True)
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_runner_turns_a_model_choice_into_a_live_run(self):
        from netcast3r.server.solver_runner import SolverRunner

        mission = self.server.index.create_mission(
            "Solver", self.target, status="active", scope=["127.0.0.1"])
        complete = scripted(
            reply("http_probe", {"target": self.target}),
            reply("done", {"summary": "target answers 200"}),
        )
        runner = SolverRunner(self.server, complete=complete)
        run = runner.start(mission["id"], {"max_steps": 3})
        deadline = time.time() + 20
        state = None
        while time.time() < deadline:
            state = self.server.index.get_run(run["id"])
            if state["status"] in ("done", "failed", "stopped", "interrupted"):
                break
            time.sleep(0.05)
        runner.shutdown(wait=True)
        self.assertEqual(state["status"], "done", state.get("error"))
        self.assertEqual(state["counts"]["mode"], "solve")
        self.assertEqual(state["counts"]["findings"], 0)
        self.assertGreaterEqual(state["counts"]["actions"], 1)
        stages = {item.get("stage") for item in
                  self.server.index.list_events(run["id"])}
        self.assertIn("reason", stages)
        self.assertIn("act", stages)
        self.assertIn("observe", stages)

    def test_training_mission_is_refused(self):
        from netcast3r.server.solver_runner import SolverRunner

        mission = self.server.index.create_mission(
            "Training range", self.target, status="active", scope=["127.0.0.1"])
        stored = self.server.index.get_mission(mission["id"])
        self.assertTrue(stored.get("training"))
        runner = SolverRunner(self.server, complete=scripted())
        with self.assertRaises(ValueError):
            runner.start(mission["id"])
        runner.shutdown(wait=False)


if __name__ == "__main__":
    unittest.main()