import json
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import autopilot
from netcast3r.server import build_server


class FakeRegistry:
    """A registry double that records calls and returns a canned verdict."""

    def __init__(self, error=False, payload=None):
        self.calls = []
        self.error = error
        self.payload = payload or {}

    def call(self, name, args, actor=""):
        self.calls.append((name, dict(args), actor))
        if self.error:
            return {"error": {"message": "refused by test"}}, True
        body = {"ok": True, "url": args.get("target", ""), "status": 200}
        body.update(self.payload)
        return body, False

    def names(self):
        return [name for name, _, _ in self.calls]


def reply(payload):
    return {"text": json.dumps(payload), "provider": "fake", "model": "free"}


def plan(*moves, thought="plan", hypothesis=None):
    body = {"thought": thought,
            "plan": [{"action": action, "args": args or {}, "why": "test"}
                     for action, args in moves]}
    if hypothesis:
        body["hypothesis"] = hypothesis
    return reply(body)


def scripted(*replies):
    queue = list(replies)

    def complete(messages):
        return queue.pop(0) if queue else reply({"thought": "empty",
                                                "summary": "nothing left",
                                                "done": True})
    return complete


def mission():
    return {"id": "msn_test", "title": "Test", "target": "http://127.0.0.1:9/",
            "objective": "prove a lead", "scope": ["127.0.0.1"], "status": "active"}


class AutopilotLoopTests(unittest.TestCase):
    def make(self, complete, registry=None, steps=8, calls=4):
        self.registry = registry or FakeRegistry()
        return autopilot.Autopilot(
            self.registry, complete, mission(), max_steps=steps,
            max_seconds=30, max_model_calls=calls, run_id="run_test")

    def test_planned_moves_run_in_order_and_create_no_findings(self):
        stages = []
        operator = self.make(scripted(
            plan(("scope_check", {"target": "http://127.0.0.1:9/"}),
                 ("http_probe", {"target": "http://127.0.0.1:9/"}),
                 thought="confirm scope then probe"),
            reply({"thought": "enough", "summary": "reachable only", "done": True}),
        ))
        operator.on_step = lambda stage, payload: stages.append(stage)
        result = operator.run()
        executed = [name for name in self.registry.names()
                    if name in ("scope_check", "http_probe")]
        self.assertEqual(executed, ["scope_check", "http_probe"])
        self.assertEqual(result["steps"][0]["args"]["mission_id"], "msn_test")
        self.assertEqual(result["findings"], 0)
        self.assertEqual(result["stop"], "operator finished")
        self.assertEqual(result["summary"], "reachable only")
        for stage in ("reason", "act", "observe", "decide"):
            self.assertIn(stage, stages)

    def test_a_model_plan_cannot_smuggle_a_finding_write(self):
        operator = self.make(scripted(
            plan(("findings_create", {"title": "fake critical"}),
                 ("runs_delete", {"run_id": "run_x"})),
        ))
        result = operator.run()
        self.assertNotIn("findings_create", self.registry.names())
        self.assertNotIn("runs_delete", self.registry.names())
        self.assertEqual(result["findings"], 0)
        # The unusable plan falls back to the deterministic baseline.
        self.assertIn("scope_check", self.registry.names())

    def test_reflection_replans_after_the_first_plan_is_spent(self):
        operator = self.make(scripted(
            plan(("http_probe", {"target": "http://127.0.0.1:9/"})),
            reply({"thought": "probe answered", "summary": "only reachability",
                   "done": False,
                   "next": [{"action": "technique_plan",
                             "args": {"target": "http://127.0.0.1:9/"},
                             "why": "rank next tests"}]}),
            reply({"thought": "out of evidence", "summary": "ranked, no proof",
                   "done": True}),
        ))
        result = operator.run()
        names = self.registry.names()
        self.assertIn("http_probe", names)
        self.assertIn("technique_plan", names)
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["stop"], "operator finished")

    def test_dead_model_falls_back_to_the_deterministic_baseline(self):
        def dead(messages):
            raise RuntimeError("provider down")

        notes = []
        operator = self.make(dead, steps=2)
        operator.on_step = lambda stage, payload: notes.append(
            str(payload.get("text") or "")) if isinstance(payload, dict) else None
        result = operator.run()
        first = [item["action"] for item in result["steps"]]
        self.assertEqual(first, ["scope_check", "http_probe"])
        self.assertEqual(result["findings"], 0)
        self.assertEqual(result["model_calls"], 1)
        self.assertTrue(any("provider down" in text for text in notes))

    def test_repeated_identical_move_stops_the_loop(self):
        operator = self.make(scripted(
            plan(("http_probe", {"target": "http://127.0.0.1:9/"}),
                 ("http_probe", {"target": "http://127.0.0.1:9/"}))),
        )
        result = operator.run()
        self.assertIn("repeated", result["stop"])
        self.assertEqual(len(result["steps"]), 1)

    def test_three_consecutive_tool_errors_stop_the_loop(self):
        operator = self.make(
            scripted(plan(("http_probe", {"target": "http://127.0.0.1:9/a"}),
                          ("http_probe", {"target": "http://127.0.0.1:9/b"}),
                          ("http_probe", {"target": "http://127.0.0.1:9/c"}))),
            registry=FakeRegistry(error=True))
        result = operator.run()
        self.assertIn("three consecutive", result["stop"])
        self.assertEqual(len(result["steps"]), 3)
        self.assertFalse(result["steps"][-1]["ok"])

    def test_notes_are_written_for_brief_plan_and_summary(self):
        operator = self.make(scripted(
            plan(("http_probe", {"target": "http://127.0.0.1:9/"}),
                 thought="one decisive probe"),
            reply({"thought": "done", "summary": "nothing proved", "done": True}),
        ))
        operator.run()
        kinds = [args.get("kind") for name, args, _ in self.registry.calls
                 if name == "agent_notes_write"]
        self.assertIn("brief", kinds)
        self.assertIn("plan", kinds)
        self.assertIn("summary", kinds)
        for name, args, actor in self.registry.calls:
            if name == "agent_notes_write":
                self.assertEqual(args.get("mission_id"), "msn_test")
                self.assertEqual(args.get("run_id"), "run_test")
                self.assertEqual(actor, "agent:autopilot")

    def test_a_plan_hypothesis_is_recorded_but_is_not_a_finding(self):
        operator = self.make(scripted(
            plan(("http_probe", {"target": "http://127.0.0.1:9/"}),
                 hypothesis={"title": "path traversal on /download",
                             "target": "http://127.0.0.1:9/",
                             "rationale": "filename parameter echoes",
                             "expected": "a 200 with the parent file body"}),
            reply({"thought": "done", "summary": "unproved", "done": True}),
        ))
        result = operator.run()
        self.assertEqual(result["hypotheses"], 1)
        self.assertEqual(result["findings"], 0)
        hypotheses = [args for name, args, _ in self.registry.calls
                      if name == "hypothesis_create"]
        self.assertEqual(hypotheses[0]["mission_id"], "msn_test")
        self.assertEqual(hypotheses[0]["title"], "path traversal on /download")

    def test_approval_fields_and_foreign_keys_are_stripped(self):
        operator = self.make(scripted(
            plan(("http_probe", {"target": "http://127.0.0.1:9/",
                                 "approval_id": "apr_x", "confirm": True,
                                 "unknown_key": "value"})),
            reply({"thought": "done", "summary": "stripped", "done": True}),
        ))
        operator.run()
        args = [item for name, item, _ in self.registry.calls
                if name == "http_probe"][0]
        self.assertNotIn("approval_id", args)
        self.assertNotIn("confirm", args)
        self.assertNotIn("unknown_key", args)
        self.assertEqual(args["mission_id"], "msn_test")


class AutopilotRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Operator", "http://127.0.0.1:9/", status="active",
            scope=["127.0.0.1"])

    def tearDown(self):
        if self.server.solver_runner is not None:
            self.server.solver_runner.shutdown(wait=True)
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_runner_turns_an_operator_plan_into_a_live_run(self):
        from netcast3r.server.solver_runner import SolverRunner

        complete = scripted(
            plan(("scope_check", {"target": "http://127.0.0.1:9/"}),
                 thought="confirm the boundary first"),
            reply({"thought": "scope is sound", "summary": "scope only",
                   "done": True}),
        )
        runner = SolverRunner(self.server, complete=complete)
        run = runner.start(self.mission["id"], {
            "mode": "autopilot", "max_steps": 2, "max_model_calls": 2,
            "max_seconds": 30})
        deadline = time.time() + 30
        state = None
        while time.time() < deadline:
            state = self.server.index.get_run(run["id"])
            if state["status"] in ("done", "failed", "stopped", "interrupted"):
                break
            time.sleep(0.05)
        runner.shutdown(wait=True)
        self.assertEqual(state["status"], "done", state.get("error"))
        self.assertEqual(state["counts"]["mode"], "autopilot")
        self.assertEqual(state["counts"]["findings"], 0)
        self.assertEqual(state["counts"]["hypotheses"], 0)
        notes = self.server.index.list_agent_notes(self.mission["id"])
        kinds = [note["kind"] for note in notes]
        self.assertIn("brief", kinds)
        self.assertIn("plan", kinds)
        self.assertIn("summary", kinds)
        stages = {item.get("stage") for item in
                  self.server.index.list_events(run["id"])}
        for stage in ("reason", "act", "observe", "decide"):
            self.assertIn(stage, stages)


class AutopilotNotesRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Notes", "http://127.0.0.1:9/", status="active", scope=["127.0.0.1"])

    def tearDown(self):
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

    def test_write_read_and_clear_notes(self):
        path = f"/api/v1/missions/{self.mission['id']}/notes"
        written = self.call("POST", path, {
            "kind": "observation", "title": "root answers 200",
            "body": "the baseline is reachable", "run_id": "run_x", "step": 2})
        self.assertEqual(written.status, 201)
        note = self.data(written)
        self.assertTrue(note["id"].startswith("note_"))

        listed = self.call("GET", path)
        self.assertEqual(listed.status, 200)
        items = self.data(listed)["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "root answers 200")
        self.assertEqual(items[0]["step"], 2)

        cleared = self.call("DELETE", path)
        self.assertEqual(cleared.status, 200)
        self.assertEqual(self.data(cleared)["cleared"], 1)
        self.assertEqual(self.data(self.call("GET", path))["items"], [])

    def test_a_note_needs_a_title_and_a_real_mission(self):
        path = f"/api/v1/missions/{self.mission['id']}/notes"
        self.assertEqual(self.call("POST", path, {"title": "  "}).status, 400)
        missing = "/api/v1/missions/msn_missing/notes"
        self.assertEqual(self.call("GET", missing).status, 404)
        self.assertEqual(self.call("POST", missing, {"title": "x"}).status, 404)

    def test_notes_survive_as_operator_memory(self):
        path = f"/api/v1/missions/{self.mission['id']}/notes"
        self.call("POST", path, {"kind": "brief", "title": "brief",
                                 "body": "five techniques ranked"})
        self.call("POST", path, {"kind": "summary", "title": "summary",
                                 "body": "no proof yet"})
        items = self.data(self.call("GET", path))["items"]
        self.assertEqual([item["kind"] for item in items], ["brief", "summary"])


if __name__ == "__main__":
    unittest.main()
