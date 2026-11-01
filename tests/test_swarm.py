import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import os

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import swarm
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
        body = {"ok": True, "url": args.get("target", ""), "status": 200,
                "title": "test"}
        body.update(self.payload)
        return body, False

    def names(self):
        return [name for name, _, _ in self.calls]

    def actors(self):
        return {actor for _, _, actor in self.calls}


def reply(payload, provider="p1"):
    return {"text": json.dumps(payload), "provider": provider, "model": "mesh"}


def always(payload, provider="p1"):
    def handler(messages, exclude, call_no):
        return reply(payload, provider)
    return handler


def objectives(*rows, thought="plan", done=False):
    body = {"thought": thought, "done": done,
            "objectives": [{"owner": owner, "goal": goal, "success": "observed"}
                           for owner, goal in rows]}
    return reply(body)


def move(action, args, why="test", expects="a difference"):
    return reply({"action": action, "args": args, "why": why,
                  "expects": expects})


def validator(verdict="inconclusive", second=None, provider="p1"):
    def handler(messages, exclude, call_no):
        if exclude:
            return reply({"verdict": second or verdict, "reason": "second",
                          "next": "settle it"}, provider="p2")
        return reply({"verdict": verdict, "reason": "first",
                      "next": "settle it"}, provider=provider)
    return handler


def scribe(*notes):
    body = {"notes": [{"kind": kind, "title": title, "body": body_text}
                      for kind, title, body_text in notes]}
    return lambda messages, exclude, call_no: reply(body)


class MeshModel:
    """A role-routed model double. Each role gets its own scripted handler."""

    def __init__(self, handlers=None, dead=()):
        self.handlers = handlers or {}
        self.dead = set(dead)
        self.calls = []
        self.excludes = []
        self._lock = __import__("threading").Lock()

    def __call__(self, role, messages, exclude=None):
        with self._lock:
            self.calls.append(role)
            self.excludes.append((role, set(exclude or ())))
        if role in self.dead or role not in self.handlers:
            raise RuntimeError(f"provider down for {role}")
        return self.handlers[role](messages, set(exclude or ()), self.calls.count(role))


def mission():
    return {"id": "msn_test", "title": "Mesh", "target": "http://127.0.0.1:9/",
            "objective": "prove a lead", "scope": ["127.0.0.1"],
            "status": "active"}


class SwarmLoopTests(unittest.TestCase):
    def make(self, model, registry=None, steps=10, calls=12):
        self.registry = registry or FakeRegistry()
        operator = swarm.Swarm(
            self.registry, model, mission(), max_steps=steps,
            max_seconds=30, max_model_calls=calls, run_id="run_mesh")
        return operator

    def test_roles_route_independently_and_create_no_findings(self):
        def scout(messages, exclude, call_no):
            objective = json.loads(messages[1]["content"])["objective"]
            suffix = "a" if "first" in objective["goal"] else "b"
            return move("http_probe",
                        {"target": f"http://127.0.0.1:9/{suffix}"})

        model = MeshModel({
            "strategist": lambda m, e, n: (
                objectives(("scout", "first lead"), ("scout", "second lead"))
                if n == 1 else objectives(done=True)),
            "scout": scout,
            "validator": validator("inconclusive"),
            "scribe": scribe(("observation", "two probes", "both answered")),
        })
        stages = []
        mesh = self.make(model)
        mesh.on_step = lambda stage, payload: stages.append(stage)
        result = mesh.run()

        self.assertEqual(result["findings"], 0)
        self.assertEqual(result["mode"], "swarm")
        self.assertEqual(result["roles"]["scout"], 2)
        self.assertEqual(result["role_calls"]["strategist"], 2)
        self.assertEqual(result["role_calls"]["validator"], 2)
        self.assertEqual(result["role_calls"]["scribe"], 1)
        self.assertEqual([item["action"] for item in result["steps"]],
                         ["http_probe", "http_probe"])
        self.assertEqual(self.registry.actors(), {"agent:swarm"})
        for stage in ("reason", "act", "observe", "decide"):
            self.assertIn(stage, stages)
        self.assertNotIn("findings_create", self.registry.names())

    def test_a_specialist_cannot_choose_another_roles_action(self):
        model = MeshModel({
            "strategist": lambda m, e, n: (
                objectives(("attacker", "test the lead"))
                if n == 1 else objectives(done=True)),
            "attacker": always({"action": "http_probe",
                                "args": {"target": "http://127.0.0.1:9/"},
                                "why": "not mine to call"}),
            "validator": validator(),
            "scribe": scribe(),
        })
        mesh = self.make(model)
        result = mesh.run()
        self.assertEqual([item["action"] for item in result["steps"]],
                         ["chain_plan"])
        self.assertNotIn("http_probe", self.registry.names())
        self.assertEqual(result["findings"], 0)

    def test_a_specialist_cannot_smuggle_a_finding_or_a_delete(self):
        model = MeshModel({
            "strategist": lambda m, e, n: (
                objectives(("scout", "try the dangerous call"))
                if n == 1 else objectives(done=True)),
            "scout": always({"action": "findings_create",
                             "args": {"title": "fake critical"}}),
            "validator": validator(),
            "scribe": scribe(("finding", "fake critical", "invented")),
        })
        mesh = self.make(model)
        result = mesh.run()
        self.assertNotIn("findings_create", self.registry.names())
        self.assertNotIn("runs_delete", self.registry.names())
        self.assertEqual(result["findings"], 0)
        # The unusable proposal fell back to a safe scout move.
        self.assertIn("scope_check", self.registry.names())

    def test_a_strategist_cannot_hand_work_to_a_non_specialist(self):
        model = MeshModel({
            "strategist": lambda m, e, n: objectives(("validator", "judge it")),
            "validator": validator(),
            "scribe": scribe(),
        })
        mesh = self.make(model)
        result = mesh.run()
        self.assertEqual(result["steps"], [])
        self.assertEqual(result["findings"], 0)
        self.assertNotIn("hypothesis_test", self.registry.names())

    def test_dead_model_runs_the_deterministic_baseline(self):
        def dead(messages, exclude, call_no):
            raise RuntimeError("provider down")

        model = MeshModel({"strategist": dead, "scout": dead, "attacker": dead,
                           "validator": dead, "scribe": dead})
        mesh = self.make(model, steps=4)
        result = mesh.run()
        self.assertEqual([item["action"] for item in result["steps"]],
                         ["scope_check", "http_probe", "chain_plan"])
        self.assertEqual(result["findings"], 0)
        self.assertEqual(result["roles"]["scout"], 2)
        self.assertEqual(result["roles"]["attacker"], 1)
        self.assertIn("deterministic", result["summary"])
        self.assertLessEqual(result["model_calls"], 12)
        self.assertEqual(self.registry.actors(), {"agent:swarm"})

    def test_model_budget_is_a_hard_cap(self):
        def scout(messages, exclude, call_no):
            objective = json.loads(messages[1]["content"])["objective"]
            suffix = "a" if "first" in objective["goal"] else "b"
            return move("http_probe",
                        {"target": f"http://127.0.0.1:9/{suffix}"})

        model = MeshModel({
            "strategist": lambda m, e, n: objectives(
                ("scout", "first lead"), ("scout", "second lead")),
            "scout": scout,
            "validator": validator(),
            "scribe": scribe(),
        })
        mesh = self.make(model, calls=3)
        result = mesh.run()
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(len(result["steps"]), 2)
        self.assertEqual(result["findings"], 0)

    def test_an_identical_move_is_skipped_not_repeated(self):
        model = MeshModel({
            "strategist": lambda m, e, n: (
                objectives(("scout", "first lead"), ("scout", "second lead"))
                if n == 1 else objectives(done=True)),
            "scout": always({"action": "http_probe",
                             "args": {"target": "http://127.0.0.1:9/"},
                             "why": "same request"}),
            "validator": validator(),
            "scribe": scribe(),
        })
        decisions = []
        mesh = self.make(model)
        mesh.on_step = lambda stage, payload: decisions.append(
            str(payload.get("text") or "")) if stage == "decide" else None
        result = mesh.run()
        self.assertEqual(len(result["steps"]), 1)
        self.assertEqual(result["roles"]["scout"], 2)
        self.assertTrue(any("repeated" in text for text in decisions))

    def test_a_skipped_repeat_is_visible_to_the_next_plan(self):
        payloads = []

        def strategist(messages, exclude, call_no):
            payloads.append(str(messages[1].get("content") or ""))
            return objectives(("scout", "same lead"))

        model = MeshModel({
            "strategist": strategist,
            "scout": always({"action": "http_probe",
                             "args": {"target": "http://127.0.0.1:9/"}}),
            "validator": validator(),
            "scribe": scribe(),
        })
        mesh = self.make(model)
        result = mesh.run()
        self.assertEqual(len(result["steps"]), 1)
        self.assertTrue(any("skipped: an identical request already ran" in text
                            for text in payloads[1:]))

    def test_a_first_round_done_is_answered_with_the_baseline(self):
        model = MeshModel({
            "strategist": lambda m, e, n: objectives(done=True),
        }, dead=("scout",))
        mesh = self.make(model)
        result = mesh.run()
        self.assertEqual([item["action"] for item in result["steps"]],
                         ["scope_check", "http_probe"])
        self.assertEqual(result["findings"], 0)

    def test_two_empty_rounds_stop_the_mesh(self):
        model = MeshModel({
            "strategist": lambda m, e, n: objectives(
                ("scout", "first lead"), ("scout", "second lead")),
            "scout": always({"action": "http_probe",
                             "args": {"target": "http://127.0.0.1:9/"},
                             "why": "same request"}),
            "validator": validator(),
            "scribe": scribe(),
        })
        mesh = self.make(model)
        result = mesh.run()
        self.assertEqual(len(result["steps"]), 1)
        self.assertEqual(result["stop"], "two rounds with no executed move")
        self.assertEqual(result["rounds"], 3)
        # An empty round costs no scribe call.
        self.assertEqual(result["role_calls"]["scribe"], 1)
        self.assertEqual(result["findings"], 0)

    def test_a_supported_verdict_is_cross_checked_with_a_second_provider(self):
        model = MeshModel({
            "strategist": lambda m, e, n: (
                objectives(("scout", "probe the root"))
                if n == 1 else objectives(done=True)),
            "scout": always({"action": "http_probe",
                             "args": {"target": "http://127.0.0.1:9/"},
                             "why": "baseline"}),
            "validator": validator("supports", second="supports"),
            "scribe": scribe(),
        })
        mesh = self.make(model)
        result = mesh.run()
        self.assertEqual(result["corroborated"], 1)
        self.assertEqual(result["contested"], 0)
        # verdicts counts primary judgments; corroboration is counted apart.
        self.assertEqual(result["verdicts"]["supports"], 1)
        self.assertEqual(result["steps"][0]["verdict"]["corroboration"],
                         "second provider agreed")
        self.assertIn(("validator", {"p1"}), model.excludes)

    def test_a_second_provider_can_contest_a_supported_verdict(self):
        model = MeshModel({
            "strategist": lambda m, e, n: (
                objectives(("scout", "probe the root"))
                if n == 1 else objectives(done=True)),
            "scout": always({"action": "http_probe",
                             "args": {"target": "http://127.0.0.1:9/"},
                             "why": "baseline"}),
            "validator": validator("supports", second="refutes"),
            "scribe": scribe(),
        })
        mesh = self.make(model)
        result = mesh.run()
        self.assertEqual(result["contested"], 1)
        self.assertEqual(result["corroborated"], 0)
        self.assertEqual(result["steps"][0]["verdict"]["corroboration"],
                         "second provider disagreed")

    def test_the_scribe_can_only_write_notes(self):
        model = MeshModel({
            "strategist": lambda m, e, n: (
                objectives(("scout", "probe the root"))
                if n == 1 else objectives(done=True)),
            "scout": always({"action": "scope_check",
                             "args": {"target": "http://127.0.0.1:9/"}}),
            "validator": validator(),
            "scribe": scribe(("dead-end", "root only", "no differential")),
        })
        mesh = self.make(model)
        result = mesh.run()
        kinds = [args.get("kind") for name, args, _ in self.registry.calls
                 if name == "agent_notes_write"]
        self.assertIn("swarm.dead-end", kinds)
        self.assertIn("swarm.round", kinds)
        for name, args, actor in self.registry.calls:
            if name == "agent_notes_write":
                self.assertEqual(actor, "agent:swarm")
                self.assertEqual(args.get("mission_id"), "msn_test")
        self.assertEqual(result["findings"], 0)


class _LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>mesh lab</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SwarmRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Mesh", "http://127.0.0.1:9/", status="active",
            scope=["127.0.0.1"])

    def tearDown(self):
        if self.server.solver_runner is not None:
            self.server.solver_runner.shutdown(wait=True)
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_runner_turns_a_mesh_round_into_a_live_run(self):
        from netcast3r.server.solver_runner import SolverRunner

        lab = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
        threading.Thread(target=lab.serve_forever, daemon=True).start()
        target = f"http://127.0.0.1:{lab.server_address[1]}/"
        run_mission = self.server.index.create_mission(
            "Mesh live", target, status="active", scope=["127.0.0.1"])
        queue = [
            objectives(("scout", "probe the root")),
            move("http_probe", {"target": target}),
            reply({"verdict": "supports", "reason": "a real baseline",
                   "next": "compare a variant"}),
            reply({"verdict": "supports", "reason": "agreed",
                   "next": "compare a variant"}),
            reply({"notes": [{"kind": "observation", "title": "root answered",
                              "body": "a 200 baseline"}]}),
            objectives(done=True),
        ]

        def complete(messages):
            return queue.pop(0) if queue else objectives(done=True)

        runner = SolverRunner(self.server, complete=complete)
        try:
            run = runner.start(run_mission["id"], {
                "mode": "swarm", "max_steps": 4, "max_model_calls": 8,
                "max_seconds": 30})
            deadline = time.time() + 30
            state = None
            while time.time() < deadline:
                state = self.server.index.get_run(run["id"])
                if state["status"] in ("done", "failed", "stopped", "interrupted"):
                    break
                time.sleep(0.05)
        finally:
            runner.shutdown(wait=True)
            lab.shutdown()
            lab.server_close()
        self.assertEqual(state["status"], "done", state.get("error"))
        self.assertEqual(state["counts"]["mode"], "swarm")
        self.assertEqual(state["counts"]["findings"], 0)
        self.assertEqual(state["counts"]["agents"], 4)
        self.assertEqual(state["counts"]["rounds"], 1)
        self.assertEqual(state["counts"]["corroborated"], 1)
        notes = self.server.index.list_agent_notes(run_mission["id"])
        kinds = [note["kind"] for note in notes]
        self.assertIn("brief", kinds)
        self.assertIn("swarm.round", kinds)
        self.assertIn("summary", kinds)
        events = self.server.index.list_events(run["id"])
        stages = {item.get("stage") for item in events}
        for stage in ("reason", "act", "observe", "decide"):
            self.assertIn(stage, stages)
        agents = {str((item.get("payload") or {}).get("agent") or "")
                  for item in events}
        self.assertIn("scout", agents)
        self.assertIn("validator", agents)
        self.assertIn("scribe", agents)


class SwarmSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.mission = self.server.index.create_mission(
            "Mesh route", "http://127.0.0.1:9/", status="active",
            scope=["127.0.0.1"])

    def tearDown(self):
        if self.server.solver_runner is not None:
            self.server.solver_runner.shutdown(wait=True)
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

    def test_the_route_passes_swarm_mode_to_the_runner(self):
        class FakeSolvers:
            def __init__(self):
                self.calls = []

            def start(self, mission_id, options):
                self.calls.append((mission_id, dict(options)))
                return {"id": "run_fake", "options": dict(options)}

        fake = FakeSolvers()
        self.server._solvers = lambda: fake
        path = f"/api/v1/missions/{self.mission['id']}/swarm"
        response = self.call("POST", path, {
            "max_steps": 3, "max_seconds": 30, "max_model_calls": 4,
            "goal": "one decisive probe"})
        self.assertEqual(response.status, 201)
        self.assertEqual(self.data(response)["id"], "run_fake")
        mission_id, options = fake.calls[0]
        self.assertEqual(mission_id, self.mission["id"])
        self.assertEqual(options["mode"], "swarm")
        self.assertEqual(options["max_steps"], 3)
        self.assertEqual(options["goal"], "one decisive probe")

    def test_the_mesh_is_a_catalogued_tool(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        self.assertIn("swarm", _TOOL_MAP)
        self.assertIn("swarm", [tool["name"] for tool in catalog()])


class EvidenceCompactionTests(unittest.TestCase):
    def test_compact_keeps_a_body_sample_and_not_cookies(self):
        from netcast3r.autopilot import _compact

        out = _compact({
            "status": 200,
            "body": '{"authentication":{"token":"eyJhbGciOiJSUzI1NiJ9.payload.sig"}}',
            "headers": {"content-type": "application/json",
                        "set-cookie": "session=super-secret"},
        })
        self.assertIn("token", out["body_sample"])
        self.assertEqual(out["headers"]["content-type"], "application/json")
        self.assertNotIn("set-cookie", out["headers"])

    def test_role_menu_shows_the_request_arguments(self):
        menu = swarm._role_menu("attacker")
        self.assertIn("http_request", menu)
        self.assertIn("method", menu)
        self.assertIn("json", menu)


if __name__ == "__main__":
    unittest.main()
