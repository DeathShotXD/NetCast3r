import json
import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import autopilot, swarm


class FakeRegistry:
    def __init__(self):
        self.calls = []

    def call(self, name, args, actor=""):
        self.calls.append((name, dict(args), actor))
        return {"ok": True, "url": args.get("target", ""), "status": 200,
                "title": "test"}, False

    def names(self):
        return [name for name, _, _ in self.calls]


def mission():
    return {"id": "msn_endless", "title": "Endless", "target": "http://127.0.0.1:9/",
            "objective": "prove a lead", "scope": ["127.0.0.1"], "status": "active"}


def reply(payload, provider="p1"):
    return {"text": json.dumps(payload), "provider": provider, "model": "mesh"}


class EndlessSwarmTests(unittest.TestCase):
    def test_endless_swarm_ignores_done_and_keeps_rotating(self):
        reg = FakeRegistry()

        def model(role, messages, exclude=None):
            if role == "strategist":
                return reply({"thought": "nothing left", "done": True})
            return reply({})  # no usable move -> deterministic rotation

        def should_stop():
            return len(reg.calls) >= 20

        mesh = swarm.Swarm(reg, model, mission(), endless=True,
                           run_id="run_endless", should_stop=should_stop)
        result = mesh.run()
        self.assertEqual(result["stop"], "cancelled")
        self.assertGreaterEqual(len(reg.calls), 20)
        # The rotation must reach for more than one repeated action.
        self.assertGreater(len(set(reg.names())), 2)


class EndlessAutopilotTests(unittest.TestCase):
    def test_endless_autopilot_ignores_done_and_keeps_rotating(self):
        reg = FakeRegistry()

        def complete(messages):
            return reply({"thought": "nothing left", "summary": "done",
                          "done": True, "plan": []})

        def should_stop():
            return len(reg.calls) >= 12

        op = autopilot.Autopilot(reg, complete, mission(), endless=True,
                                 run_id="run_endless_ap", should_stop=should_stop)
        result = op.run()
        self.assertEqual(result["stop"], "cancelled")
        self.assertGreaterEqual(len(reg.calls), 12)
        self.assertGreater(len(set(reg.names())), 2)


class OwnerNormalisationTests(unittest.TestCase):
    def test_free_form_owners_map_to_mesh_roles(self):
        mesh = swarm.Swarm(FakeRegistry(), lambda role, m, e=None: reply({}),
                           mission(), max_steps=2, max_seconds=10)
        rows = mesh._clean_objectives([
            {"owner": "Engagement Lead", "goal": "Confirm authorization"},
            {"owner": "auth-tester", "goal": "Test login enumeration"},
            {"owner": "Recon Analyst", "goal": "Map the surface"},
            {"owner": "attacker", "goal": "Test IDOR"},
        ])
        self.assertEqual([row["owner"] for row in rows],
                         ["attacker", "attacker", "scout", "attacker"])


class BoundedStillStopsTests(unittest.TestCase):
    """Without endless, the old budgets and stop reasons must be preserved."""

    def test_bounded_autopilot_still_honours_done(self):
        reg = FakeRegistry()

        def complete(messages):
            return reply({"thought": "nothing left", "summary": "done",
                          "done": True, "plan": []})

        op = autopilot.Autopilot(reg, complete, mission(), max_steps=4,
                                 max_seconds=30, max_model_calls=2)
        result = op.run()
        self.assertLessEqual(result["actions"], 4)
        self.assertNotEqual(result["stop"], "cancelled")


if __name__ == "__main__":
    unittest.main()
