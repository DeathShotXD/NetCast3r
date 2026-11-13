import unittest

from netcast3r.mcp import tools


class _Registry:
    def __init__(self, payloads):
        self.payloads = payloads
        self.calls = []

    def call(self, tool, args, actor=""):
        self.calls.append((tool, args))
        return self.payloads.get(tool, {}), False


def _ctx(payloads):
    ctx = tools.ToolContext(plane=None, policy="readonly", base=None)
    ctx.registry = _Registry(payloads)
    return ctx


class PlanRunTests(unittest.TestCase):
    def test_idor_plan_runs_gated_and_cascades(self):
        ctx = _ctx({
            "access_control_compare": {"distinct_responses": 2},
            "idor_sequence_probe": {"distinct_shapes": 3},
        })
        result = tools.plan_run(ctx, {
            "goal": "id or object authorization",
            "target": "https://app.example.com/api/users/1",
            "signals": ["idor"], "profile": "attacker",
            "extra": {"ids": "1,2,3"}, "scope": ["example.com"],
        })
        self.assertTrue(result["executed"])
        self.assertEqual(result["plan"], "idor-two-identity")
        self.assertEqual(result["state"], "verified")
        self.assertEqual(result["supports"], 2)
        self.assertEqual(result["estimate"]["model_calls"], 0)
        # two follow-ups for each of two supported steps
        self.assertEqual(len(result["cascade"]), 4)
        self.assertEqual([tool for tool, _ in ctx.registry.calls],
                         ["access_control_compare", "idor_sequence_probe"])

    def test_failing_gate_refutes_without_a_model(self):
        ctx = _ctx({
            "access_control_compare": {"distinct_responses": 1},
            "idor_sequence_probe": {"distinct_shapes": 1},
        })
        result = tools.plan_run(ctx, {
            "goal": "id or", "target": "https://app.example.com/u/1",
            "signals": ["idor"], "profile": "attacker",
            "extra": {"ids": "1,2"}, "scope": ["example.com"],
        })
        self.assertEqual(result["state"], "refuted")
        self.assertEqual(result["refutes"], 2)
        self.assertEqual(result["cascade"], [])

    def test_not_ready_does_not_execute(self):
        ctx = _ctx({})
        result = tools.plan_run(ctx, {
            "goal": "sql injection", "target": "https://app.example.com/i?id=1",
            "signals": ["mysql"], "scope": ["example.com"],
        })
        self.assertFalse(result["executed"])
        self.assertIn("parameter", result["missing_arguments"])
        self.assertEqual(ctx.registry.calls, [])

    def test_out_of_scope_is_refused(self):
        ctx = _ctx({"takeover_scan": {"counts": {"vulnerable": 1}}})
        with self.assertRaises(tools.ToolError):
            tools.plan_run(ctx, {
                "goal": "dangling cname", "target": "https://evil.test/x",
                "signals": ["takeover"], "scope": ["example.com"],
            })

    def test_needs_a_registry(self):
        ctx = tools.ToolContext(plane=None, policy="readonly", base=None)
        with self.assertRaises(tools.ToolError):
            tools.plan_run(ctx, {
                "goal": "websocket", "target": "wss://app.example.com/chat",
                "signals": ["websocket"], "scope": ["example.com"],
            })


if __name__ == "__main__":
    unittest.main()
