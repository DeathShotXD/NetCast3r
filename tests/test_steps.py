import unittest

from netcast3r import steps


class _Registry:
    def __init__(self, payloads):
        self.payloads = payloads
        self.calls = []

    def call(self, tool, args, actor=""):
        self.calls.append((tool, args, actor))
        payload = self.payloads.get(tool, {})
        return payload, False


VERIFY_STEP = {
    "tool": "http_request",
    "args": {"target": "https://app.example.com/x"},
    "verify": [{"path": "status", "eq": 200}],
    "expected": "the endpoint answers 200",
}


class GateTests(unittest.TestCase):
    def test_pass_is_deterministic_and_skips_the_model(self):
        registry = _Registry({"http_request": {"status": 200}})
        result = steps.execute_steps([VERIFY_STEP], "app.example.com", "msn_x",
                                     registry, complete=None)
        row = result["steps"][0]
        self.assertEqual(row["verdict"], "supports")
        self.assertEqual(row["gate"]["verdict"], "pass")
        self.assertEqual(result["supports"], 1)

    def test_fail_is_deterministic(self):
        registry = _Registry({"http_request": {"status": 403}})
        result = steps.execute_steps([VERIFY_STEP], "app.example.com", "msn_x",
                                     registry, complete=None)
        row = result["steps"][0]
        self.assertEqual(row["verdict"], "refutes")
        self.assertEqual(row["gate"]["verdict"], "fail")
        self.assertEqual(result["refutes"], 1)

    def test_missing_field_falls_back_to_the_judge(self):
        # A gate that cannot be evaluated is "repeat", and with no model the
        # step is inconclusive, never a pass.
        registry = _Registry({"http_request": {"body": "no status here"}})
        result = steps.execute_steps([VERIFY_STEP], "app.example.com", "msn_x",
                                     registry, complete=None)
        row = result["steps"][0]
        self.assertEqual(row["verdict"], "inconclusive")
        self.assertEqual(row["gate"]["verdict"], "repeat")

    def test_no_assertion_uses_the_model_path(self):
        step = {"tool": "http_request",
                "args": {"target": "https://app.example.com/x"}}
        registry = _Registry({"http_request": {"status": 200}})
        result = steps.execute_steps([step], "app.example.com", "msn_x",
                                     registry, complete=None)
        self.assertEqual(result["steps"][0]["verdict"], "inconclusive")
        self.assertIsNone(result["steps"][0]["gate"])

    def test_destructive_tool_is_blocked(self):
        step = {"tool": "missions_delete", "args": {"mission_id": "msn_x"}}
        registry = _Registry({})
        result = steps.execute_steps([step], "app.example.com", "msn_x", registry)
        self.assertEqual(result["steps"][0]["verdict"], "blocked")
        self.assertEqual(result["blocked"], 1)
        self.assertEqual(registry.calls, [])

    def test_state_of(self):
        self.assertEqual(steps.state_of(1, 0, 0, 1, False), "verified")
        self.assertEqual(steps.state_of(0, 1, 0, 1, False), "refuted")
        self.assertEqual(steps.state_of(0, 0, 1, 1, False), "blocked")


if __name__ == "__main__":
    unittest.main()
