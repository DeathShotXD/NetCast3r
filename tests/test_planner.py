import unittest

from netcast3r import planner


class LibraryTests(unittest.TestCase):
    def test_library_lists_plans(self):
        data = planner.library()
        ids = {row["id"] for row in data["items"]}
        self.assertIn("idor-two-identity", ids)
        self.assertIn("sqli-differential", ids)

    def test_library_query(self):
        data = planner.library("graphql")
        self.assertEqual(data["items"][0]["id"], "graphql-authz")


class RankTests(unittest.TestCase):
    def test_sql_signal_picks_sqli(self):
        ranked = planner.rank("find sql injection", ["mysql"])
        self.assertEqual(ranked[0]["plan"].id, "sqli-differential")

    def test_no_context_falls_back_to_recon(self):
        ranked = planner.rank("", [])
        self.assertEqual(ranked[0]["plan"].id, "generic-recon")

    def test_takeover_signal(self):
        ranked = planner.rank("", ["dangling cname", "subdomain"])
        self.assertEqual(ranked[0]["plan"].id, "takeover")


class CompileTests(unittest.TestCase):
    def test_compile_fills_target_and_flags_missing(self):
        result = planner.compile_plan(goal="sql injection",
                                      target="https://app.example.com/item?id=1",
                                      signals=["mysql"])
        self.assertEqual(result["chosen"], "sqli-differential")
        first = result["steps"][0]
        self.assertEqual(first["tool"], "injection_differential_probe")
        self.assertEqual(first["args"]["target"], "https://app.example.com/item?id=1")
        self.assertFalse(result["ready"])
        self.assertIn("parameter", result["missing_arguments"])
        # every step carries a verification assertion
        self.assertTrue(all(step["verify"] for step in result["steps"]))

    def test_compile_ready_when_arguments_supplied(self):
        result = planner.compile_plan(
            goal="id or", target="https://app.example.com/api/users/1",
            signals=["idor"], profile="attacker",
            extra={"ids": "1,2,3"})
        self.assertEqual(result["chosen"], "idor-two-identity")
        self.assertNotIn("profile", result["missing_arguments"])
        self.assertNotIn("ids", result["missing_arguments"])

    def test_compile_binds_mission_id(self):
        result = planner.compile_plan(goal="websocket cswsh",
                                      target="wss://app.example.com/chat",
                                      signals=["websocket"],
                                      mission_id="msn_test")
        self.assertEqual(result["chosen"], "websocket-cswsh")
        step = result["steps"][0]
        self.assertEqual(step["tool"], "ws_audit")
        if "mission_id" in step["args"]:
            self.assertEqual(step["args"]["mission_id"], "msn_test")

    def test_candidates_included(self):
        result = planner.compile_plan(goal="cache poisoning", signals=["cache"])
        self.assertTrue(result["candidates"])
        self.assertEqual(result["candidates"][0]["id"], result["chosen"])

    def test_unknown_tool_is_flagged(self):
        # A plan whose tool is not in the catalog must not pretend to be ready.
        original = planner.PLANS
        planner.PLANS = (planner.Plan(
            id="x", title="x", goal="x", impact="low", signals=("x",),
            steps=({"tool": "no_such_tool_xyz", "args": {}, "verify": []},)),)
        try:
            result = planner.compile_plan(goal="x", signals=["x"])
            self.assertFalse(result["ready"])
            self.assertFalse(result["steps"][0]["known"])
        finally:
            planner.PLANS = original

    def test_summary(self):
        self.assertIn("plans", planner.summary())


if __name__ == "__main__":
    unittest.main()
