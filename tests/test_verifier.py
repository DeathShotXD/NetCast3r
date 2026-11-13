import unittest

from netcast3r import verifier


class PathTests(unittest.TestCase):
    def test_dotted_path_with_index(self):
        data = {"results": [{"status": 200}, {"status": 403}]}
        self.assertEqual(verifier._get(data, "results.1.status"), 403)
        self.assertEqual(verifier._get(data, "results.9.status"), verifier._MISSING)
        self.assertEqual(verifier._get(data, "nope"), verifier._MISSING)


class VerifyTests(unittest.TestCase):
    def test_op_eq_pass(self):
        result = verifier.verify({"path": "status", "eq": 200}, {"status": 200})
        self.assertEqual(result["verdict"], "pass")

    def test_op_gte_fail(self):
        result = verifier.verify({"path": "counts.vulnerable", "gte": 1},
                                 {"counts": {"vulnerable": 0}})
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("not gte", result["reason"])

    def test_contains_is_case_insensitive(self):
        result = verifier.verify({"path": "body", "contains": "mysql"},
                                 {"body": "SQL syntax near MySQL server"})
        self.assertEqual(result["verdict"], "pass")

    def test_regex(self):
        result = verifier.verify({"path": "body", "regex": r"SQL syntax.*MySQL"},
                                 {"body": "SQL syntax error in MySQL"})
        self.assertEqual(result["verdict"], "pass")

    def test_in_and_not_contains(self):
        ok = verifier.verify({"path": "status", "in": [301, 302]}, {"status": 302})
        bad = verifier.verify({"path": "body", "not_contains": "error"},
                              {"body": "an error occurred"})
        self.assertEqual(ok["verdict"], "pass")
        self.assertEqual(bad["verdict"], "fail")

    def test_present_false(self):
        result = verifier.verify({"path": "x", "present": False}, {"y": 1})
        self.assertEqual(result["verdict"], "pass")

    def test_changed_against_baseline(self):
        assertion = {"path": "body_sha256", "changed": True}
        self.assertEqual(verifier.verify(assertion, {"body_sha256": "b"},
                                         {"body_sha256": "a"})["verdict"], "pass")
        self.assertEqual(verifier.verify(assertion, {"body_sha256": "a"},
                                         {"body_sha256": "a"})["verdict"], "fail")

    def test_changed_without_baseline_repeats(self):
        result = verifier.verify({"path": "body_sha256", "changed": True},
                                 {"body_sha256": "b"})
        self.assertEqual(result["verdict"], "repeat")

    def test_missing_field_repeats(self):
        result = verifier.verify({"path": "status", "eq": 200}, {"body": "x"})
        self.assertEqual(result["verdict"], "repeat")

    def test_transport_refusal_repeats(self):
        result = verifier.verify({"path": "status", "eq": 200},
                                 {"error": {"message": "timed out"}})
        self.assertEqual(result["verdict"], "repeat")
        self.assertIn("timed out", result["reason"])

    def test_all_checks(self):
        assertion = {"all": [{"path": "status", "in": [301, 302]},
                             {"path": "headers.location", "present": True}]}
        result = verifier.verify(assertion, {"status": 302,
                                             "headers": {"location": "https://evil"}})
        self.assertEqual(result["verdict"], "pass")

    def test_no_observation(self):
        self.assertEqual(verifier.verify({"path": "x", "eq": 1}, None)["verdict"],
                         "repeat")


class PlanVerifyTests(unittest.TestCase):
    def test_verify_plan_states(self):
        plan = {"steps": [{"n": 1, "tool": "a", "verify": [{"path": "ok", "eq": True}]},
                          {"n": 2, "tool": "b", "verify": [{"path": "ok", "eq": True}]}]}
        result = verifier.verify_plan(plan, [
            {"n": 1, "observation": {"ok": True}},
            {"n": 2, "observation": {"ok": True}},
        ])
        self.assertEqual(result["state"], "verified")
        self.assertEqual(result["passed"], 2)

    def test_verify_plan_partial(self):
        plan = {"steps": [{"n": 1, "tool": "a", "verify": [{"path": "ok", "eq": True}]},
                          {"n": 2, "tool": "b", "verify": [{"path": "ok", "eq": True}]}]}
        result = verifier.verify_plan(plan, [
            {"n": 1, "observation": {"ok": True}},
            {"n": 2, "observation": {"ok": False}},
        ])
        self.assertEqual(result["state"], "partial")

    def test_missing_step_repeats(self):
        plan = {"steps": [{"n": 1, "tool": "a", "verify": [{"path": "ok", "eq": True}]}]}
        result = verifier.verify_plan(plan, [])
        self.assertEqual(result["state"], "blocked")

    def test_summary(self):
        self.assertIn("changed", verifier.summary()["checks"])


if __name__ == "__main__":
    unittest.main()
