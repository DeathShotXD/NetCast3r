import unittest

from netcast3r import ormleak


class PayloadTests(unittest.TestCase):
    def test_payloads_cover_frameworks(self):
        rows = ormleak.payloads("title")
        params = [key for row in rows for key in row["params"]]
        self.assertIn("title__contains", params)
        self.assertIn("title[contains]", params)
        self.assertIn("$filter", params)
        self.assertTrue(any("__user__username" in key for key in params))

    def test_payloads_are_deduplicated(self):
        rows = ormleak.payloads("title")
        seen = [(row["kind"], tuple(sorted(row["params"].items()))) for row in rows]
        self.assertEqual(len(seen), len(set(seen)))


class ProbeTests(unittest.TestCase):
    def test_error_and_length_signals(self):
        def fetch(url):
            if "title__contains" in url:
                return {"status": 200, "body": "ok" + "x" * 40, "headers": {}}
            if "title__gt" in url:
                return {"status": 500, "body": "FieldError: invalid lookup",
                        "headers": {}}
            return {"status": 200, "body": "ok", "headers": {}}

        rows = [
            {"kind": "django", "params": {"title__contains": "nc3r"}},
            {"kind": "django", "params": {"title__gt": "nc3r"}},
            {"kind": "django", "params": {"title__isnull": ""}},
        ]
        result = ormleak.probe("https://app.example.com/search", "title",
                               fetch=fetch, payload_list=rows)
        verdicts = {(row["kind"]) : row["verdict"] for row in result["results"]}
        by_param = {list(row["params"])[0]: row["verdict"]
                    for row in result["results"]}
        self.assertEqual(by_param["title__contains"], "length_signal")
        self.assertEqual(by_param["title__gt"], "error_leak")
        self.assertEqual(by_param["title__isnull"], "no_signal")
        self.assertEqual(result["counts"]["error_leak"], 1)
        self.assertTrue(verdicts)

    def test_findings_rank_error_first(self):
        def fetch(url):
            if "gt" in url.split("?")[-1]:
                return {"status": 500, "body": "FieldError", "headers": {}}
            if "contains" in url:
                return {"status": 200, "body": "o" * 100, "headers": {}}
            return {"status": 200, "body": "ok", "headers": {}}
        result = ormleak.probe("https://app.example.com/s", "title", fetch=fetch,
                               payload_list=[
                                   {"kind": "django", "params": {"title__contains": "x"}},
                                   {"kind": "django", "params": {"title__gt": "x"}}])
        found = ormleak.findings(result)
        self.assertEqual(found[0]["severity"], "high")
        self.assertEqual(len(found), 2)

    def test_summary(self):
        self.assertIn("django", ormleak.summary()["operators"])


if __name__ == "__main__":
    unittest.main()
