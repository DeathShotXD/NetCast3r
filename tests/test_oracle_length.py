import unittest
from unittest import mock

from netcast3r.mcp import tools


class _Ctx:
    def __init__(self):
        self.limiter = tools.RateLimiter()


class LengthOracleTests(unittest.TestCase):
    def test_etag_length_extracts_one_character(self):
        from urllib.parse import unquote

        def fake_http_request(ctx, probe):
            decoded = unquote(probe["target"])
            expr = decoded.split("=")[-1]
            position = 1 if ",1," in decoded else 2
            if position == 1 and expr == str(ord("a")):
                return {"status": 200, "body": "match",
                        "headers": {"etag": "W/" + "0" * 40}}
            return {"status": 200, "body": "miss", "headers": {"etag": "W/aaa"}}

        args = {
            "target": "https://app.example.com/q?x={{expr}}",
            "true_when": "length", "length_field": "etag", "length_threshold": 20,
            "charset": "ab", "query": "secret", "max_length": 4,
        }
        with mock.patch.object(tools, "http_request", side_effect=fake_http_request):
            result = tools.oracle_extract(_Ctx(), args)
        self.assertEqual(result["value"], "a")
        self.assertEqual(result["true_when"], "length")
        self.assertEqual(result["length_field"], "etag")

    def test_length_requires_a_threshold(self):
        args = {"target": "https://a/b?x={{expr}}", "true_when": "length"}
        with self.assertRaises(tools.ToolError):
            tools.oracle_extract(_Ctx(), args)

    def test_unknown_oracle_is_refused(self):
        args = {"target": "https://a/b?x={{expr}}", "true_when": "vibes"}
        with self.assertRaises(tools.ToolError):
            tools.oracle_extract(_Ctx(), args)


if __name__ == "__main__":
    unittest.main()
