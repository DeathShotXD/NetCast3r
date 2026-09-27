import unittest

from netcast3r.report import redact, render


class RedactTests(unittest.TestCase):
    def test_short_value_masked(self):
        self.assertEqual(redact("abcd"), "ab**")

    def test_long_value_keeps_edges(self):
        result = redact("AWS_KEY_PLACEHOLDER")
        self.assertTrue(result.startswith("AKIAIO"))
        self.assertTrue(result.endswith("MPLE"))
        self.assertIn("...", result)


class RenderTests(unittest.TestCase):
    def test_report_has_sections_and_redacts(self):
        findings = [{
            "title": "Stripe credential exposed in client JavaScript",
            "severity": "critical",
            "secret_type": "stripe_live",
            "value": "STRIPE_LIVE_PLACEHOLDER",
            "source": "https://target/app.js",
            "status": "verified (HTTP 200)",
            "impact": "live key shipped to clients",
            "proof": '{"charges": []}',
            "reproduction": ["GET /v1/account"],
        }]
        text = render("https://target", {"pages": 1, "verified": 1}, findings, ["https://evil/x"])
        self.assertIn("# NetCast3r report", text)
        self.assertIn("## Findings", text)
        self.assertIn("## Out of scope skipped", text)
        self.assertIn("sk_liv...uvwx", text)
        self.assertNotIn("STRIPE_LIVE_PLACEHOLDER", text)


if __name__ == "__main__":
    unittest.main()
