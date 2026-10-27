import json
import tempfile
import unittest
from pathlib import Path

from netcast3r.report import public_finding, redact, render, save_sarif

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
STRIPE_KEY = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"


class RedactTests(unittest.TestCase):
    def test_short_value_masked(self):
        self.assertEqual(redact("abcd"), "ab**")

    def test_two_char_value_is_hidden(self):
        self.assertEqual(redact("ab"), "**")

    def test_long_value_keeps_edges(self):
        result = redact(AWS_KEY)
        self.assertTrue(result.startswith("AKIAIO"))
        self.assertTrue(result.endswith("MPLE"))
        self.assertIn("...", result)

    def test_proof_is_scrubbed_of_the_secret(self):
        secret = "SECRETVAL123456"
        findings = [{
            "title": "t", "severity": "high", "secret_type": "x", "value": secret,
            "source": "s", "status": "verified", "impact": "i",
            "proof": f"GET /me -> {secret} accepted",
            "reproduction": [f"curl -H 'auth: {secret}'"],
        }]
        text = render("target", {}, findings)
        self.assertNotIn(secret, text)

    def test_a_fence_in_the_proof_cannot_break_out(self):
        findings = [{
            "title": "t", "severity": "high", "secret_type": "x", "value": "v",
            "proof": "```\n# INJECTED\n```",
        }]
        text = render("target", {}, findings)
        self.assertIn("````", text)

    def test_report_scrubs_a_paired_credential_from_proof_text(self):
        pair = "SuperSecretPair"
        findings = [{
            "title": "t", "severity": "high", "secret_type": "database_url",
            "value": f"postgresql://app:{pair}@db.internal/app",
            "pair_value": pair, "proof": f"login with {pair} succeeded",
        }]
        text = render("target", {}, findings)
        self.assertNotIn(pair, text)

    def test_public_finding_redacts_both_halves_of_a_pair(self):
        secret = "postgresql://app:SuperSecretPair@db.internal/app"
        pair = "SuperSecretPair"
        public = public_finding({
            "value": secret, "pair_value": pair,
            "proof": f"psql {secret}",
            "corroboration": {"verdicts": [{"reason": f"used {pair}"}]},
        })
        blob = json.dumps(public)
        self.assertNotIn(secret, blob)
        self.assertNotIn(pair, blob)
        self.assertIn("...", public["value"])
        self.assertIn("...", public["pair_value"])


class RenderTests(unittest.TestCase):
    def test_report_has_sections_and_redacts(self):
        findings = [{
            "title": "Stripe credential exposed in client JavaScript",
            "severity": "critical",
            "secret_type": "stripe_live",
            "value": STRIPE_KEY,
            "source": "https://target/app.js",
            "status": "verified (HTTP 200)",
            "impact": "live key shipped to clients",
            "proof": '{"charges": []}',
            "reproduction": ["GET /v1/account"],
        }]
        text = render("https://target", {"pages": 1, "verified": 1}, findings, ["https://evil/x"])
        self.assertIn("# NetCast3r report", text)
        self.assertIn("## Confirmed findings", text)
        self.assertIn("## Out of scope skipped", text)
        self.assertIn("sk_liv...uvwx", text)
        self.assertNotIn(STRIPE_KEY, text)

    def test_code_review_evidence_is_scrubbed_of_findings(self):
        findings = [{
            "title": "Stripe credential exposed", "severity": "critical",
            "secret_type": "stripe_live", "value": STRIPE_KEY,
            "proof": "ok", "reproduction": [],
        }]
        review = {
            "loopholes": [{"detail": "key in the bundle", "severity": "high",
                           "evidence": f"var k = '{STRIPE_KEY}'",
                           "source": "https://target/app.js"}],
            "endpoints": [{"path": f"/api/keys?token={STRIPE_KEY}", "method": "get",
                           "note": f"uses {STRIPE_KEY}"}],
        }
        text = render("https://target", {"pages": 1}, findings, review=review)
        self.assertNotIn(STRIPE_KEY, text)
        self.assertIn("var k = ", text)
        self.assertIn("key in the bundle", text)

    def test_unconfirmed_and_code_review_sections(self):
        unverified = [{
            "type": "aws_secret_access_key", "value": AWS_KEY,
            "source": "https://target/app.js", "severity": "critical",
            "detail": "request failed: ConnectError",
            "steps": ["aws sts get-caller-identity --output json"],
        }]
        review = {
            "loopholes": [{"detail": "token in client bundle", "severity": "high",
                           "evidence": "var k='...'", "source": "https://target/app.js"}],
            "endpoints": [{"path": "/api/users", "method": "get", "note": "no auth",
                           "source": "https://target/app.js"}],
        }
        text = render("https://target", {"pages": 1}, [], unverified=unverified, review=review)
        self.assertIn("## High and critical candidates (not confirmed)", text)
        self.assertIn("## Code review", text)
        self.assertIn("aws sts get-caller-identity", text)
        self.assertIn("token in client bundle", text)
        self.assertIn("GET /api/users", text)
        self.assertNotIn(AWS_KEY, text)

    def test_sarif_output(self):
        findings = [{
            "title": "Stripe credential exposed",
            "severity": "critical",
            "secret_type": "stripe_live",
            "source": "https://target/app.js",
        }]
        workdir = Path(tempfile.mkdtemp())
        path = save_sarif(workdir, findings)
        document = json.loads(path.read_text())
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(document["runs"][0]["results"][0]["ruleId"], "stripe_live")
        self.assertEqual(document["runs"][0]["results"][0]["level"], "error")

    def test_sarif_scrubs_a_paired_credential_from_title_and_source(self):
        pair = "SuperSecretPair"
        findings = [{
            "title": f"leaked {pair}", "severity": "high", "secret_type": "db",
            "value": f"postgresql://app:{pair}@db/app",
            "pair_value": pair, "source": f"https://target/{pair}.txt",
        }]
        workdir = Path(tempfile.mkdtemp())
        path = save_sarif(workdir, findings)
        self.assertNotIn(pair, path.read_text())


if __name__ == "__main__":
    unittest.main()
