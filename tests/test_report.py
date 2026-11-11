# codeaudit: ignore-file py-hardcoded-secret -- deliberate redaction fixtures
import json
import tempfile
import unittest
from pathlib import Path

from netcast3r.report import (public_finding, redact, render, render_finding_poc,
                              save_sarif)

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

    def test_sarif_accepts_a_generic_finding_with_a_line(self):
        findings = [{
            "title": "IDOR exposes another tenant invoice",
            "severity": "medium",
            "category": "idor",
            "source": "src/api/invoices.py",
            "line": 42,
            "confidence": 0.9,
            "module_id": "auth-idor",
        }]
        workdir = Path(tempfile.mkdtemp())
        path = save_sarif(workdir, findings)
        result = json.loads(path.read_text())["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "idor")
        self.assertEqual(result["level"], "warning")
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["region"]["startLine"], 42)
        self.assertEqual(result["properties"]["module_id"], "auth-idor")

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


class FindingPocTests(unittest.TestCase):
    def test_manual_evidence_keeps_its_lines_and_nests_its_headings(self):
        finding = {
            "id": "fnd_test", "title": "t", "severity": "critical",
            "secret_type": "sqli", "impact": "impact line",
            "source": "manual",
            "evidence": ("# Confirmed\n\n## Summary\nline one\nline two\n\n"
                         "```\nGET /x\n```"),
        }
        text = render_finding_poc(finding, mission={"target": "https://target/"})
        self.assertIn("### Confirmed", text)
        self.assertIn("#### Summary", text)
        self.assertIn("line one\nline two", text)
        self.assertEqual(text.count("line one"), 1)
        self.assertIn("## Affected asset\n\n`https://target/`", text)
        self.assertNotIn("### python", text)

    def test_recorded_request_keeps_the_python_replay(self):
        finding = {
            "id": "fnd_test", "title": "t", "severity": "high",
            "secret_type": "x", "evidence": "# proof",
            "evidence_chain": [{
                "kind": "tool_call", "tool": "http_request",
                "request": {"target": "https://target/a", "method": "GET"},
                "response": {"status": 500}, "at": "2026-01-01T00:00:00Z",
            }],
        }
        text = render_finding_poc(finding, mission={"target": "https://target/"})
        self.assertIn("### python", text)
        self.assertIn("requests.request('GET', 'https://target/a')", text)
        self.assertIn("assert response.status_code == 500", text)

    def test_evidence_fence_is_not_used_as_the_manual_curl(self):
        finding = {
            "id": "fnd_test", "title": "t", "severity": "low",
            "secret_type": "x",
            "evidence": "```\nGET /only-text\n```",
        }
        text = render_finding_poc(finding)
        self.assertIn("no structured request was recorded", text)


if __name__ == "__main__":
    unittest.main()
