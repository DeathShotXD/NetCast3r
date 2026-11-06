import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import verdicts
from netcast3r.investigations import evidence, render_markdown
from netcast3r.server import build_server


def call(tool="http_request", status=200, body="", headers=None,
         target="https://example.com/api/auth/callback", error="",
         row_status="ok"):
    return {
        "id": "tcl_test",
        "tool": tool,
        "status": row_status,
        "error": error,
        "created_at": "2026-11-02T18:22:36Z",
        "args": {"target": target},
        "result": {"status": status, "url": target, "body": body,
                   "headers": headers or {}},
    }


class SsrfVerdictTests(unittest.TestCase):
    def test_a_metadata_body_is_the_only_thing_that_proves_ssrf(self):
        verdict = verdicts.classify_ssrf([
            call(status=200, body="ami-id\ninstance-id\ni-1234"),
        ])
        self.assertEqual(verdict["verdict"], "supported")
        self.assertTrue(verdict["proves_technique"])

    def test_signals_prove_a_metadata_body_after_the_body_is_redacted(self):
        row = call(status=200, body="[redacted]")
        row["result"]["signals"] = {"metadata_marker": "aws:ami-id",
                                    "body_sha256": "a" * 64, "body_len": 120}
        verdict = verdicts.classify_ssrf([row])
        self.assertEqual(verdict["verdict"], "supported")
        self.assertTrue(verdict["proves_technique"])

    def test_a_refusal_without_edge_evidence_is_blocked_not_edge_blocked(self):
        # The stored body and headers are redacted, so the harness cannot
        # claim which layer refused the request.
        verdict = verdicts.classify_ssrf([
            call(status=403, body="[redacted]"),
            call(status=403, body="[redacted]"),
        ])
        self.assertEqual(verdict["verdict"], "blocked")
        self.assertFalse(verdict["proves_technique"])

    def test_non_http_rows_are_not_probes(self):
        verdict = verdicts.classify_ssrf([
            call(tool="kb_corpus", status=0, body="ssrf metadata notes"),
        ])
        self.assertEqual(verdict["verdict"], "untested")

    def test_a_cloudflare_403_is_blocked_not_refuted(self):
        verdict = verdicts.classify_ssrf([
            call(status=403, body="<html>error</html>",
                 headers={"cf-ray": "abc123", "server": "cloudflare"}),
            call(status=403, body="<html>error</html>",
                 headers={"server": "cloudflare"}),
        ])
        self.assertEqual(verdict["verdict"], "edge-blocked")
        self.assertFalse(verdict["proves_technique"])
        self.assertIn("blocked", verdict["next_step"].lower())

    def test_a_redirect_to_an_external_host_is_an_open_redirect_not_ssrf(self):
        verdict = verdicts.classify_ssrf([
            call(status=301, headers={"location": "https://example.org/test"}),
        ])
        self.assertEqual(verdict["verdict"], "redirect-only")
        self.assertFalse(verdict["proves_technique"])
        self.assertEqual(verdict["related_technique"], "open-redirect")

    def test_a_transport_error_is_inconclusive(self):
        verdict = verdicts.classify_ssrf([
            call(status=0, error="ReadTimeout", row_status="error"),
        ])
        self.assertEqual(verdict["verdict"], "inconclusive")
        self.assertFalse(verdict["proves_technique"])

    def test_a_string_error_status_does_not_crash_the_classifier(self):
        # A failed call records result.status as the string "error".
        row = call(status=0, error="ConnectError", row_status="error")
        row["result"]["status"] = "error"
        verdict = verdicts.classify_ssrf([row])
        self.assertEqual(verdict["verdict"], "inconclusive")
        self.assertEqual(verdict["probes"][0]["status"], 0)

    def test_null_bytes_do_not_break_classification(self):
        row = call(status=403, headers={"server": "cloudflare"})
        row["args"] = {"target": "https://example.com/\x00"}
        row["result"]["body"] = "bad\x00body"
        verdict = verdicts.classify_ssrf([row])
        self.assertEqual(verdict["verdict"], "edge-blocked")

    def test_no_probe_is_untested(self):
        verdict = verdicts.classify_ssrf([])
        self.assertEqual(verdict["verdict"], "untested")
        self.assertFalse(verdict["proves_technique"])

    def test_an_unrelated_technique_has_no_classifier(self):
        self.assertIsNone(verdicts.classify(
            {"technique": "xss", "title": "Reflected XSS"}, []))


class OpenRedirectVerdictTests(unittest.TestCase):
    def test_an_external_location_is_proven_behaviour(self):
        verdict = verdicts.classify_open_redirect([
            call(status=301, headers={"location": "https://example.org/next"}),
        ])
        self.assertEqual(verdict["verdict"], "proven")
        self.assertTrue(verdict["proves_technique"])
        self.assertIn("chain", verdict["reportability"])

    def test_an_internal_redirect_is_not_proven(self):
        verdict = verdicts.classify_open_redirect([
            call(status=302, headers={"location": "/en/"}),
        ])
        self.assertEqual(verdict["verdict"], "inconclusive")
        self.assertFalse(verdict["proves_technique"])


class EvidenceVerdictTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Verdict mission", "example.com", status="active",
            autonomy="autonomous", scope=["example.com"])

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_evidence_carries_a_verdict_and_the_case_file_renders_it(self):
        lead = self.index.create_hypothesis(
            "SSRF through the fetcher", target="https://example.com/fetch",
            mission_id=self.mission["id"], technique="ssrf",
            rationale="url parameter", expected="metadata body")
        self.index.add_tool_call(
            "http_request", risk="medium", status="ok", actor="agent:swarm",
            mission_id=self.mission["id"],
            args={"target": "https://example.com/fetch?url=http://169.254.169.254/"},
            result={"status": 403, "headers": {"server": "cloudflare"},
                    "body": "blocked"})
        record = evidence(self.index, lead["id"])
        self.assertIsNotNone(record["verdict"])
        self.assertEqual(record["verdict"]["verdict"], "edge-blocked")
        text = render_markdown(record)
        self.assertIn("## Verdict", text)
        self.assertIn("edge-blocked", text)

    def test_evidence_without_verdict_still_renders(self):
        lead = self.index.create_hypothesis(
            "Reflected XSS in search", target="https://example.com/search",
            mission_id=self.mission["id"], technique="xss",
            rationale="reflected marker", expected="execution")
        record = evidence(self.index, lead["id"])
        self.assertIsNone(record["verdict"])
        self.assertIn("Reflected XSS", render_markdown(record))


if __name__ == "__main__":
    unittest.main()
