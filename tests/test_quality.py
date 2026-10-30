import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import quality
from netcast3r.server.index import Index


class QualityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "netcast3r.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_score_rises_with_evidence_and_detail(self):
        finding = self.index.create_finding("x", "high")
        low = quality.score_finding(self.index, finding["id"])
        self.assertLess(low["score"], 55)
        self.assertTrue(low["missing"])

        detailed = self.index.create_finding(
            "SnapDeploy: deploy token bypasses the manage-scope check",
            "high",
            impact=("A deploy-scoped token reaches manage handlers through a percent-encoded "
                    "path, so the documented scope boundary is not enforced."),
            evidence=("POST /api/mobile/services/%61ddons returned 400 while the literal "
                      "path returned 403 INSUFFICIENT_SCOPE; see the attached log."),
            confidence=0.95, tags=["authz", "encoding"])
        self.index.add_finding_artifact(detailed["id"], "scope.log",
                                        b"POST /services/%61ddons -> 400\n", "text/plain")
        self.index.add_finding_artifact(detailed["id"], "control.log",
                                        b"POST /services/addons -> 403\n", "text/plain")
        high = quality.score_finding(self.index, detailed["id"])
        self.assertGreater(high["score"], low["score"])
        self.assertGreaterEqual(high["score"], 85)
        self.assertEqual(high["grade"], "A")
        self.assertEqual(high["artifacts"], 2)
        self.assertEqual(high["missing"], [])

    def test_unknown_finding_is_rejected(self):
        with self.assertRaises(ValueError):
            quality.score_finding(self.index, "fnd_missing")


class ProgramStatsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "netcast3r.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_payouts_are_grouped_without_conversion(self):
        self.index.create_submission("One", program="Acme", platform="hackerone",
                                     status="paid", bounty_cents=50000, currency="USD")
        self.index.create_submission("Two", program="Acme", platform="hackerone",
                                     status="accepted", bounty_cents=25000, currency="USD")
        self.index.create_submission("Three", program="Acme", platform="hackerone",
                                     status="rejected", currency="USD")
        self.index.create_submission("Four", program="Euro", platform="other",
                                     status="paid", bounty_cents=10000, currency="EUR")
        stats = quality.program_stats(self.index)
        acme = next(item for item in stats["items"] if item["program"] == "Acme")
        self.assertEqual(acme["submissions"], 3)
        self.assertEqual(acme["accepted"], 2)
        self.assertEqual(acme["paid"], 1)
        self.assertEqual(acme["bounty_cents"], 75000)
        self.assertEqual(acme["average_bounty_cents"], 37500)
        self.assertAlmostEqual(acme["acceptance_rate"], 0.667)
        euro = next(item for item in stats["items"] if item["program"] == "Euro")
        self.assertEqual(euro["currency"], "EUR")
        self.assertEqual(euro["bounty_cents"], 10000)


if __name__ == "__main__":
    unittest.main()
