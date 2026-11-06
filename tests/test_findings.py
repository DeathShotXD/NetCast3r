import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server import build_server


class FindingMissionLinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Link", "https://example.com", status="active", scope=["example.com"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_a_promoted_hypothesis_carries_its_mission(self):
        hypothesis = self.index.create_hypothesis(
            "Path traversal", target="https://example.com/download",
            mission_id=self.mission["id"], technique="path-traversal",
            rationale="file parameter", expected="config body")
        self.index.patch_hypothesis(
            hypothesis["id"], status="supported",
            test={"steps": [{"url": "https://example.com/download"}]},
            result={"ok": True, "passed": 1, "failed": 0})
        finding = self.index.promote_hypothesis(
            hypothesis["id"], title="Traversal", severity="critical",
            impact="Attacker reads files.", evidence="x" * 64)
        self.assertEqual(finding["mission_id"], self.mission["id"])
        mission = self.index.get_mission(self.mission["id"])
        self.assertEqual(mission["finding_count"], 1)
        items, total = self.index.list_findings(mission_id=self.mission["id"])
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["id"], finding["id"])

    def test_a_direct_finding_records_the_mission(self):
        finding = self.index.create_finding(
            title="Direct", severity="high", mission_id=self.mission["id"],
            impact="Attacker gain.", evidence="y" * 64)
        self.assertEqual(finding["mission_id"], self.mission["id"])
        mission = self.index.get_mission(self.mission["id"])
        self.assertEqual(mission["finding_count"], 1)

    def test_an_unknown_mission_is_refused(self):
        with self.assertRaises(ValueError):
            self.index.create_finding(
                title="Bad", severity="high", mission_id="msn_missing",
                impact="Attacker gain.", evidence="z" * 64)


if __name__ == "__main__":
    unittest.main()
