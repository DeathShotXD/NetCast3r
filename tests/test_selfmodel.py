import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import learning, selfmodel, training
from netcast3r.server.index import Index


class SelfModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "index.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_seed_installs_bundled_skill_packs(self):
        added = learning.seed_builtin_skills(self.index)
        self.assertGreaterEqual(added, 17)
        skill = self.index.get_skill("sqli-advanced")
        self.assertIsNotNone(skill)
        self.assertEqual(skill["source"], "netcast3r:pack")
        self.assertIn("boolean pair", skill["body"])
        again = learning.seed_builtin_skills(self.index)
        self.assertEqual(again, 0)

    def test_snapshot_and_gaps_use_stored_records(self):
        lab = next(item for item in training.catalog()
                   if item["category"] == "SQL injection"
                   and item["source"] == "portswigger")
        training.record(
            self.index, lab["slug"], "solved",
            evidence="Congratulations, you solved the lab!",
            lesson="A quote and a boolean pair proved the category parameter was "
                   "concatenated into a SQL string.")
        learning.seed_builtin_skills(self.index)
        state = selfmodel.snapshot(self.index)
        self.assertGreaterEqual(state["counts"]["training_solved"], 1)
        injection = next(item for item in state["dimensions"]
                         if item["dimension"] == "injection")
        self.assertGreater(injection["score"], 0)
        self.assertIn("sqli-advanced", injection["skills"])
        self.assertIn(state["level"],
                      {"nascent", "developing", "competent", "advanced"})
        gaps = selfmodel.gaps(self.index, limit=3)
        self.assertTrue(gaps["items"])
        self.assertLessEqual(len(gaps["items"]), 3)
        self.assertTrue(all(item["action"] for item in gaps["items"]))

    def test_upgrade_proposals_are_human_gated(self):
        with self.assertRaises(ValueError):
            selfmodel.propose(self.index, "short", "rationale " * 4, "evidence")
        with self.assertRaises(ValueError):
            selfmodel.propose(self.index, "Improve cache testing",
                              "The pack has no cache exercise evidence yet",
                              "evidence", area="not-a-real-area")
        proposal = selfmodel.propose(
            self.index, "Add a cache-key differential drill",
            "The last three runs never tested an unkeyed header, which leaves "
            "cache poisoning unexercised.",
            "selfmodel gap: advanced score below 50; no cache lab solved",
            area="advanced", priority="high")
        self.assertEqual(proposal["status"], "proposed")
        updated = self.index.update_upgrade_proposal(
            proposal["id"], status="accepted", rationale="Scheduled for the next cycle")
        self.assertEqual(updated["status"], "accepted")
        items = self.index.list_upgrade_proposals(status="accepted")
        self.assertEqual([item["id"] for item in items], [proposal["id"]])


if __name__ == "__main__":
    unittest.main()
