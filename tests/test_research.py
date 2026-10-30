import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import research
from netcast3r.server.index import Index


class ResearchLibraryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "index.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_catalogue_is_parseable_and_sourced(self):
        items = research.techniques()
        self.assertGreaterEqual(len(items), 30)
        ids = [item["id"] for item in items]
        self.assertEqual(len(ids), len(set(ids)))
        for item in items:
            self.assertTrue(item["title"])
            self.assertTrue(item["steps"])
            self.assertTrue(item["proof"])
            self.assertTrue(item["sources"])
            for url in item["sources"]:
                self.assertTrue(url.startswith("https://"))
            self.assertIn(item["impact"], {"critical", "high", "medium", "low"})
            self.assertIn(item["rarity"], {"rare", "uncommon", "common"})

    def test_search_filters_and_sources(self):
        found = research.search(tag="orm")
        self.assertTrue(found["items"])
        self.assertTrue(all("orm" in item["tags"] for item in found["items"]))
        rare = research.search(rarity="rare", limit=100)
        self.assertTrue(all(item["rarity"] == "rare" for item in rare["items"]))
        summary = research.sources()
        self.assertEqual(summary["total"], len(research.techniques()))
        self.assertTrue(summary["by_class"])

    def test_plan_matches_fingerprint(self):
        nextjs = research.plan(self.index, target="https://app.example.com",
                               tech="nextjs", limit=5)
        self.assertEqual(nextjs["items"][0]["id"], "nextjs-cache-poison")
        self.assertTrue(any("nextjs" in why for why in nextjs["items"][0]["why"]))
        graphql = research.plan(self.index, tech="graphql", limit=5)
        self.assertIn("graphql-gid-authz",
                      [item["id"] for item in graphql["items"]])
        identity = research.plan(self.index, signals=["oauth", "sso"], limit=5)
        self.assertTrue(any("oauth" in item["id"] for item in identity["items"]))
        empty = research.plan(self.index, limit=3)
        self.assertEqual(len(empty["items"]), 3)
        self.assertGreaterEqual(empty["items"][0]["score"], empty["items"][1]["score"])

    def test_hunt_plan_combines_mission_and_techniques(self):
        mission = self.index.create_mission(
            "Example hunt", "https://app.example.com", scope=["app.example.com"])
        plan = research.hunt_plan(self.index, mission["id"], tech="nextjs", limit=4)
        self.assertEqual(plan["mission_id"], mission["id"])
        self.assertEqual(plan["phases"][0]["phase"], "scope")
        self.assertEqual(plan["techniques"][0]["id"], "nextjs-cache-poison")
        phases = [item["phase"] for item in plan["phases"]]
        self.assertIn("technique-tests", phases)
        self.assertIn("evidence", phases)
        with self.assertRaises(ValueError):
            research.hunt_plan(self.index, "msn_missing")

    def test_ingest_stores_a_sourced_skill(self):
        with self.assertRaises(ValueError):
            research.ingest(self.index, "not-a-url", "A useful title", "x" * 100)
        with self.assertRaises(ValueError):
            research.ingest(self.index, "https://example.com/post",
                            "A useful title", "too short")
        result = research.ingest(
            self.index, "https://example.com/post",
            "Parser differential in a SAML library",
            "Validation and signature verification used different XML parsers. "
            "A namespace change made the verifier read one assertion while the "
            "application consumed another. The fix is to canonicalise and verify "
            "the exact node that is consumed, not a re-parsed copy.",
            tags=["saml", "parser"])
        skill = self.index.get_skill(result["name"])
        self.assertIsNotNone(skill)
        self.assertEqual(skill["source"], "https://example.com/post")
        self.assertIn("saml", skill["tags"])
        self.assertIn("research", skill["tags"])


if __name__ == "__main__":
    unittest.main()
