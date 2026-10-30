import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import chains


class ChainTests(unittest.TestCase):
    def test_library_is_parseable(self):
        items = chains.chains()
        self.assertGreaterEqual(len(items), 10)
        ids = [item["id"] for item in items]
        self.assertEqual(len(ids), len(set(ids)))
        for item in items:
            self.assertTrue(item["steps"])
            self.assertTrue(item["proof"])
            self.assertTrue(item["sources"])
            self.assertIn(item["impact"], {"critical", "high", "medium", "low"})

    def test_search_and_plan(self):
        found = chains.search(tag="oauth")
        self.assertTrue(found["items"])
        self.assertTrue(all("oauth" in item["tags"] for item in found["items"]))
        plan = chains.plan(None, target="https://app.example", signals=["graphql"])
        self.assertIn("graphql-gid-pii", [item["id"] for item in plan["items"]])
        fallback = chains.plan(None, target="https://unknown.example", limit=2)
        self.assertTrue(fallback["items"])
        self.assertEqual(len(fallback["items"]), 2)

    def test_sources(self):
        summary = chains.sources()
        self.assertEqual(summary["total"], len(chains.chains()))
        self.assertTrue(summary["by_impact"])


if __name__ == "__main__":
    unittest.main()
