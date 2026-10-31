import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import feedwatch
from netcast3r.server.index import Index


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "index.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_sources_are_curated_and_unique(self):
        items = feedwatch.sources()
        self.assertGreaterEqual(len(items), 6)
        ids = [item["id"] for item in items]
        self.assertEqual(len(ids), len(set(ids)))
        for item in items:
            self.assertTrue(item["url"].startswith("https://"))

    def test_parse_rss_and_atom(self):
        rss = """<rss><channel><item>
          <title>Critical bug</title><link>https://example.com/a</link>
          <pubDate>Mon, 01 Jan 2026 00:00:00 GMT</pubDate>
          <description>&lt;p&gt;Details&lt;/p&gt;</description>
        </item></channel></rss>"""
        parsed = feedwatch.parse_rss(rss)
        self.assertEqual(parsed[0]["title"], "Critical bug")
        self.assertEqual(parsed[0]["url"], "https://example.com/a")
        atom = """<feed xmlns="http://www.w3.org/2005/Atom"><entry>
          <title>Atom bug</title><link href="https://example.com/b"/>
          <updated>2026-01-01T00:00:00Z</updated>
          <summary>Summary</summary>
        </entry></feed>"""
        parsed = feedwatch.parse_rss(atom)
        self.assertEqual(parsed[0]["url"], "https://example.com/b")

    def test_parse_kev(self):
        payload = '{"vulnerabilities":[{"cveID":"CVE-2026-0001","vulnerabilityName":"Example","dateAdded":"2026-01-01","shortDescription":"Exploited"}]}'
        parsed = feedwatch.parse_kev(payload)
        self.assertEqual(parsed[0]["title"], "CVE-2026-0001 - Example")
        self.assertIn("CVE-2026-0001", parsed[0]["url"])

    def test_index_deduplicates_by_url(self):
        first = self.index.add_knowledge_item(
            "msrc", "One", "https://example.com/a", summary="x", tags=["msrc"])
        second = self.index.add_knowledge_item(
            "msrc", "One again", "https://example.com/a", summary="y")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(self.index.list_knowledge()), 1)
        self.index.mark_knowledge(first["id"], "read")
        self.assertEqual(self.index.get_knowledge(first["id"])["status"], "read")

    def test_refresh_fetches_concurrently_and_survives_a_dead_feed(self):
        import threading
        import time

        original = feedwatch._fetch
        state = {"current": 0, "peak": 0, "calls": []}
        lock = threading.Lock()

        def fake_fetch(url, timeout=feedwatch.FEED_TIMEOUT):
            with lock:
                state["calls"].append(url)
                state["current"] += 1
                state["peak"] = max(state["peak"], state["current"])
            time.sleep(0.05)
            with lock:
                state["current"] -= 1
            if "github" in url:
                raise RuntimeError("feed down")
            if "cisa.gov" in url:
                return ('{"vulnerabilities":[{"cveID":"CVE-2026-0001",'
                        '"vulnerabilityName":"Example","dateAdded":"2026-01-01",'
                        '"shortDescription":"Exploited"}]}')
            return ("<rss><channel><item><title>Item</title>"
                    f"<link>{url}/item</link></item></channel></rss>")

        feedwatch._fetch = fake_fetch
        try:
            result = feedwatch.refresh(self.index, limit=3)
        finally:
            feedwatch._fetch = original

        total = len(feedwatch.sources())
        self.assertEqual(len(state["calls"]), total)
        # Sequential fetching could never overlap; a pool must.
        self.assertGreater(state["peak"], 1)
        self.assertEqual([err["source"] for err in result["errors"]],
                         ["github-advisories"])
        self.assertEqual(len(result["items"]), total - 1)
        self.assertEqual(len(self.index.list_knowledge()), total - 1)


if __name__ == "__main__":
    unittest.main()
