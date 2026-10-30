import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import training
from netcast3r.mcp import tools
from netcast3r.server.index import Index


class TrainingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "index.db")
        self.labs = training.catalog()

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_catalogue_is_complete_and_parseable(self):
        self.assertGreaterEqual(len(self.labs), 250)
        slugs = [lab["slug"] for lab in self.labs]
        self.assertEqual(len(slugs), len(set(slugs)))
        for lab in self.labs[:20]:
            self.assertTrue(lab["slug"].startswith("lab-"))
            self.assertTrue(lab["title"])
            self.assertIn(lab["difficulty"], {"apprentice", "practitioner", "expert"})
            self.assertTrue(lab["url"].startswith("https://portswigger.net/web-security/"))
        self.assertGreaterEqual(
            len({lab.get("source") for lab in self.labs}), 4)

    def test_multi_source_catalogue_and_plan(self):
        sources = {item["source"] for item in training.sources(self.index)}
        self.assertIn("portswigger", sources)
        self.assertIn("acunetix-testphp", sources)
        self.assertIn("local-juice-shop", sources)
        item = training.plan(self.index, source="acunetix-testphp", limit=3)
        self.assertEqual(len(item["items"]), 3)
        self.assertTrue(all(entry["source"] == "acunetix-testphp"
                            for entry in item["items"]))
        self.assertTrue(all(entry["objective"] for entry in item["items"]))
        self.assertTrue(all(entry["proof"] for entry in item["items"]))
        mixed = training.plan(self.index, limit=8)["items"]
        self.assertEqual(len({entry["category"] for entry in mixed}), 8)

    def test_pack_record_keeps_its_source(self):
        lab = next(item for item in self.labs
                   if item.get("source") == "local-juice-shop")
        result = training.record(
            self.index, lab["slug"], "solved",
            instance_url="http://127.0.0.1:3000/#/search?q=test",
            evidence="The payload executed in the browser on the local range.",
            lesson="Traced the search value from the URL into an innerHTML sink "
                   "and proved execution in the managed browser.")
        self.assertEqual(result["progress"]["source"], "local-juice-shop")
        lesson = self.index.get_lesson(result["progress"]["lesson_id"])
        self.assertIn("Training exercise", lesson["title"])
        with self.assertRaises(ValueError):
            training.record(self.index, lab["slug"], "in_progress",
                            instance_url="https://example.com/")
        status = training.status(self.index, source="local-juice-shop")
        self.assertEqual(status["solved"], 1)
        self.assertEqual(status["source"], "local-juice-shop")

    def test_plan_rotates_categories_and_prefers_apprentice(self):
        result = training.plan(self.index, limit=6)
        items = result["items"]
        self.assertEqual(len(items), 6)
        self.assertEqual(len({item["category"] for item in items}), 6)
        self.assertTrue(all(item["status"] == "new" for item in items))
        first = training.plan(self.index, category="SQL injection", limit=1)["items"][0]
        self.assertEqual(first["category"], "SQL injection")
        self.assertEqual(first["difficulty"], "apprentice")

    def test_solved_record_requires_evidence_and_lesson(self):
        lab = next(item for item in self.labs if item["category"] == "SQL injection")
        with self.assertRaises(ValueError):
            training.record(self.index, lab["slug"], "solved")
        with self.assertRaises(ValueError):
            training.record(self.index, lab["slug"], "solved", evidence="Congratulations")
        result = training.record(
            self.index, lab["slug"], "solved",
            evidence="Congratulations, you solved the lab!",
            lesson="The category parameter was injectable in a string context; "
                   "a boolean OR changed the result set.",
            technique="UNION-less boolean injection")
        self.assertEqual(result["progress"]["status"], "solved")
        self.assertTrue(result["progress"]["lesson_id"])
        status = training.status(self.index)
        self.assertGreaterEqual(status["solved"], 1)
        self.assertEqual(status["by_category"]["SQL injection"]["solved"], 1)
        lesson = self.index.get_lesson(result["progress"]["lesson_id"])
        self.assertIn("PortSwigger lab solved", lesson["title"])
        expertise = {row["tech"]: row for row in self.index.list_expertise()}
        self.assertIn("sqli", expertise)

    def test_blocked_record_can_keep_a_lesson(self):
        lab = self.labs[0]
        result = training.record(
            self.index, lab["slug"], "blocked",
            lesson="The lab instance expired before the payload could be tested.",
            notes="Retry in a fresh instance.")
        self.assertEqual(result["progress"]["status"], "blocked")
        self.assertTrue(result["progress"]["lesson_id"])

    def test_toolbook_search_and_exact(self):
        found = training.toolbook(query="smuggling")
        self.assertTrue(any(item["name"] == "smuggler" for item in found["items"]))
        entry = training.toolbook(name="ffuf")
        self.assertEqual(entry["tool"]["name"], "ffuf")
        self.assertIn("scope", entry["note"].lower())

    def test_verify_rejects_non_academy_host(self):
        ctx = SimpleNamespace(base="/tmp", policy="supervised")
        with self.assertRaises(tools.ToolError):
            tools.training_verify(ctx, {"instance_url": "https://example.com/"})

    def test_verify_reads_academy_banner(self):
        ctx = SimpleNamespace(base="/tmp", policy="supervised")
        with mock.patch.object(tools, "http_request",
                               return_value={"status": 200,
                                             "body": "Congratulations, you solved the lab!"}):
            result = tools.training_verify(
                ctx, {"instance_url": "https://abc123.web-security-academy.net/"})
        self.assertTrue(result["solved"])
        self.assertIn("Congratulations", result["evidence"])


if __name__ == "__main__":
    unittest.main()
