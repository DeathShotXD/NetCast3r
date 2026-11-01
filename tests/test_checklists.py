import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import checklists
from netcast3r.server import build_server


class CatalogTests(unittest.TestCase):
    def test_ids_are_unique_and_every_framework_is_present(self):
        items = checklists.catalog()
        ids = [item["id"] for item in items]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(items), 80)
        frameworks = {item["framework"] for item in items}
        for name in ("WSTG", "API Top 10", "LLM Top 10", "2025 Research",
                     "Cloud", "MASVS"):
            self.assertIn(name, frameworks)

    def test_every_module_reference_exists(self):
        from netcast3r import exploits

        known = {module["id"] for module in exploits.catalog()}
        missing = {module for item in checklists.catalog()
                   for module in item["modules"] if module not in known}
        self.assertEqual(missing, set())

    def test_next_items_puts_critical_first(self):
        items = checklists.next_items(None, "msn_missing", limit=5)
        self.assertEqual(len(items), 5)
        self.assertEqual(items[0]["severity"], "critical")


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Hunt", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])

    def tearDown(self):
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_default_summary_is_all_untested(self):
        summary = checklists.summary(self.index, self.mission["id"])
        self.assertEqual(summary["percent"], 0.0)
        self.assertEqual(summary["counts"]["untested"], summary["total"])
        self.assertEqual(summary["counts"]["covered"], 0)

    def test_marking_moves_the_percentage(self):
        checklists.mark(self.index, self.mission["id"], "wstg-authz-01",
                        "covered", evidence="two-account matrix run")
        checklists.mark(self.index, self.mission["id"], "wstg-inpv-09",
                        "vulnerable", evidence="OAST hit from the image fetcher")
        summary = checklists.summary(self.index, self.mission["id"])
        self.assertEqual(summary["counts"]["covered"], 1)
        self.assertEqual(summary["counts"]["vulnerable"], 1)
        self.assertGreater(summary["percent"], 0)
        ids = [item["id"] for item in checklists.next_items(
            self.index, self.mission["id"], limit=100)]
        self.assertNotIn("wstg-authz-01", ids)
        self.assertNotIn("wstg-inpv-09", ids)

    def test_an_unknown_item_is_refused(self):
        with self.assertRaises(ValueError):
            checklists.mark(self.index, self.mission["id"], "nope", "covered")
        with self.assertRaises(ValueError):
            checklists.mark(self.index, self.mission["id"], "wstg-authz-01", "done")

    def test_a_module_run_moves_its_items(self):
        written = checklists.record_module_run(
            self.index, self.mission["id"], "server-ssrf-metadata",
            {"candidate": {"id": "cand_1", "title": "blind SSRF"},
             "supports": 1, "blocked": 0})
        self.assertTrue(written)
        rows = {row["item_id"]: row for row in
                self.index.list_coverage(self.mission["id"])}
        self.assertEqual(rows["wstg-inpv-09"]["status"], "vulnerable")
        self.assertIn("cand_1", rows["wstg-inpv-09"]["evidence"])

    def test_a_clean_run_covers(self):
        checklists.record_module_run(
            self.index, self.mission["id"], "web-cors",
            {"candidate": {}, "supports": 0, "blocked": 0})
        rows = {row["item_id"]: row for row in
                self.index.list_coverage(self.mission["id"])}
        self.assertEqual(rows["wstg-conf-03"]["status"], "covered")

    def test_a_hunt_run_covers_recon_items(self):
        checklists.record_hunt_run(
            self.index, self.mission["id"],
            {"endpoints": 118, "pages": 4, "js_files": 5, "candidates": 2})
        rows = {row["item_id"]: row for row in
                self.index.list_coverage(self.mission["id"])}
        self.assertEqual(rows["wstg-info-02"]["status"], "covered")
        self.assertEqual(rows["wstg-info-03"]["status"], "covered")
        # A secret candidate leaves the JavaScript item in progress, not closed.
        self.assertEqual(rows["wstg-cli-04"]["status"], "in_progress")
        self.assertGreater(
            checklists.summary(self.index, self.mission["id"])["percent"], 0)

    def test_routes(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        catalog = self.server.route("GET", "/api/v1/checklists", {}, headers, b"")
        self.assertEqual(catalog.status, 200)
        self.assertGreater(len(json.loads(catalog.body.decode())["items"]), 80)

        got = self.server.route(
            "GET", f"/api/v1/missions/{self.mission['id']}/coverage", {},
            headers, b"")
        self.assertEqual(got.status, 200)
        payload = json.loads(got.body.decode())
        self.assertIn("percent", payload)
        self.assertIn("next", payload)

        marked = self.server.route(
            "POST", f"/api/v1/missions/{self.mission['id']}/coverage", {},
            headers,
            json.dumps({"item_id": "api-01", "status": "in_progress",
                        "evidence": "matrix queued"}).encode())
        self.assertEqual(marked.status, 201)
        rows = {row["item_id"]: row for row in
                self.index.list_coverage(self.mission["id"])}
        self.assertEqual(rows["api-01"]["status"], "in_progress")


if __name__ == "__main__":
    unittest.main()
