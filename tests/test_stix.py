import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

import httpx

from netcast3r import stix
from netcast3r.server.index import Index


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "netcast3r.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_bundle_has_identity_vulnerability_and_report(self):
        finding = self.index.create_finding(
            "CVE-2025-12345 in Example gateway",
            "high",
            impact="An unauthenticated request reaches the admin handler.",
            evidence="POST /admin returned 200 from a zero-cookie context.",
            confidence=0.9, tags=["authz", "cve"])
        bundle = stix.export_bundle(self.index)
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        types = [item["type"] for item in bundle["objects"]]
        self.assertIn("identity", types)
        self.assertIn("report", types)
        self.assertIn("vulnerability", types)
        vulnerability = next(item for item in bundle["objects"]
                             if item["type"] == "vulnerability")
        self.assertEqual(vulnerability["x_netcast3r_finding_id"], finding["id"])
        self.assertEqual(vulnerability["external_references"][0]["external_id"],
                         "CVE-2025-12345")
        report = next(item for item in bundle["objects"] if item["type"] == "report")
        self.assertIn(vulnerability["id"], report["object_refs"])
        self.assertEqual(bundle["x_netcast3r_count"], 1)

    def test_severity_filter_and_empty_export(self):
        self.index.create_finding("Low note", "low")
        bundle = stix.export_bundle(self.index, severity="high")
        self.assertEqual(bundle["x_netcast3r_count"], 0)
        self.assertEqual([item["type"] for item in bundle["objects"]],
                         ["identity", "report"])


class TaxiiTests(unittest.TestCase):
    def _handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/taxii2/"):
            return httpx.Response(200, json={
                "title": "Test TAXII", "api_roots": ["https://taxii.example/api"],
                "default": "https://taxii.example/api"})
        if path.endswith("/collections/"):
            return httpx.Response(200, json={"collections": [{
                "id": "c1", "title": "Feed", "can_read": True, "can_write": False}]})
        if "/objects/" in path:
            return httpx.Response(200, json={"objects": [{
                "type": "indicator", "id": "indicator--x",
                "pattern": "[url:value = 'https://example.org']"}],
                "more": False})
        return httpx.Response(404)

    def test_discovery_collections_and_objects(self):
        transport = httpx.MockTransport(self._handler)
        client = stix.TaxiiClient("https://taxii.example/taxii2/", transport=transport)
        discovery = client.discovery()
        self.assertEqual(discovery["title"], "Test TAXII")
        collections = client.collections("https://taxii.example/api")
        self.assertEqual(collections[0]["id"], "c1")
        objects = client.objects("https://taxii.example/api", "c1", limit=10)
        self.assertEqual(objects["objects"][0]["type"], "indicator")

    def test_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "integrations.json"
            path.write_text(json.dumps({"taxii": {
                "url": "https://taxii.example/taxii2/", "token": "secret"}}))
            config = stix.load_taxii_config(tmp)
        self.assertTrue(config["configured"])
        self.assertEqual(config["url"], "https://taxii.example/taxii2")
        self.assertEqual(config["token"], "secret")


if __name__ == "__main__":
    unittest.main()
