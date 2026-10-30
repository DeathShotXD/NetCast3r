import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import surface
from netcast3r.server.index import Index
from netcast3r.store import Store


class SurfaceDiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "index.db")
        self.base_dir = Path(self.tmp.name) / "results-a"
        self.new_dir = Path(self.tmp.name) / "results-b"
        self.base_dir.mkdir()
        self.new_dir.mkdir()
        self.base = Store(self.base_dir / "netcast3r.db")
        self.new = Store(self.new_dir / "netcast3r.db")
        self.base.add_endpoint("https://example.com/api/v1", "js")
        self.base.add_endpoint("https://example.com/old", "js")
        self.base.add_subdomain("old.example.com")
        self.new.add_endpoint("https://example.com/api/v1", "js")
        self.new.add_endpoint("https://example.com/api/v2", "js")
        self.new.add_subdomain("new.example.com")
        self.run_a = self.index.create_run(
            "example.com", results_dir=str(self.base_dir))
        self.run_b = self.index.create_run(
            "example.com", results_dir=str(self.new_dir))

    def tearDown(self):
        self.base.close()
        self.new.close()
        self.index.close()
        self.tmp.cleanup()

    def test_added_and_removed_items(self):
        result = surface.diff(self.index, self.run_a["id"], self.run_b["id"])
        self.assertEqual(result["counts"]["endpoints"]["added"], 1)
        self.assertEqual(result["counts"]["endpoints"]["removed"], 1)
        self.assertEqual(result["added"]["endpoints"], ["https://example.com/api/v2"])
        self.assertEqual(result["removed"]["endpoints"], ["https://example.com/old"])
        self.assertEqual(result["added"]["subdomains"], ["new.example.com"])
        self.assertEqual(result["summary"]["new_endpoints"], 1)

    def test_missing_run_is_an_error(self):
        with self.assertRaises(ValueError):
            surface.diff(self.index, self.run_a["id"], "run_missing")


if __name__ == "__main__":
    unittest.main()
