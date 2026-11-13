import tempfile
import unittest
from pathlib import Path

from netcast3r import csp


class AnalyzeTests(unittest.TestCase):
    def test_template_literal_path_is_medium(self):
        source = "const r = await axios.get(`/api/items/${location.search}`);"
        result = csp.analyze(source, "app.js")
        self.assertEqual(len(result["findings"]), 1)
        row = result["findings"][0]
        self.assertIn("location.search", row["sources"])
        self.assertIn("axios", row["sinks"])
        self.assertTrue(row["builds_path"])
        self.assertEqual(row["severity"], "medium")

    def test_postmessage_traversal_is_high(self):
        source = "onmessage = (e) => fetch('/api/' + e.data + '/../../x');"
        result = csp.analyze(source, "worker.js")
        row = result["findings"][0]
        self.assertIn("postMessage data", row["sources"])
        self.assertEqual(row["severity"], "high")
        self.assertEqual(row["payload"], "../../")

    def test_plain_source_to_sink_is_low(self):
        result = csp.analyze("fetch(location.href);", "a.js")
        self.assertEqual(result["findings"][0]["severity"], "low")
        self.assertFalse(result["findings"][0]["builds_path"])

    def test_no_source_no_finding(self):
        result = csp.analyze("fetch('/api/static');", "a.js")
        self.assertEqual(result["findings"], [])

    def test_counts(self):
        source = ("fetch('/a/' + location.hash);\n"
                  "axios.get(`/b/${location.search}`);\n")
        result = csp.analyze(source, "a.js")
        self.assertEqual(result["counts"].get("medium", 0)
                         + result["counts"].get("low", 0), len(result["findings"]))


class ScanTests(unittest.TestCase):
    def test_scan_reads_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.js"
            path.write_text("fetch('/x/' + location.hash);", encoding="utf-8")
            result = csp.scan(str(path))
        self.assertEqual(result["file"], "bundle.js")
        self.assertEqual(len(result["findings"]), 1)

    def test_missing_file(self):
        result = csp.scan("/no/such/file.js")
        self.assertEqual(result["findings"], [])
        self.assertIn("error", result)

    def test_summary(self):
        self.assertIn("fetch", csp.summary()["sinks"])


if __name__ == "__main__":
    unittest.main()
