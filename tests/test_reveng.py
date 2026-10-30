# codeaudit: ignore-file py-pickle -- describes an input fixture, it never loads one
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import reveng


class SourceAnalysisTests(unittest.TestCase):
    def test_source_tree_reports_secret_endpoints_and_sinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(
                'const API = "https://api.internal.example.com/v1/users";\n'
                'const key = "AKIAIOSFODNN7EXAMPLE";\n'
                'function render(v) { el.innerHTML = v; }\n'
                'fetch("/api/v2/orders").then(r => r.json());\n')
            (root / "worker.py").write_text(
                "import pickle\n"
                "def load(raw):\n"
                "    return pickle.loads(raw)\n")
            result = reveng.analyze("source", str(root))
        titles = [item["title"] for item in result["observations"]]
        self.assertTrue(any("aws access key" in title for title in titles))
        self.assertTrue(any("html sink" in title for title in titles))
        self.assertTrue(any("pickle" in title for title in titles))
        urls = {item["url"] for item in result["endpoints"]}
        self.assertIn("https://api.internal.example.com/v1/users", urls)
        self.assertIn("/api/v2/orders", urls)
        self.assertEqual(result["summary"]["files"], 2)
        self.assertGreaterEqual(result["summary"]["severity"]["high"], 1)
        # Secret values are never returned in full.
        for secret in result["secrets"]:
            self.assertIn("...", secret["preview"])

    def test_single_javascript_file_uses_the_js_analyzer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.js"
            path.write_text(
                'fetch("https://api.example.com/v1/orders");\n'
                'const key = "AKIAIOSFODNN7EXAMPLE";\n'
                'el.innerHTML = location.hash;\n')
            result = reveng.analyze("auto", str(path))
        self.assertEqual(result["kind"], "js")
        self.assertTrue(result["endpoints"])
        self.assertTrue(result["secrets"])

    def test_placeholder_assignments_are_not_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.js").write_text(
                'const apiKey = "your_api_key_here";\n'
                'const password = process.env.PASSWORD;\n')
            result = reveng.analyze("source", str(root))
        self.assertEqual(result["secrets"], [])

    def test_rea_plan_adds_kind_specific_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.js"
            path.write_text('fetch("https://api.example.com/v1/orders");\n')
            result = reveng.rea_plan(str(path), goal="map the API")
        self.assertEqual(result["artifact"]["kind"], "js")
        self.assertEqual(result["goal"], "map the API")
        self.assertTrue(result["next_steps"])
        self.assertIn("gitleaks", result["tooling"])

    def test_missing_path_is_an_error(self):
        with self.assertRaises(ValueError):
            reveng.analyze("source", "/definitely/not/here")


class ContractAnalysisTests(unittest.TestCase):
    def test_contract_patterns_are_line_addressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Vault.sol").write_text(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.0;\n"
                "contract Vault {\n"
                "    function withdraw() external {\n"
                "        require(tx.origin == owner);\n"
                "        payable(msg.sender).transfer(address(this).balance);\n"
                "    }\n"
                "    function kill() external { selfdestruct(payable(msg.sender)); }\n"
                "}\n")
            result = reveng.analyze("contract", str(root))
        titles = [item["title"] for item in result["observations"]]
        self.assertTrue(any("tx origin" in title for title in titles))
        self.assertTrue(any("selfdestruct" in title for title in titles))
        tx = next(item for item in result["observations"] if "tx origin" in item["title"])
        self.assertEqual(tx["line"], 5)
        self.assertEqual(tx["severity"], "high")


class BinaryAnalysisTests(unittest.TestCase):
    def test_pe_strings_and_kernel_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "driver.sys"
            blob = (b"MZ" + b"\x00" * 64
                    + b"https://api.example.com/v1/ping\x00"
                    + b"IoCreateDevice\x00MmMapIoSpace\x00"
                    + b"AKIAIOSFODNN7EXAMPLE\x00"
                    + b"IOCTL_KILL_PROCESS\x00")
            path.write_bytes(blob)
            result = reveng.analyze("binary", str(path))
        self.assertEqual(result["summary"]["format"], "PE")
        names = [item["title"] for item in result["observations"]]
        self.assertTrue(any("IoCreateDevice" in name for name in names))
        self.assertTrue(any("aws access key" in name.lower() for name in names))
        self.assertIn("https://api.example.com/v1/ping", result["summary"]["urls"])
        self.assertIn("IOCTL_KILL_PROCESS", result["summary"]["ioctl_names"])

    def test_detect_kind_uses_magic_and_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf = Path(tmp) / "sample.bin"
            elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
            self.assertEqual(reveng.detect_kind(str(elf)), "binary")
            apk = Path(tmp) / "sample.apk"
            apk.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
            self.assertEqual(reveng.detect_kind(str(apk)), "apk")


class RenderTests(unittest.TestCase):
    def test_markdown_contains_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.py"
            path.write_text("import pickle\npickle.loads(raw)\n")
            result = reveng.analyze("source", str(path))
        text = reveng.render_markdown(result)
        self.assertIn("# source", text)
        self.assertIn("pickle", text)
        self.assertIn("Observations are leads", result["note"])


if __name__ == "__main__":
    unittest.main()
