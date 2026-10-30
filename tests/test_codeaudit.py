# codeaudit: ignore-file py-eval-exec,py-bare-except -- planted defects for the auditor test
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import codeaudit


class CodeAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, "utf-8")
        return path

    def test_flags_real_python_defects(self):
        self.write("bad.py", (
            "import os\n"
            "def run(value):\n"
            "    try:\n"
            "        pass\n"
            "    except:\n"
            "        pass\n"
            "    os.system('echo ' + value)\n"
            "    return eval(value)\n"
        ))
        report = codeaudit.scan(self.root)
        rules = {item["rule"] for item in report["findings"]}
        self.assertIn("py-bare-except", rules)
        self.assertIn("py-swallowed-exception", rules)
        self.assertIn("py-os-system", rules)
        self.assertIn("py-eval-exec", rules)
        self.assertGreater(report["total_findings"], 0)

    def test_flags_frontend_sinks(self):
        self.write("app.js", "el.innerHTML = userInput;\n")
        self.write("View.svelte", "<p>{@html body}</p>\n")
        report = codeaudit.scan(self.root)
        rules = {item["rule"] for item in report["findings"]}
        self.assertIn("js-inner-html", rules)
        self.assertIn("svelte-html", rules)

    def test_inline_suppression_is_recorded_not_hidden(self):
        self.write("safe.py", (
            "import os\n"
            "os.system('echo ok')  # codeaudit: ignore py-os-system -- fixed argument\n"
        ))
        report = codeaudit.scan(self.root)
        active = [item for item in report["findings"]
                  if item["rule"] == "py-os-system"]
        self.assertEqual(active, [])
        reasons = [item["reason"] for item in report["suppressed"]
                   if item["rule"] == "py-os-system"]
        self.assertTrue(any("fixed argument" in reason for reason in reasons))

    def test_file_level_suppression(self):
        self.write("safe.py", (
            "# codeaudit: ignore-file py-os-system\n"
            "import os\n"
            "os.system('echo ok')\n"
        ))
        report = codeaudit.scan(self.root)
        self.assertFalse([item for item in report["findings"]
                          if item["rule"] == "py-os-system"])
        self.assertTrue([item for item in report["suppressed"]
                         if item["rule"] == "py-os-system"])

    def test_clean_file_has_no_findings(self):
        self.write("clean.py", "def add(a, b):\n    return a + b\n")
        report = codeaudit.scan(self.root)
        self.assertEqual(report["total_findings"], 0)
        self.assertEqual(report["grade"], "A")

    def test_the_auditor_does_not_match_its_own_rule_table(self):
        source = Path(codeaudit.__file__)
        report = codeaudit.scan(source)
        self.assertEqual(report["total_findings"], 0, report["findings"])

    def test_rules_catalogue_is_discoverable(self):
        items = codeaudit.rules()
        self.assertGreater(len(items), 10)
        for item in items:
            self.assertIn(item["severity"], {"high", "medium", "low", "info"})
            self.assertTrue(item["fix"])


if __name__ == "__main__":
    unittest.main()