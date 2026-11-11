"""Helix toolsmith: write, run, reuse, and study tools."""

import tempfile
import unittest
from pathlib import Path

from netcast3r import brain, toolshed
from netcast3r.server import build_server


class ToolsmithTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Toolsmith", "https://lab.example.com/", status="active",
            autonomy="autonomous", scope=["lab.example.com"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_write_run_and_reuse_a_script(self):
        record = toolshed.write_script(
            self.index, self.tmp, "hello-world",
            "import sys\nprint('hello', sys.argv[1] if len(sys.argv) > 1 else 'world')\n",
            purpose="print a greeting", mission_id=self.mission["id"])
        self.assertEqual(record["name"], "hello-world")
        self.assertTrue(Path(record["path"]).is_file())

        result = toolshed.run_script(self.index, self.tmp, "hello-world",
                                     args=["helix"], mission_id=self.mission["id"])
        self.assertEqual(result["status"], "ok", result)
        self.assertIn("hello helix", result["stdout"])

        rows = self.index.list_helix_scripts(query="greeting")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["runs"], 1)
        self.assertEqual(rows[0]["successes"], 1)

    def test_script_name_and_language_are_validated(self):
        with self.assertRaises(ValueError):
            toolshed.write_script(self.index, self.tmp, "../escape", "print(1)")
        with self.assertRaises(ValueError):
            toolshed.write_script(self.index, self.tmp, "ok-name", "x",
                                  language="ruby")

    def test_study_an_installed_tool_and_delete_a_script(self):
        note = toolshed.study_tool(self.index, name="git-dumper")
        self.assertTrue(note["installed"])
        self.assertTrue(note["path"].endswith("git-dumper"))
        self.assertTrue(self.index.list_tool_notes(query="git"))

        toolshed.write_script(self.index, self.tmp, "temp-tool", "print('x')")
        self.assertTrue(toolshed.delete_script(self.index, self.tmp, "temp-tool"))
        self.assertIsNone(self.index.get_helix_script("temp-tool"))

    def test_brain_can_write_and_run_its_own_tool(self):
        written = brain._apply(self.index, self.server._director(), {
            "kind": "script_write", "name": "brain-tool",
            "purpose": "prove the toolsmith",
            "content": "print('brain-tool-ok')\n",
            "mission_id": self.mission["id"]}, self.mission["id"])
        self.assertTrue(written["applied"], written)

        run = brain._apply(self.index, self.server._director(), {
            "kind": "script_run", "name": "brain-tool",
            "mission_id": self.mission["id"]}, self.mission["id"])
        self.assertTrue(run["applied"], run)
        self.assertIn("brain-tool-ok", run["result"]["stdout"])

    def test_supervised_mission_cannot_write_host_code(self):
        supervised = self.index.create_mission(
            "Supervised", "https://lab.example.com/", status="active",
            autonomy="supervised", scope=["lab.example.com"])
        out = brain._apply(self.index, self.server._director(), {
            "kind": "script_write", "name": "blocked-tool",
            "content": "print('x')", "mission_id": supervised["id"]},
            supervised["id"])
        self.assertFalse(out["applied"])
        self.assertIn("autonomous", out["reason"])


if __name__ == "__main__":
    unittest.main()
