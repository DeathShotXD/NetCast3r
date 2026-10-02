import tempfile
import unittest
from pathlib import Path

from netcast3r.config import load_config


class ConfigTests(unittest.TestCase):
    def _write(self, body):
        workdir = Path(tempfile.mkdtemp())
        path = workdir / "netcast3r.toml"
        path.write_text(body)
        return path

    def test_route_without_model_defaults(self):
        config = load_config(self._write('[[routes]]\nagent = "scribe"\n'))
        self.assertEqual(config.route_for("scribe").model, "")

    def test_output_flags_are_independent(self):
        config = load_config(self._write("[run]\nwrite_json = true\nwrite_jsonl = true\n"))
        self.assertTrue(config.run.write_json)
        self.assertTrue(config.run.write_jsonl)


if __name__ == "__main__":
    unittest.main()
