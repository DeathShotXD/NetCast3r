import tempfile
import unittest
from pathlib import Path

from netcast3r.config import default_config, load_config


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

    def test_provider_reads_a_key_from_a_file(self):
        workdir = Path(tempfile.mkdtemp())
        keyfile = workdir / "nvidia.key"
        keyfile.write_text("nvapi-file-secret\n")
        path = self._write(
            "[[providers]]\n"
            'name = "nvidia"\n'
            'base_url = "https://integrate.api.nvidia.com/v1"\n'
            f'api_key_file = "{keyfile}"\n'
            'models = ["nvidia/nemotron-3-ultra-550b-a55b"]\n'
        )
        provider = load_config(path).provider("nvidia")
        self.assertIsNotNone(provider)
        self.assertEqual(provider.resolve_key(), "nvapi-file-secret")

    def test_nvidia_leads_the_default_pool(self):
        config = default_config()
        provider = config.provider("nvidia")
        self.assertIsNotNone(provider)
        self.assertEqual(provider.base_url, "https://integrate.api.nvidia.com/v1")
        self.assertEqual(provider.priority, 5)
        self.assertIn("nvidia/nemotron-3-ultra-550b-a55b", provider.models)
        self.assertEqual([item.name for item in config.ordered_providers()[:2]],
                         ["nvidia", "openrouter"])


if __name__ == "__main__":
    unittest.main()
