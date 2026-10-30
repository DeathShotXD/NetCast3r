import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import model_training
from netcast3r.providers import Completion
from netcast3r.server.index import Index


class ModelTrainingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "index.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_model_text_is_advisory_and_verified_chain_is_kept(self):
        recipe = {
            "title": "Test lab",
            "lesson": "The verified lesson with the exact payload and proof.",
            "steps": [{"kind": "http", "method": "GET", "path": "/test"}],
        }

        class FakeBus:
            def __init__(self, *args, **kwargs):
                pass

            def complete(self, *args, **kwargs):
                return Completion(text="The model explanation.",
                                  provider="fake", model="free-model")

        with mock.patch.object(model_training, "ProviderBus", FakeBus):
            result = model_training.study_recipe(
                self.index, "test-lab", recipe)
        skill = self.index.get_skill(result["skill"]["name"])
        self.assertIn("Verified chain (authoritative)", skill["body"])
        self.assertIn("The verified lesson", skill["body"])
        self.assertIn("Model explanation (advisory)", skill["body"])
        self.assertTrue(result["used_model"])


if __name__ == "__main__":
    unittest.main()
