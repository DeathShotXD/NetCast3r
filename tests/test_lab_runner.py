import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import training
from netcast3r.server.lab_runner import RECIPES, LabRunner


class LabRecipeTests(unittest.TestCase):
    def test_recipes_target_known_catalogue_labs(self):
        slugs = {lab["slug"] for lab in training.catalog()}
        self.assertGreaterEqual(len(RECIPES), 4)
        for slug, recipe in RECIPES.items():
            self.assertIn(slug, slugs)
            self.assertTrue(
                recipe["page"].startswith("https://portswigger.net/")
                or recipe["page"].startswith("http://127.0.0.1:"))
            self.assertTrue(recipe["steps"])
            self.assertEqual(recipe["steps"][-1]["kind"], "record")

    def test_recipe_substitution_and_assertions(self):
        variables = {"base": "https://lab.example", "secret": "abc"}
        self.assertEqual(
            LabRunner._sub("{{base}}/files/{{secret}}", variables),
            "https://lab.example/files/abc")
        self.assertEqual(
            LabRunner._sub({"cookie": "session={{secret}}"}, variables),
            {"cookie": "session=abc"})

    def test_available_lists_only_supported_recipes(self):
        class FakeServer:
            pass
        runner = LabRunner(FakeServer())
        try:
            items = runner.available()
            self.assertEqual({item["slug"] for item in items}, set(RECIPES))
        finally:
            runner.shutdown(wait=False)


if __name__ == "__main__":
    unittest.main()
