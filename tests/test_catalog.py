import re
import unittest

from netcast3r.secrets import load_patterns
from netcast3r.validate import load_recipes

WRITE_VARIANTS = {"github_write", "gitlab_write", "slack_webhook_write",
                  "discord_webhook_write"}
INTERNAL = {"mock"}


class CatalogTests(unittest.TestCase):
    def test_patterns_load_and_compile(self):
        patterns = load_patterns()
        self.assertGreaterEqual(len(patterns), 300)
        ids = [p.id for p in patterns]
        self.assertEqual(len(ids), len(set(ids)), "pattern ids must be unique")
        for pattern in patterns:
            self.assertIsInstance(pattern.regex, re.Pattern)

    def test_recipes_load_and_are_well_formed(self):
        recipes = load_recipes()
        self.assertGreaterEqual(len(recipes), 130)
        for name, recipe in recipes.items():
            self.assertEqual(name, recipe.type)
            self.assertTrue(recipe.url, f"{name} has no url")
            self.assertTrue(recipe.success_codes or recipe.success_match,
                            f"{name} has no success signal")

    def test_every_recipe_has_a_matching_pattern(self):
        types = {p.type for p in load_patterns()}
        for name in load_recipes():
            if name in INTERNAL or name in WRITE_VARIANTS:
                continue
            self.assertIn(name, types, f"recipe {name} cannot be reached by any pattern")

    def test_write_recipes_exist(self):
        recipes = load_recipes()
        writes = [name for name, recipe in recipes.items() if recipe.write]
        self.assertGreaterEqual(len(writes), 5)

    def test_pair_recipes_reference_a_detected_type(self):
        types = {p.type for p in load_patterns()}
        for name, recipe in load_recipes().items():
            if recipe.pair_type:
                self.assertIn(recipe.pair_type, types,
                              f"{name} pairs with undetected type {recipe.pair_type}")


if __name__ == "__main__":
    unittest.main()
