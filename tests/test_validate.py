import unittest

import httpx

from netcast3r.validate import Recipe, Validator

CALLS: list[str] = []


def handler(request: httpx.Request) -> httpx.Response:
    CALLS.append(request.url.path)
    auth = request.headers.get("Authorization", "")
    if request.url.path == "/user" and auth == "token good":
        return httpx.Response(200, text='{"login": "operator"}')
    if request.url.path == "/user":
        return httpx.Response(401, text='{"message": "Bad credentials"}')
    if request.url.path == "/paired":
        primary = request.headers.get("X-Primary", "")
        secondary = request.headers.get("X-Secondary", "")
        if primary == "prime" and secondary == "second":
            return httpx.Response(200, text='{"ok":true}')
        return httpx.Response(401, text='{"error":"bad"}')
    if request.url.path == "/gist":
        return httpx.Response(201, text='{"id":"1"}')
    return httpx.Response(404, text="not found")


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        CALLS.clear()
        self.recipes = {
            "github": Recipe(
                type="github",
                provider="GitHub",
                method="GET",
                url="https://api.github.com/user",
                headers={"Authorization": "token {value}"},
                success_codes=[200],
                success_match='"login"',
                fail_codes=[401],
            ),
            "stateful": Recipe(
                type="stateful",
                provider="Lab",
                method="POST",
                url="https://example.test/write",
                success_codes=[200],
                write=True,
            ),
            "paired": Recipe(
                type="paired",
                provider="Pair",
                method="GET",
                url="https://example.test/paired",
                headers={"X-Primary": "{value}", "X-Secondary": "{value2}"},
                success_codes=[200],
                success_match='"ok":true',
                fail_codes=[401],
                pair_type="paired_secret",
            ),
            "gist": Recipe(
                type="gist",
                provider="GitHub",
                method="GET",
                url="https://api.github.com/user",
                headers={"Authorization": "token {value}"},
                success_codes=[200],
                success_match='"login"',
                fail_codes=[401],
            ),
            "gist_write": Recipe(
                type="gist_write",
                provider="GitHub",
                method="POST",
                url="https://example.test/gist",
                success_codes=[201],
                success_match='"id"',
                write=True,
            ),
        }
        client = httpx.Client(transport=httpx.MockTransport(handler))
        self.validator = Validator(recipes=self.recipes, tier="read", client=client)

    def test_verified(self):
        result = self.validator.validate("github", "good")
        self.assertEqual(result.status, "verified")

    def test_unverified(self):
        result = self.validator.validate("github", "bad")
        self.assertEqual(result.status, "unverified")

    def test_unknown_type(self):
        result = self.validator.validate("nope", "value")
        self.assertEqual(result.status, "unknown")

    def test_write_recipe_held_at_read_tier(self):
        result = self.validator.validate("stateful", "value")
        self.assertEqual(result.status, "skipped")

    def test_write_recipe_runs_at_write_tier(self):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        validator = Validator(recipes=self.recipes, tier="write", client=client)
        result = validator.validate("stateful", "value")
        self.assertNotEqual(result.status, "skipped")

    def test_pair_recipe_without_companion_is_unknown(self):
        result = self.validator.validate("paired", "prime")
        self.assertEqual(result.status, "unknown")
        self.assertIn("paired_secret", result.detail)

    def test_pair_recipe_renders_both_values(self):
        result = self.validator.validate("paired", "prime", "", "second")
        self.assertEqual(result.status, "verified")

    def test_write_variant_is_used_at_write_tier(self):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        validator = Validator(recipes=self.recipes, tier="write", client=client)
        result = validator.validate("gist", "good")
        self.assertEqual(result.status, "verified")
        self.assertIn("/gist", CALLS)

    def test_write_variant_is_ignored_at_read_tier(self):
        result = self.validator.validate("gist", "good")
        self.assertEqual(result.status, "verified")
        self.assertNotIn("/gist", CALLS)
        self.assertIn("/user", CALLS)


if __name__ == "__main__":
    unittest.main()
