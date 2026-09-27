import unittest

import httpx

from netcast3r.validate import Recipe, Validator


def handler(request: httpx.Request) -> httpx.Response:
    auth = request.headers.get("Authorization", "")
    if request.url.path == "/user" and auth == "token good":
        return httpx.Response(200, text='{"login": "operator"}')
    if request.url.path == "/user":
        return httpx.Response(401, text='{"message": "Bad credentials"}')
    return httpx.Response(404, text="not found")


class ValidatorTests(unittest.TestCase):
    def setUp(self):
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


if __name__ == "__main__":
    unittest.main()
