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

    def test_a_value_in_the_url_is_percent_encoded(self):
        seen = {}

        def capture(request):
            seen["url"] = str(request.url)
            return httpx.Response(200, text='{"ok":true}')

        recipe = Recipe(type="enc", provider="E", method="GET",
                        url="https://e.test/check?token={value}",
                        success_match="ok", success_codes=[200])
        validator = Validator(recipes={"enc": recipe}, tier="read",
                              client=httpx.Client(transport=httpx.MockTransport(capture)))
        result = validator.validate("enc", "a/b&c=d")
        self.assertEqual(result.status, "verified")
        self.assertIn("token=a%2Fb%26c%3Dd", seen["url"])

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


class FalsePositiveTests(unittest.TestCase):
    def _validator(self, recipe, text, code):
        def handler(request):
            return httpx.Response(code, text=text)
        return Validator(recipes={recipe.type: recipe}, tier="read",
                         client=httpx.Client(transport=httpx.MockTransport(handler)))

    def test_a_success_marker_on_a_failure_status_is_not_verified(self):
        recipe = Recipe(type="x", provider="X", method="GET", url="https://x.test/",
                        success_match="error", success_codes=[200], fail_codes=[401])
        result = self._validator(recipe, '{"error":"unauthorized"}', 401).validate("x", "v")
        self.assertNotEqual(result.status, "verified")

    def test_a_4xx_in_success_codes_never_verifies(self):
        recipe = Recipe(type="y", provider="Y", method="GET", url="https://y.test/",
                        success_codes=[200, 404])
        result = self._validator(recipe, "not found", 404).validate("y", "v")
        self.assertNotEqual(result.status, "verified")

    def test_a_control_character_value_is_refused(self):
        recipe = Recipe(type="z", provider="Z", method="GET", url="https://z.test/?k={value}",
                        success_match="ok", success_codes=[200])
        result = self._validator(recipe, "ok", 200).validate("z", "a\r\nX-Injected: 1")
        self.assertEqual(result.status, "unknown")
        self.assertIn("control", result.detail)


if __name__ == "__main__":
    unittest.main()
