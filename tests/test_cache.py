import unittest

from netcast3r import cache

PRIVATE = "<html><title>Account</title>private dashboard data</html>"


class StatusTests(unittest.TestCase):
    def test_hit_from_age(self):
        state = cache.cache_status({"Age": "120", "Cache-Control": "public"})
        self.assertTrue(state["cached"])
        self.assertTrue(state["cacheable"])

    def test_hit_from_x_cache(self):
        self.assertTrue(cache.cache_status({"X-Cache": "HIT"})["cached"])
        self.assertFalse(cache.cache_status({"X-Cache": "MISS"})["cached"])

    def test_no_store_is_not_cacheable(self):
        state = cache.cache_status({"Cache-Control": "private, no-store"})
        self.assertFalse(state["cacheable"])
        self.assertTrue(state["no_store"])


class DeceptionTests(unittest.TestCase):
    def _fetch(self):
        def fetch(url, headers):
            if url.endswith("/nonexistent.css"):
                return {"status": 200, "body": PRIVATE,
                        "headers": {"Age": "90", "X-Cache": "HIT"}}
            if url.endswith("/nonexistent.js"):
                return {"status": 200, "body": PRIVATE, "headers": {}}
            return {"status": 200, "body": PRIVATE,
                    "headers": {"Cache-Control": "private, no-store"}}
        return fetch

    def test_deception_when_private_page_is_cached(self):
        result = cache.deception("https://app.example.com/dashboard",
                                 variants=["/nonexistent.css", "/nonexistent.js"],
                                 fetch=self._fetch())
        rows = {row["suffix"]: row for row in result["results"]}
        self.assertEqual(rows["/nonexistent.css"]["verdict"], "cache_deception")
        self.assertTrue(rows["/nonexistent.css"]["same_as_base"])
        self.assertEqual(rows["/nonexistent.js"]["verdict"], "cacheable_private")
        self.assertEqual(result["counts"]["cache_deception"], 1)
        self.assertEqual(len(result["deception"]), 1)

    def test_not_cached_when_pages_differ(self):
        def fetch(url, headers):
            if url.endswith(".css"):
                return {"status": 404, "body": "not found", "headers": {}}
            return {"status": 200, "body": PRIVATE,
                    "headers": {"Cache-Control": "private"}}
        result = cache.deception("https://app.example.com/dashboard",
                                 variants=["/x.css"], fetch=fetch)
        self.assertEqual(result["results"][0]["verdict"], "not_cached")


class PoisoningTests(unittest.TestCase):
    def test_reflection_then_poison(self):
        _state = {"value": ""}

        def fetch2(url, headers):
            injected = (headers or {}).get("X-Forwarded-Host")
            if injected:
                _state["value"] = injected
                return {"status": 200, "body": f"<link href='https://{injected}/'>",
                        "headers": {"X-Cache": "HIT"}}
            if _state["value"]:
                return {"status": 200, "body": f"poisoned copy for {_state['value']}",
                        "headers": {}}
            return {"status": 200, "body": "clean", "headers": {}}

        result = cache.poisoning("https://app.example.com/",
                                 headers=["X-Forwarded-Host"], fetch=fetch2)
        self.assertEqual(result["results"][0]["verdict"], "poisoned")
        self.assertEqual(result["counts"]["poisoned"], 1)

    def test_reflection_only_is_not_poisoned(self):
        def fetch(url, headers):
            value = (headers or {}).get("X-Host")
            if value:
                return {"status": 200, "body": f"echo {value}",
                        "headers": {"X-Echo": value}}
            return {"status": 200, "body": "clean", "headers": {}}

        result = cache.poisoning("https://app.example.com/",
                                 headers=["X-Host"], fetch=fetch)
        self.assertEqual(result["results"][0]["verdict"], "reflected")
        self.assertTrue(result["results"][0]["echoed_header"])

    def test_unreflected_page_is_not_a_lead(self):
        result = cache.poisoning("https://app.example.com/", headers=["Forwarded"],
                                 fetch=lambda url, headers: {"status": 200,
                                                             "body": "clean",
                                                             "headers": {}})
        self.assertEqual(result["results"][0]["verdict"], "cacheable_no_echo")


class AuditTests(unittest.TestCase):
    def test_audit_modes(self):
        fetch = lambda url, headers: {"status": 200, "body": "x", "headers": {}}
        result = cache.audit("https://app.example.com/", mode="deception", fetch=fetch)
        self.assertIn("deception", result)
        self.assertNotIn("poisoning", result)


if __name__ == "__main__":
    unittest.main()
