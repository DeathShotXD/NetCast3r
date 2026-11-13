import unittest

from netcast3r import redirect


class PayloadTests(unittest.TestCase):
    def test_payloads_cover_common_bypasses(self):
        kinds = {row["kind"] for row in redirect.open_redirect_payloads(
            "app.example.com", "canary.test")}
        for expected in ("absolute", "protocol_relative", "userinfo",
                         "suffix_host", "backslash"):
            self.assertIn(expected, kinds)


class ClassifyTests(unittest.TestCase):
    def test_open_redirect_to_canary(self):
        hops = [{"hop": 1, "url": "https://app.example.com/go", "status": 302,
                 "location": "https://nc3r-canary.invalid/"}]
        result = redirect.classify_chain("https://app.example.com/go", hops,
                                         canary="nc3r-canary.invalid")
        self.assertEqual(result["verdict"], "open_redirect")
        self.assertEqual(result["canary_host"], "nc3r-canary.invalid")

    def test_redirect_loop(self):
        hops = [{"hop": 1, "url": "/a", "status": 302, "location": "/b"},
                {"hop": 2, "url": "/b", "status": 302, "location": "/a"},
                {"hop": 3, "url": "/a", "status": 0, "location": ""}]
        self.assertEqual(redirect.classify_chain("https://app.example.com/a", hops)
                         ["verdict"], "redirect_loop")

    def test_external_redirect(self):
        hops = [{"hop": 1, "url": "https://app.example.com/go", "status": 301,
                 "location": "https://other.example/"}]
        result = redirect.classify_chain("https://app.example.com/go", hops)
        self.assertEqual(result["verdict"], "external_redirect")
        self.assertIn("other.example", result["external_hosts"])


class ChainTests(unittest.TestCase):
    def _fetch(self, pages):
        def fetch(url):
            return pages.get(url, {"status": 404, "headers": {}, "body": ""})
        return fetch

    def test_chain_to_canary(self):
        pages = {
            "https://app.example.com/go": {"status": 302,
                                           "headers": {"location": "/next"}, "body": ""},
            "https://app.example.com/next": {"status": 302,
                                             "headers": {"location":
                                                         "https://nc3r-canary.invalid/"},
                                             "body": ""},
            "https://nc3r-canary.invalid/": {"status": 200, "headers": {}, "body": "x"},
        }
        result = redirect.chain("https://app.example.com/go",
                                fetch=self._fetch(pages), canary="nc3r-canary.invalid")
        self.assertEqual(result["verdict"], "open_redirect")
        self.assertEqual(result["hops_followed"], 3)

    def test_loop_is_cut(self):
        pages = {
            "https://app.example.com/a": {"status": 302,
                                          "headers": {"location": "/b"}, "body": ""},
            "https://app.example.com/b": {"status": 302,
                                          "headers": {"location": "/a"}, "body": ""},
        }
        result = redirect.chain("https://app.example.com/a",
                                fetch=self._fetch(pages))
        self.assertEqual(result["verdict"], "redirect_loop")

    def test_no_redirect(self):
        pages = {"https://app.example.com/": {"status": 200, "headers": {},
                                              "body": "ok"}}
        result = redirect.chain("https://app.example.com/", fetch=self._fetch(pages))
        self.assertEqual(result["verdict"], "same_origin")

    def test_summary(self):
        self.assertIn("open_redirect", redirect.summary()["verdicts"])


if __name__ == "__main__":
    unittest.main()
