import unittest

from netcast3r.config import default_config
from netcast3r.recon import Recon
from netcast3r.scope import ScopeManager


class FakeRecon(Recon):
    def wayback(self, domain, limit=5000):
        return [
            "https://app.example.com/static/a.js",
            "https://app.example.com/page",
            "https://other.example.net/b.js",
            "https://app.example.com/static/c.js?x=1",
            "https://app.example.com/static/a.js",
        ]


class ReconTests(unittest.TestCase):
    def test_historical_js_keeps_only_in_scope_js(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        recon = FakeRecon(scope, default_config())
        urls = recon.historical_js(["example.com"], limit=10, max_js=10)
        self.assertEqual(urls, [
            "https://app.example.com/static/a.js",
            "https://app.example.com/static/c.js?x=1",
        ])

    def test_historical_js_respects_the_cap(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        recon = FakeRecon(scope, default_config())
        urls = recon.historical_js(["example.com"], limit=10, max_js=1)
        self.assertEqual(len(urls), 1)


if __name__ == "__main__":
    unittest.main()
