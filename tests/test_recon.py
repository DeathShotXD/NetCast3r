import base64
import json
import unittest

from netcast3r.config import default_config
from netcast3r.recon import Recon
from netcast3r.scope import ScopeManager


class _Response:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status
        self.headers = {"content-type": "application/json"}


class _StubSession:
    def __init__(self, text):
        self.text = text
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append(url)
        return _Response(self.text)


class _PageSession:
    def __init__(self, pages):
        self.pages = pages

    def get(self, url, **kwargs):
        if url in self.pages:
            return _Response(self.pages[url])
        return None


class _ApiSession:
    def __init__(self, specs=None, graphql=""):
        self.specs = specs or {}
        self.graphql = graphql
        self.posted = []

    def get(self, url, **kwargs):
        return _Response(self.specs[url]) if url in self.specs else None

    def request(self, method, url, json=None, **kwargs):
        self.posted.append((method, url))
        return _Response(self.graphql)


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


class SourceMapTests(unittest.TestCase):
    def test_remote_source_map_is_recovered(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        body = json.dumps({"sourcesContent": ["const KEY='abc'", "export const x=1"]})
        recon = Recon(scope, default_config(), session=_StubSession(body))
        js = "var a=1;\n//# sourceMappingURL=app.js.map\n"
        url, text = recon._source_map("https://app.example.com/app.js", js)
        self.assertEqual(url, "https://app.example.com/app.js.map")
        self.assertIn("const KEY='abc'", text)
        self.assertIn("export const x=1", text)

    def test_inline_source_map_is_decoded_without_a_request(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        payload = base64.b64encode(
            json.dumps({"sourcesContent": ["secret"]}).encode()).decode()
        js = "//# sourceMappingURL=data:application/json;base64," + payload
        recon = Recon(scope, default_config(), session=_StubSession(""))
        url, text = recon._source_map("https://app.example.com/app.js", js)
        self.assertTrue(url.endswith("#sourcemap"))
        self.assertEqual(text, "secret")

    def test_out_of_scope_source_map_is_not_fetched(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        session = _StubSession(json.dumps({"sourcesContent": ["x"]}))
        recon = Recon(scope, default_config(), session=session)
        js = "//# sourceMappingURL=https://cdn.other.net/app.js.map"
        self.assertIsNone(recon._source_map("https://app.example.com/app.js", js))
        self.assertEqual(session.requested, [])

    def test_a_map_without_contents_is_ignored(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        recon = Recon(scope, default_config(), session=_StubSession("{}"))
        self.assertIsNone(
            recon._source_map("https://app.example.com/app.js",
                              "//# sourceMappingURL=app.js.map"))

    def test_crawl_scans_recovered_sources(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        pages = {
            "https://app.example.com/app.js":
                "var a=1;\n//# sourceMappingURL=app.js.map",
            "https://app.example.com/app.js.map":
                json.dumps({"sourcesContent": ["const HIDDEN='x'"]}),
        }
        recon = Recon(scope, default_config(), session=_PageSession(pages))
        result = recon.crawl(["https://app.example.com/app.js"])
        self.assertIn("https://app.example.com/app.js.map", result.js_text)
        self.assertIn("const HIDDEN='x'",
                      result.js_text["https://app.example.com/app.js.map"])


class ApiDiscoveryTests(unittest.TestCase):
    def test_openapi_paths_are_discovered(self):
        scope = ScopeManager(in_scope=["example.com"])
        spec = json.dumps({"paths": {"/api/users": {}, "/api/orders": {}}})
        session = _ApiSession(specs={"https://example.com/openapi.json": spec})
        recon = Recon(scope, default_config(), session=session)
        found = recon.discover_apis(["https://example.com"])
        self.assertIn("https://example.com/api/users", found)
        self.assertIn("https://example.com/api/orders", found)

    def test_graphql_introspection_marks_the_endpoint(self):
        scope = ScopeManager(in_scope=["example.com"])
        session = _ApiSession(
            graphql='{"data":{"__schema":{"queryType":{"name":"Q"}}}}')
        recon = Recon(scope, default_config(), session=session)
        found = recon.discover_apis(["https://example.com"])
        self.assertIn("https://example.com/graphql", found)

    def test_a_closed_graphql_endpoint_is_not_reported(self):
        scope = ScopeManager(in_scope=["example.com"])
        session = _ApiSession(
            graphql='{"errors":[{"message":"introspection is disabled"}]}')
        recon = Recon(scope, default_config(), session=session)
        self.assertEqual(recon.discover_apis(["https://example.com"]), [])

    def test_out_of_scope_roots_are_skipped(self):
        scope = ScopeManager(in_scope=["example.com"])
        session = _ApiSession(graphql='{"__schema":{}}')
        recon = Recon(scope, default_config(), session=session)
        self.assertEqual(recon.discover_apis(["https://other.net"]), [])
        self.assertEqual(session.posted, [])


if __name__ == "__main__":
    unittest.main()
