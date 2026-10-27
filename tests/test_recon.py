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
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append(url)
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


class _RedirectSession:
    def __init__(self, chain):
        self.chain = chain
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append(url)
        entry = self.chain.get(url)
        if entry is None:
            return None
        status, headers, text = entry
        response = _Response(text, status)
        response.headers = headers
        return response


class FetchTests(unittest.TestCase):
    def test_a_redirect_out_of_scope_is_refused(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        session = _RedirectSession({
            "https://app.example.com/go":
                (302, {"location": "https://internal.other.net/x", "content-type": "text/html"}, ""),
        })
        recon = Recon(scope, default_config(), session=session)
        self.assertEqual(recon.fetch("https://app.example.com/go"), (0, "", ""))
        self.assertEqual(session.requested, ["https://app.example.com/go"])

    def test_an_in_scope_redirect_is_followed_once(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        session = _RedirectSession({
            "https://app.example.com/go":
                (301, {"location": "/home", "content-type": "text/html"}, ""),
            "https://app.example.com/home":
                (200, {"content-type": "text/html"}, "<html>ok</html>"),
        })
        recon = Recon(scope, default_config(), session=session)
        self.assertEqual(recon.fetch("https://app.example.com/go"),
                         (200, "<html>ok</html>", "text/html"))
        self.assertEqual(session.requested,
                         ["https://app.example.com/go", "https://app.example.com/home"])

    def test_a_redirect_loop_ends_cleanly(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        session = _RedirectSession({
            "https://app.example.com/a":
                (302, {"location": "/b", "content-type": "text/html"}, ""),
            "https://app.example.com/b":
                (302, {"location": "/a", "content-type": "text/html"}, ""),
        })
        recon = Recon(scope, default_config(), session=session)
        self.assertEqual(recon.fetch("https://app.example.com/a"), (0, "", ""))

    def test_crawl_stops_when_asked(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        session = _PageSession({"https://app.example.com/": "<a href='/a'>a</a>"})
        recon = Recon(scope, default_config(), session=session)
        result = recon.crawl(["https://app.example.com/"], should_stop=lambda: True)
        self.assertEqual(result.pages, [])

    def test_default_max_pages_keeps_the_auto_floor(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        config = default_config()
        config.run.max_pages = 0
        config.run.concurrency = 4
        recon = Recon(scope, config, session=_PageSession({}))
        self.assertEqual(recon.max_pages, 100)

    def test_explicit_max_pages_is_a_hard_cap(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        config = default_config()
        config.run.max_pages = 1
        pages = {
            "https://app.example.com/": "<a href='/a'>a</a><a href='/b'>b</a>",
            "https://app.example.com/a": "<p>a</p>",
            "https://app.example.com/b": "<p>b</p>",
        }
        session = _PageSession(pages)
        recon = Recon(scope, config, session=session)
        result = recon.crawl(["https://app.example.com/"])
        self.assertEqual(session.requested, ["https://app.example.com/"])
        self.assertEqual(result.pages, ["https://app.example.com/"])

    def test_zero_depth_fetches_only_the_seed(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        config = default_config()
        config.run.depth = 0
        pages = {
            "https://app.example.com/": "<a href='/child'>child</a>",
            "https://app.example.com/child": "<p>child</p>",
        }
        session = _PageSession(pages)
        recon = Recon(scope, config, session=session)
        result = recon.crawl(["https://app.example.com/"])
        self.assertEqual(session.requested, ["https://app.example.com/"])
        self.assertEqual(result.pages, ["https://app.example.com/"])

    def test_non_http_links_are_ignored(self):
        scope = ScopeManager(in_scope=["*.example.com"])
        session = _PageSession({
            "https://app.example.com/": (
                "<a href='mailto:x@example.com'>m</a>"
                "<a href='javascript:void(0)'>j</a>"
                "<script src='/a.js'></script>"),
            "https://app.example.com/a.js": "var x=1;",
        })
        recon = Recon(scope, default_config(), session=session)
        result = recon.crawl(["https://app.example.com/"])
        self.assertEqual(result.out_of_scope, [])
        self.assertEqual(result.js_urls, ["https://app.example.com/a.js"])


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

    def test_a_json_file_is_not_treated_as_javascript(self):
        scope = ScopeManager(in_scope=["app.example.com"])
        pages = {"https://app.example.com/data.json": '{"a": 1}'}
        recon = Recon(scope, default_config(), session=_PageSession(pages))
        result = recon.crawl(["https://app.example.com/data.json"])
        self.assertIn("https://app.example.com/data.json", result.pages)
        self.assertNotIn("https://app.example.com/data.json", result.js_urls)


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

    def test_robots_and_sitemap_paths_are_collected(self):
        scope = ScopeManager(in_scope=["example.com"])
        robots = "User-agent: *\nDisallow: /admin\nDisallow: /\n"
        sitemap = "<urlset><url><loc>https://example.com/pricing</loc></url></urlset>"
        session = _ApiSession(specs={
            "https://example.com/robots.txt": robots,
            "https://example.com/sitemap.xml": sitemap,
        })
        recon = Recon(scope, default_config(), session=session)
        found = recon.discover_wellknown(["https://example.com"])
        self.assertIn("https://example.com/admin", found)
        self.assertIn("https://example.com/pricing", found)
        self.assertNotIn("https://example.com/", found)

    def test_out_of_scope_sitemap_entries_are_skipped(self):
        scope = ScopeManager(in_scope=["example.com"])
        sitemap = "<urlset><url><loc>https://evil.net/x</loc></url></urlset>"
        session = _ApiSession(specs={"https://example.com/sitemap.xml": sitemap})
        recon = Recon(scope, default_config(), session=session)
        self.assertEqual(recon.discover_wellknown(["https://example.com"]), [])


if __name__ == "__main__":
    unittest.main()
