import json
import unittest

from netcast3r.config import default_config
from netcast3r.recon import Recon
from netcast3r.scope import ScopeManager
from netcast3r.subdomains import SubdomainFinder


class _Response:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status
        self.headers = {"content-type": "application/json"}


class _Session:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append(url)
        return self.routes.get(url)


def _always_false(host):
    return False


class SubdomainFinderTests(unittest.TestCase):
    def _finder(self, routes=None, resolving=(), scope=("example.com",), resolver=None):
        config = default_config()
        config.run.subdomains = True
        session = _Session(routes)
        if resolver is None:
            seen = set(resolving)
            resolver = lambda host: host in seen
        return SubdomainFinder(ScopeManager(in_scope=list(scope)), config, session,
                               resolver=resolver), session

    def test_crt_names_are_parsed_deduped_and_scoped(self):
        crt = json.dumps([
            {"name_value": "www.example.com\napi.example.com"},
            {"common_name": "*.example.com"},
            {"name_value": "evil.other.net"},
            {"name_value": "WWW.example.com"},
        ])
        routes = {"https://crt.sh/?q=%25.example.com&output=json": _Response(crt)}
        finder, _ = self._finder(routes)
        found = finder.find(["example.com"])
        self.assertIn("www.example.com", found)
        self.assertIn("api.example.com", found)
        self.assertNotIn("example.com", found)
        self.assertNotIn("evil.other.net", found)
        self.assertEqual(found, sorted(set(found)))

    def test_passive_dns_names_are_collected(self):
        otx = json.dumps({"passive_dns": [
            {"hostname": "portal.example.com"},
            {"hostname": "x.other.net"},
        ]})
        routes = {
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns":
                _Response(otx),
        }
        finder, _ = self._finder(routes)
        found = finder.find(["example.com"])
        self.assertIn("portal.example.com", found)
        self.assertNotIn("x.other.net", found)

    def test_brute_force_keeps_only_resolving_names(self):
        resolving = {"dev.example.com", "api.example.com"}
        finder, _ = self._finder(resolving=resolving)
        found = finder.find(["example.com"])
        self.assertIn("dev.example.com", found)
        self.assertIn("api.example.com", found)
        self.assertNotIn("beta.example.com", found)

    def test_a_wildcard_dns_answer_skips_the_brute_pass(self):
        calls = []

        def resolver(host):
            calls.append(host)
            return True

        finder, _ = self._finder(resolver=resolver)
        found = finder.find(["example.com"])
        self.assertEqual(found, [])
        self.assertEqual(len(calls), 1)

    def test_results_are_capped(self):
        crt = json.dumps([
            {"name_value": "a.example.com"},
            {"name_value": "b.example.com"},
            {"name_value": "c.example.com"},
        ])
        routes = {"https://crt.sh/?q=%25.example.com&output=json": _Response(crt)}
        finder, _ = self._finder(routes)
        finder.limit = 2
        found = finder.find(["example.com"])
        self.assertEqual(len(found), 2)

    def test_a_broken_source_does_not_raise(self):
        finder, _ = self._finder(routes={"https://crt.sh/?q=%25.example.com&output=json":
                                         _Response("not json")})
        found = finder.find(["example.com"])
        self.assertEqual(found, [])

    def test_address_targets_are_not_enumerated(self):
        finder, session = self._finder()
        self.assertEqual(finder.find(["127.0.0.1"]), [])
        self.assertEqual(session.requested, [])

    def test_recon_expands_domains_into_https_seeds(self):
        config = default_config()
        config.run.subdomains = True
        crt = json.dumps([{"name_value": "www.example.com"}])
        session = _Session({"https://crt.sh/?q=%25.example.com&output=json": _Response(crt)})
        recon = Recon(ScopeManager(in_scope=["example.com"]), config,
                      session=session, resolver=_always_false)
        seeds = recon.expand_seeds(["example.com"])
        self.assertEqual(seeds, ["https://www.example.com"])

    def test_expanded_seeds_are_empty_when_the_stage_is_off(self):
        config = default_config()
        config.run.subdomains = False
        recon = Recon(ScopeManager(in_scope=["example.com"]), config,
                      session=_Session(), resolver=_always_false)
        self.assertEqual(recon.expand_seeds(["example.com"]), [])


if __name__ == "__main__":
    unittest.main()
