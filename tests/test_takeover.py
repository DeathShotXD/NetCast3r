import unittest
from unittest import mock

from netcast3r import takeover


def _chain(name, cname="", addresses=("1.2.3.4",), nxdomain=False):
    return {"name": name, "chain": [cname] if cname else [], "cname": cname or name,
            "addresses": list(addresses), "nxdomain": nxdomain, "rcode": "NOERROR"}


class MatchTests(unittest.TestCase):
    def test_suffix_match_is_label_aware(self):
        self.assertTrue(takeover._suffix_match("bucket.s3.amazonaws.com", "s3.amazonaws.com"))
        self.assertTrue(takeover._suffix_match("s3.amazonaws.com", "s3.amazonaws.com"))
        self.assertFalse(takeover._suffix_match("nots3.amazonaws.com", "s3.amazonaws.com"))
        self.assertFalse(takeover._suffix_match("", "s3.amazonaws.com"))

    def test_match_cname_returns_rows(self):
        rows = takeover.match_cname("bucket.s3.amazonaws.com")
        self.assertTrue(any(row.service == "AWS/S3" for row in rows))

    def test_summary_counts(self):
        data = takeover.summary()
        self.assertGreaterEqual(data["services"], 50)
        self.assertGreaterEqual(data["vulnerable_services"], 20)


class CheckTests(unittest.TestCase):
    def test_s3_dangling_bucket_is_vulnerable(self):
        resolver = lambda name: _chain(name, "mybucket.s3.amazonaws.com")
        fetch = lambda url: {"status": 404,
                             "body": "<?xml><Error><Code>NoSuchBucket</Code>"
                                     "The specified bucket does not exist</Error>"}
        result = takeover.check("cdn.example.com", resolver=resolver, fetch=fetch)
        self.assertEqual(result["status"], "vulnerable")
        self.assertEqual(result["service"], "AWS/S3")
        self.assertIn("The specified bucket does not exist", result["evidence"])

    def test_nxdomain_service_is_vulnerable(self):
        resolver = lambda name: _chain(name, "app.elasticbeanstalk.com",
                                       addresses=(), nxdomain=True)
        fetch = mock.Mock(side_effect=AssertionError("must not fetch on NXDOMAIN"))
        result = takeover.check("app.example.com", resolver=resolver, fetch=fetch)
        self.assertEqual(result["status"], "vulnerable")
        self.assertEqual(result["matched_fingerprint"], "NXDOMAIN")
        fetch.assert_not_called()

    def test_claimed_service(self):
        resolver = lambda name: _chain(name, "site.agilecrm.com")
        fetch = lambda url: {"status": 200, "body": "<html>Welcome to a real app</html>"}
        result = takeover.check("crm.example.com", resolver=resolver, fetch=fetch)
        self.assertEqual(result["status"], "claimed")

    def test_fingerprint_only_body_is_a_candidate(self):
        resolver = lambda name: _chain(name, "pages.example.net")
        fetch = lambda url: {"status": 404,
                             "body": "404 There isn't a GitHub Pages site here."}
        result = takeover.check("blog.example.net", resolver=resolver, fetch=fetch)
        self.assertEqual(result["status"], "candidate")
        self.assertTrue(result["matched_fingerprint"])

    def test_no_known_service_answers_normally(self):
        resolver = lambda name: _chain(name, "origin.internal.example")
        fetch = lambda url: {"status": 200, "body": "<html>a normal site</html>"}
        result = takeover.check("www.example.com", resolver=resolver, fetch=fetch)
        self.assertEqual(result["status"], "no_match")

    def test_no_cname_chain_is_not_fetched(self):
        resolver = lambda name: _chain(name)
        fetch = mock.Mock(side_effect=AssertionError("no CNAME, no fetch"))
        result = takeover.check("www.example.com", resolver=resolver, fetch=fetch)
        self.assertEqual(result["status"], "no_match")
        fetch.assert_not_called()

    def test_dns_error_is_unresolvable(self):
        from netcast3r import dnsq

        def resolver(name):
            raise dnsq.DnsError("timeout")

        result = takeover.check("www.example.com", resolver=resolver,
                                fetch=mock.Mock())
        self.assertEqual(result["status"], "unresolvable")


class ScanTests(unittest.TestCase):
    def test_scan_ranks_vulnerable_first(self):
        chains = {
            "a.example.com": _chain("a.example.com", "b.s3.amazonaws.com"),
            "b.example.com": _chain("b.example.com", "c.agilecrm.com"),
            "c.example.com": _chain("c.example.com", "origin.example.org"),
        }
        bodies = {
            "https://a.example.com/": "The specified bucket does not exist",
            "https://b.example.com/": "normal application",
        }
        result = takeover.scan(
            ["c.example.com", "b.example.com", "a.example.com"],
            resolver=lambda name: chains[name],
            fetch=lambda url: {"status": 200, "body": bodies.get(url, "")})
        self.assertEqual(result["checked"], 3)
        self.assertEqual(result["results"][0]["status"], "vulnerable")
        self.assertEqual(result["counts"].get("vulnerable"), 1)
        self.assertEqual(result["counts"].get("claimed"), 1)

    def test_scan_dedupes_and_limits(self):
        result = takeover.scan(["a.example.com", "a.example.com"],
                               resolver=lambda name: _chain(name),
                               fetch=lambda url: {"status": 200, "body": ""})
        self.assertEqual(result["checked"], 1)


if __name__ == "__main__":
    unittest.main()
