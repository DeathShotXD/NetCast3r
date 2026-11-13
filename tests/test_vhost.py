import unittest

from netcast3r import vhost


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_uses_status_length_hash_title(self):
        a = vhost.fingerprint({"status": 200, "body": "<html><title>Home</title></html>"})
        b = vhost.fingerprint({"status": 200, "body": "<html><title>Home</title></html>"})
        c = vhost.fingerprint({"status": 404, "body": "<html><title>Home</title></html>"})
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(a[0], 200)
        self.assertEqual(a[3], "Home")


class CandidateTests(unittest.TestCase):
    def test_explicit_hosts_come_first_and_prefixes_derive(self):
        names = vhost.candidates("https://app.example.com", ["x.example.com"],
                                 ["dev", "api"], 10)
        self.assertEqual(names, ["x.example.com", "dev.example.com", "api.example.com"])

    def test_empty_prefixes_do_not_expand(self):
        names = vhost.candidates("https://app.example.com", ["a.example.com"], (), 10)
        self.assertEqual(names, ["a.example.com"])

    def test_limit_applies(self):
        names = vhost.candidates("https://example.com", [], ["a", "b", "c"], 2)
        self.assertEqual(len(names), 2)


class DiscoverTests(unittest.TestCase):
    BASE = "https://app.example.com/"
    PAGES = {
        "app.example.com": (200, "<html><title>App</title></html>"),
        "dev.example.com": (200, "<html><title>Dev Portal</title>a lot more text here</html>"),
    }
    WILDCARD = (200, "<html><title>Welcome</title></html>")

    def _fetch(self, wildcard=True):
        def fetch(url, headers):
            host = (headers or {}).get("Host", "app.example.com")
            if host == "app.example.com" and not headers:
                return {"status": 200, "body": self.PAGES["app.example.com"][1]}
            if host in self.PAGES:
                status, body = self.PAGES[host]
                return {"status": status, "body": body}
            if host == "timeout.example.com":
                return {"status": 0, "body": "", "error": "timed out"}
            if wildcard:
                return {"status": self.WILDCARD[0], "body": self.WILDCARD[1]}
            return {"status": 200, "body": self.PAGES["app.example.com"][1]}
        return fetch

    def test_virtual_host_from_different_page(self):
        result = vhost.discover(self.BASE,
                                hosts=["app.example.com", "dev.example.com"],
                                prefixes=(), fetch=self._fetch(wildcard=False))
        rows = {row["host"]: row for row in result["results"]}
        self.assertEqual(rows["dev.example.com"]["status"], "virtual_host")
        self.assertEqual(rows["app.example.com"]["status"], "default")
        self.assertEqual(result["counts"]["virtual_host"], 1)
        self.assertEqual(result["virtual_hosts"][0]["title"], "Dev Portal")

    def test_wildcard_is_detected_and_labelled(self):
        result = vhost.discover(self.BASE,
                                hosts=["dev.example.com", "gone.example.com"],
                                prefixes=(), fetch=self._fetch(wildcard=True))
        rows = {row["host"]: row for row in result["results"]}
        self.assertEqual(rows["dev.example.com"]["status"], "virtual_host")
        self.assertEqual(rows["gone.example.com"]["status"], "wildcard")
        self.assertIsNotNone(result["wildcard"])
        self.assertEqual(result["counts"]["wildcard"], 1)

    def test_fetch_error_is_recorded(self):
        result = vhost.discover(self.BASE, hosts=["timeout.example.com"],
                                prefixes=(), fetch=self._fetch())
        self.assertEqual(result["results"][0]["status"], "error")
        self.assertEqual(result["counts"]["error"], 1)

    def test_unknown_base_host(self):
        result = vhost.discover("", hosts=["x"], prefixes=(),
                                fetch=self._fetch())
        self.assertEqual(result["checked"], 0)
        self.assertIn("host", result["note"])

    def test_default_prefix_set_expands_when_not_given(self):
        seen = []

        def fetch(url, headers):
            seen.append((headers or {}).get("Host"))
            return {"status": 200, "body": "same"}

        vhost.discover("https://app.example.com", hosts=[], prefixes=None,
                       fetch=fetch, limit=5, random_probe=False)
        self.assertIn("www.example.com", seen)


if __name__ == "__main__":
    unittest.main()
