import unittest

from netcast3r import oauth


class AuthorizeTests(unittest.TestCase):
    def test_implicit_flow_missing_state_nested_redirect(self):
        url = ("https://idp.example.com/authorize?client_id=abc"
               "&response_type=token"
               "&redirect_uri=" + "https%3A%2F%2Fapp.example.com%2Fcb%3Fnext%3D"
               "https%3A%2F%2Fevil.example"
               "&scope=openid")
        result = oauth.analyze_authorize(url)
        ids = {row["id"] for row in result["findings"]}
        self.assertIn("implicit_flow", ids)
        self.assertIn("missing_state", ids)
        self.assertIn("nested_redirect", ids)
        self.assertIn("missing_nonce", ids)
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_userinfo_and_wildcard_redirect(self):
        url = ("https://idp.example.com/authorize?client_id=a&response_type=code"
               "&state=xyz&redirect_uri=https%3A%2F%2Fapp.example.com%40evil.example%2Fcb")
        ids = {row["id"] for row in oauth.analyze_authorize(url)["findings"]}
        self.assertIn("userinfo_redirect_uri", ids)
        wildcard = ("https://idp.example.com/authorize?client_id=a&response_type=code"
                    "&state=x&redirect_uri=https%3A%2F%2F*.example.com%2Fcb")
        ids2 = {row["id"] for row in oauth.analyze_authorize(wildcard)["findings"]}
        self.assertIn("wildcard_redirect_uri", ids2)

    def test_missing_pkce_on_code_flow(self):
        url = "https://idp.example.com/authorize?client_id=a&response_type=code&state=x"
        ids = {row["id"] for row in oauth.analyze_authorize(url)["findings"]}
        self.assertIn("missing_pkce", ids)


class MutationTests(unittest.TestCase):
    def test_suffix_host_mutation_uses_canary(self):
        mutations = oauth.redirect_uri_mutations("https://app.example.com/cb")
        kinds = {row["kind"]: row["value"] for row in mutations}
        self.assertIn("suffix_host", kinds)
        self.assertIn(oauth.CANARY_HOST, kinds["suffix_host"])
        self.assertIn("userinfo", kinds)

    def test_probe_accepts_canary_redirect(self):
        def fetch(url, headers):
            if oauth.CANARY_HOST in url and "suffix_host" in url:
                return {"status": 302, "headers": {"location":
                        f"https://app.example.com.{oauth.CANARY_HOST}/cb?code=A"}}
            if oauth.CANARY_HOST in url:
                return {"status": 302, "headers": {"location": f"https://app.example.com.{oauth.CANARY_HOST}/cb"}}
            return {"status": 200, "headers": {}}

        # Only the suffix_host mutation should resolve to the canary host.
        mutations = [row for row in oauth.redirect_uri_mutations(
            "https://app.example.com/cb") if row["kind"] == "suffix_host"]
        result = oauth.probe_redirect(
            "https://idp.example.com/authorize?client_id=a&response_type=code"
            "&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
            fetch=fetch, mutations=mutations)
        self.assertEqual(result["tested"], 1)
        self.assertTrue(result["accepted"][0]["accepted"])


class CallbackTests(unittest.TestCase):
    def test_token_in_url(self):
        result = oauth.analyze_callback(
            "https://app.example.com/callback?access_token=SECRETVALUE")
        ids = {row["id"] for row in result["findings"]}
        self.assertIn("token_in_url", ids)

    def test_code_without_state(self):
        result = oauth.analyze_callback("https://app.example.com/callback?code=abc")
        ids = {row["id"] for row in result["findings"]}
        self.assertIn("code_without_state", ids)


class AuditTests(unittest.TestCase):
    def test_unknown_kind_for_business_url(self):
        result = oauth.audit("https://shop.example.com/account")
        self.assertEqual(result["kind"], "unknown")
        self.assertEqual(result["findings"], [])

    def test_authorize_kind_includes_mutations(self):
        result = oauth.audit(
            "https://idp.example.com/authorize?client_id=a&response_type=code"
            "&state=x&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb")
        self.assertEqual(result["kind"], "authorize")
        self.assertTrue(result["mutations"])

    def test_summary(self):
        self.assertIn("implicit_flow", oauth.summary()["checks"])


if __name__ == "__main__":
    unittest.main()
