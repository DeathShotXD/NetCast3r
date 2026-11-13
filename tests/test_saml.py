import base64
import unittest

from netcast3r import saml

UNSIGNED = ('<samlp:Response><saml:Assertion ID="a1">'
            "<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>"
            "</saml:Assertion></samlp:Response>")

SIGNED = ('<samlp:Response><saml:Assertion ID="a1">'
          "<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>"
          "<ds:Signature><ds:SignedInfo>"
          '<ds:Reference URI="#a1"/></ds:SignedInfo></ds:Signature>'
          "<saml:Conditions NotOnOrAfter=\"2999-01-01T00:00:00Z\">"
          "<saml:AudienceRestriction><saml:Audience>sp</saml:Audience>"
          "</saml:AudienceRestriction></saml:Conditions>"
          "</saml:Assertion></samlp:Response>")


class AnalyzeTests(unittest.TestCase):
    def test_unsigned_response(self):
        result = saml.analyze(UNSIGNED)
        ids = {row["id"] for row in result["findings"]}
        self.assertIn("unsigned_response", ids)
        self.assertIn("missing_audience", ids)
        self.assertIn("missing_notonorafter", ids)

    def test_signed_response_has_no_signature_findings(self):
        result = saml.analyze(SIGNED)
        ids = {row["id"] for row in result["findings"]}
        self.assertNotIn("unsigned_response", ids)
        self.assertNotIn("signature_not_over_assertion", ids)
        self.assertEqual(result["shape"]["signatures"], 1)

    def test_multiple_assertions(self):
        text = UNSIGNED.replace("</samlp:Response>",
                                '<saml:Assertion ID="a2"></saml:Assertion>'
                                "</samlp:Response>")
        ids = {row["id"] for row in saml.analyze(text)["findings"]}
        self.assertIn("multiple_assertions", ids)

    def test_signature_not_over_assertion(self):
        text = UNSIGNED.replace("<samlp:Response>",
                                '<samlp:Response><ds:Signature>'
                                '<ds:Reference URI="#other"/></ds:Signature>')
        ids = {row["id"] for row in saml.analyze(text)["findings"]}
        self.assertIn("signature_not_over_assertion", ids)

    def test_comment_injection(self):
        text = UNSIGNED.replace("user@example.com", "admin@example.com<!-- -->")
        ids = {row["id"] for row in saml.analyze(text)["findings"]}
        self.assertIn("comment_injection", ids)

    def test_entity_is_reported_not_expanded(self):
        text = ('<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + UNSIGNED)
        ids = {row["id"] for row in saml.analyze(text)["findings"]}
        self.assertIn("xxe_entity", ids)

    def test_base64_input(self):
        encoded = base64.b64encode(SIGNED.encode()).decode()
        result = saml.analyze(encoded)
        self.assertEqual(result["shape"]["signatures"], 1)

    def test_empty_input(self):
        self.assertIn("error", saml.analyze(""))

    def test_summary(self):
        self.assertIn("multiple_assertions", saml.summary()["checks"])


if __name__ == "__main__":
    unittest.main()
