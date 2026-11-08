# codeaudit: ignore-file py-private-key,py-hardcoded-secret -- deliberate fixtures
import re
import unittest

from netcast3r.secrets import Extractor, Pattern, shannon_entropy

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
JWT = ".".join([
    "eyJhbGciOiJIUzI1NiJ9",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
])


class EntropyTests(unittest.TestCase):
    def test_low_entropy_below_high_entropy(self):
        self.assertLess(shannon_entropy("aaaaaaaa"), shannon_entropy("a8Fk2pQ9xZ"))


class ExtractorTests(unittest.TestCase):
    def setUp(self):
        self.extractor = Extractor()

    def test_finds_aws_key(self):
        text = f'const key = "{AWS_KEY}";'
        found = self.extractor.scan(text, source="app.js")
        types = {secret.type for secret in found}
        self.assertIn("aws", types)

    def test_finds_jwt(self):
        text = f"token={JWT}"
        found = self.extractor.scan(text)
        self.assertIn("jwt", {secret.type for secret in found})

    def test_finds_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        found = self.extractor.scan(text)
        self.assertIn("private_key", {secret.type for secret in found})

    def test_dedupes(self):
        text = f"{AWS_KEY} {AWS_KEY}"
        found = self.extractor.scan(text)
        aws = [secret for secret in found if secret.type == "aws"]
        self.assertEqual(len(aws), 1)

    def test_entropy_filter_on_generic(self):
        pattern = Pattern(id="gen", type="generic", regex=re.compile(r'secret\s*=\s*"([A-Za-z0-9]{12,64})"'),
                          entropy=3.2)
        extractor = Extractor(patterns=[pattern])
        weak = extractor.scan('secret = "aaaaaaaaaaaa"')
        strong = extractor.scan('secret = "a8Fk2pQ9xZ7mB4n"')
        self.assertEqual(len(weak), 0)
        self.assertEqual(len(strong), 1)

    def test_a_keyword_inside_a_longer_keyword_still_opens_a_window(self):
        # The alternation matches "access_token" as one word. The "token"
        # pattern must still see its own keyword inside that span.
        short = Pattern(id="short", type="short",
                        regex=re.compile(r'token\s*=\s*"([A-Za-z0-9]{12,64})"'),
                        keywords=["token"])
        long = Pattern(id="long", type="long",
                       regex=re.compile(r'access_token\s*=\s*"([A-Za-z0-9]{12,64})"'),
                       keywords=["access_token"])
        extractor = Extractor(patterns=[short, long])
        found = extractor.scan('access_token = "a8Fk2pQ9xZ7mB4n"')
        self.assertEqual({secret.type for secret in found}, {"short", "long"})


if __name__ == "__main__":
    unittest.main()
