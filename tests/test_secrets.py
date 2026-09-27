import re
import unittest

from netcast3r.secrets import Extractor, Pattern, shannon_entropy


class EntropyTests(unittest.TestCase):
    def test_low_entropy_below_high_entropy(self):
        self.assertLess(shannon_entropy("aaaaaaaa"), shannon_entropy("a8Fk2pQ9xZ"))


class ExtractorTests(unittest.TestCase):
    def setUp(self):
        self.extractor = Extractor()

    def test_finds_aws_key(self):
        text = 'const key = "AWS_KEY_PLACEHOLDER";'
        found = self.extractor.scan(text, source="app.js")
        types = {secret.type for secret in found}
        self.assertIn("aws", types)

    def test_finds_jwt(self):
        text = "token=JWT_PLACEHOLDER"
        found = self.extractor.scan(text)
        self.assertIn("jwt", {secret.type for secret in found})

    def test_finds_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        found = self.extractor.scan(text)
        self.assertIn("private_key", {secret.type for secret in found})

    def test_dedupes(self):
        text = "AWS_KEY_PLACEHOLDER AWS_KEY_PLACEHOLDER"
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


if __name__ == "__main__":
    unittest.main()
