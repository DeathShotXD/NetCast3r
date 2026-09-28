import tempfile
import unittest
from pathlib import Path

from netcast3r.wordlist import Wordlist


class WordlistTests(unittest.TestCase):
    def test_extracts_words_and_filters_stopwords(self):
        words = Wordlist()
        words.add_text("const invoiceTotal = 1; const self = true; return value;")
        result = words.words()
        self.assertIn("invoiceTotal", result)
        self.assertIn("invoicetotal", result)
        self.assertIn("value", result)
        self.assertNotIn("const", result)
        self.assertNotIn("return", result)

    def test_url_segments_and_params(self):
        words = Wordlist()
        words.add_url("https://target.test/api/v2/user-profile?id=1&accountId=2")
        result = words.words()
        self.assertIn("api", result)
        self.assertIn("user-profile", result)
        self.assertIn("accountId", result)

    def test_save(self):
        words = Wordlist()
        words.add_text("checkoutPayment")
        workdir = Path(tempfile.mkdtemp())
        path = words.save(workdir / "wordlist.txt")
        self.assertTrue(path.exists())
        self.assertIn("checkoutPayment", path.read_text())


if __name__ == "__main__":
    unittest.main()
