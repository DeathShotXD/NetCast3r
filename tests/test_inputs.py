import json
import tempfile
import unittest
from pathlib import Path

from netcast3r import inputs


def write(suffix: str, text: str) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    handle.write(text)
    handle.close()
    return Path(handle.name)


class InputTests(unittest.TestCase):
    def test_har(self):
        path = write(".har", json.dumps({"log": {"entries": [
            {"request": {"url": "https://a.test/app.js"},
             "response": {"content": {"text": "const x = 1;"}}}
        ]}}))
        source = inputs.load(path)
        self.assertIn("https://a.test/app.js", source.urls)
        self.assertEqual(source.bodies["https://a.test/app.js"], "const x = 1;")

    def test_burp(self):
        xml = ('<?xml version="1.0"?><items><item>'
               '<url>https://b.test/app.js</url>'
               '<response base64="false">const y = 2;</response>'
               '</item></items>')
        source = inputs.load(write(".xml", xml))
        self.assertIn("https://b.test/app.js", source.urls)
        self.assertIn("const y = 2;", source.bodies.get("https://b.test/app.js", ""))

    def test_zap(self):
        text = "==== 1 ==========\nGET https://c.test/app.js HTTP/1.1\n\nconst z = 3;\n"
        source = inputs.load(write(".txt", text))
        self.assertIn("https://c.test/app.js", source.urls)

    def test_caido_csv(self):
        source = inputs.load(write(".csv", "id,host,method,path\n1,d.test,GET,/app.js\n"))
        self.assertIn("https://d.test/app.js", source.urls)

    def test_plain(self):
        source = inputs.load(write(".txt", "https://e.test/app.js\n# note\nf.test\n"))
        self.assertIn("https://e.test/app.js", source.urls)
        self.assertIn("f.test", source.urls)


if __name__ == "__main__":
    unittest.main()
