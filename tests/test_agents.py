import unittest

from netcast3r.agents import Scribe


class _Bus:
    def __init__(self):
        self.sent = []

    def _candidates(self, name):
        return ["mock"]

    def chat_stream(self, name, messages, on_chunk=None):
        self.sent.append((name, messages))
        return "narrative"


class ScribeTests(unittest.TestCase):
    def test_the_raw_secret_never_reaches_the_model(self):
        bus = _Bus()
        scribe = Scribe(bus)
        finding = {
            "title": "AWS key exposed",
            "severity": "high",
            "secret_type": "aws_access_key",
            "value": "AKIAIOSFODNN7EXAMPLE",
            "proof": "the response echoed AKIAIOSFODNN7EXAMPLE back",
            "source": "https://target/app.js",
        }
        result = scribe.write(finding)
        self.assertEqual(result.text, "narrative")
        content = bus.sent[0][1][1]["content"]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", content)
        self.assertIn("AKIAIO...MPLE", content)


if __name__ == "__main__":
    unittest.main()
