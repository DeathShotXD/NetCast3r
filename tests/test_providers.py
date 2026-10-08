import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netcast3r.config import Config, ProviderConfig, RouteConfig
from netcast3r.providers import Chunk, ProviderBus


class StreamHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path.startswith("/rate"):
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"rate limited")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        events = [
            {"choices": [{"delta": {"reasoning": "weighing options"}}]},
            {"choices": [{"delta": {"content": "Hello"}}]},
            {"choices": [{"delta": {"content": " world"}}]},
        ]
        for event in events:
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")

    def log_message(self, *args):
        pass


class ProviderBusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), StreamHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _config(self):
        base = f"http://127.0.0.1:{self.port}"
        return Config(
            providers=[
                ProviderConfig(name="openrouter", base_url=f"{base}/rate", api_key="dummy", priority=10),
                ProviderConfig(name="ollama", base_url=base, priority=20, models=["mock-model"]),
            ],
            routes=[RouteConfig(agent="scribe", model="mock-model", provider="")],
        )

    def test_streams_content_and_reasoning(self):
        bus = ProviderBus(self._config())
        chunks = []
        result = bus.chat_stream("scribe", [{"role": "user", "content": "hi"}], on_chunk=chunks.append)
        self.assertEqual(result, "Hello world")
        kinds = {chunk.kind for chunk in chunks}
        self.assertIn("reasoning", kinds)
        self.assertIn("content", kinds)
        self.assertIn("done", kinds)

    def test_falls_back_after_rate_limit(self):
        bus = ProviderBus(self._config())
        done = []
        bus.chat_stream("scribe", [{"role": "user", "content": "hi"}],
                        on_chunk=lambda chunk: done.append(chunk) if chunk.kind == "done" else None)
        self.assertTrue(done)
        self.assertEqual(done[0].text, "ollama")

    def test_observer_sees_every_attempt(self):
        seen = []
        bus = ProviderBus(self._config(), observer=seen.append)
        bus.chat_stream("scribe", [{"role": "user", "content": "hi"}])
        kinds = [row["kind"] for row in seen]
        self.assertEqual(kinds, ["call", "done", "call", "done"])
        self.assertFalse(seen[1]["ok"])
        self.assertEqual(seen[1]["provider"], "openrouter")
        self.assertTrue(seen[3]["ok"])
        self.assertEqual(seen[3]["provider"], "ollama")
        self.assertGreaterEqual(seen[3]["ms"], 0)

    def test_rate_limited_provider_cools_down(self):
        seen = []
        bus = ProviderBus(self._config(), observer=seen.append)
        bus.chat_stream("scribe", [{"role": "user", "content": "hi"}])
        bus.chat_stream("scribe", [{"role": "user", "content": "hi"}])
        calls = [row["provider"] for row in seen if row["kind"] == "call"]
        self.assertEqual(calls, ["openrouter", "ollama", "ollama"])

    def test_cooldown_escalates_and_clears(self):
        import time as _time

        bus = ProviderBus(self._config())
        bus._penalize("openrouter")
        first = bus._cooldown["openrouter"][0] - _time.monotonic()
        self.assertAlmostEqual(first, bus.COOLDOWN_BASE, delta=2)
        bus._penalize("openrouter")
        second = bus._cooldown["openrouter"][0] - _time.monotonic()
        self.assertAlmostEqual(second, bus.COOLDOWN_BASE * 2, delta=2)
        self.assertTrue(bus._cooling("openrouter"))
        bus._settle("openrouter")
        self.assertFalse(bus._cooling("openrouter"))


if __name__ == "__main__":
    unittest.main()
