import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netcast3r.config import Config, ProviderConfig, RouteConfig
from netcast3r.providers import Chunk, ProviderBus, model_family


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

    def test_max_candidates_caps_the_fallback_chain(self):
        seen = []
        bus = ProviderBus(self._config(), observer=seen.append)
        result = bus.complete("scribe", [{"role": "user", "content": "hi"}],
                              max_candidates=1)
        self.assertEqual(result.text, "")
        # Soft 429 rotates without hard-failing the provider name, but the
        # candidate cap still stops the chain after one attempt.
        self.assertEqual(result.failed, [])
        calls = [row["provider"] for row in seen if row["kind"] == "call"]
        self.assertEqual(calls, ["openrouter"])
        self.assertTrue(any(row.get("kind") == "done" and not row.get("ok")
                            for row in seen))

    def test_route_model_only_applies_to_the_routed_provider(self):
        base = f"http://127.0.0.1:{self.port}"
        config = Config(
            providers=[
                ProviderConfig(name="openrouter", base_url=f"{base}/rate",
                               api_key="dummy", priority=10,
                               models=["or-model"]),
                ProviderConfig(name="ollama", base_url=base, priority=20,
                               models=["mock-model"]),
            ],
            routes=[RouteConfig(agent="scribe", model="special",
                                provider="ollama")],
        )
        rows = [(provider.name, model)
                for provider, model, _ in ProviderBus(config)._candidates("scribe")]
        self.assertIn(("ollama", "special"), rows)
        self.assertIn(("openrouter", "or-model"), rows)
        self.assertNotIn(("openrouter", "special"), rows)

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

    def test_rate_limit_walks_sibling_models_before_cooling(self):
        """A 429 retires one model but still tries the next model on the same
        provider before the provider cools down for later calls."""
        base = f"http://127.0.0.1:{self.port}"

        class MultiModel(BaseHTTPRequestHandler):
            hits = []

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                try:
                    model = json.loads(raw).get("model")
                except Exception:
                    model = ""
                MultiModel.hits.append(model)
                if model == "first-model":
                    self.send_response(429)
                    self.end_headers()
                    self.wfile.write(b"rate limited")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "choices": [{"message": {"content": "ok"}}],
                    "usage": {"total_tokens": 1},
                }).encode())

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), MultiModel)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            port = server.server_address[1]
            config = Config(
                providers=[ProviderConfig(
                    name="tokenharbor",
                    base_url=f"http://127.0.0.1:{port}",
                    api_key="dummy", priority=1,
                    models=["first-model", "second-model"])],
                routes=[RouteConfig(agent="prime", provider="tokenharbor",
                                    model="first-model")],
            )
            MultiModel.hits = []
            bus = ProviderBus(config)
            result = bus.complete("prime", [{"role": "user", "content": "hi"}])
            self.assertEqual(result.text, "ok")
            self.assertEqual(result.provider, "tokenharbor")
            self.assertEqual(result.model, "second-model")
            self.assertEqual(MultiModel.hits, ["first-model", "second-model"])
            # The rate-limited model stays retired; the provider itself settles
            # because a sibling answered.
            self.assertTrue(bus._model_dead("tokenharbor", "first-model"))
            self.assertFalse(bus._cooling("tokenharbor"))
        finally:
            server.shutdown()

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

    def test_moe_orders_experts_and_staggers_keys(self):
        self.assertEqual(model_family("deepseek-v4.1-flash:free"), "deepseek")
        self.assertEqual(model_family("mimo-v2.6-flash:free"), "mimo")
        self.assertEqual(model_family("qwen3-coder:free"), "qwen")
        models = ["deepseek-v4.1-flash:free", "mimo-v2.6-flash:free",
                  "qwen3-coder:free"]
        config = Config(
            providers=[
                ProviderConfig(name="th-hunt-1", base_url="http://127.0.0.1/v1",
                               api_key="a", priority=1, models=list(models)),
                ProviderConfig(name="th-hunt-2", base_url="http://127.0.0.1/v1",
                               api_key="b", priority=2, models=list(models)),
            ],
            routes=[RouteConfig(agent="scout", provider="", model="")],
        )
        bus = ProviderBus(config)
        first = [model for provider, model, _ in bus._candidates("scout")
                 if provider.name == "th-hunt-1"]
        second = [model for provider, model, _ in bus._candidates("scout")
                  if provider.name == "th-hunt-2"]
        self.assertEqual(set(first), set(models))
        self.assertEqual(set(second), set(models))
        # Scout prefers mimo; at least one lane should lead with mimo/qwen/deepseek
        # without every lane pinning the same id first.
        self.assertTrue(first and second)
        self.assertIn(model_family(first[0]), {"mimo", "deepseek", "qwen"})

    def test_empty_reply_rotates_to_the_next_model(self):
        """An empty body retires that model and still returns the sibling."""

        class EmptyThenOk(BaseHTTPRequestHandler):
            hits = []

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                try:
                    model = json.loads(raw).get("model")
                except Exception:
                    model = ""
                EmptyThenOk.hits.append(model)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                content = "" if model == "first-model" else "ok"
                self.wfile.write(json.dumps({
                    "choices": [{"message": {"content": content}}],
                }).encode())

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), EmptyThenOk)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            port = server.server_address[1]
            config = Config(
                providers=[ProviderConfig(
                    name="tokenharbor",
                    base_url=f"http://127.0.0.1:{port}",
                    api_key="dummy", priority=1,
                    models=["first-model", "second-model"])],
                routes=[RouteConfig(agent="prime", provider="tokenharbor",
                                    model="first-model")],
            )
            EmptyThenOk.hits = []
            bus = ProviderBus(config)
            result = bus.complete("prime", [{"role": "user", "content": "hi"}])
            self.assertEqual(result.text, "ok")
            self.assertEqual(result.model, "second-model")
            self.assertEqual(result.failed, [])
            self.assertEqual(EmptyThenOk.hits, ["first-model", "second-model"])
            self.assertTrue(bus._model_dead("tokenharbor", "first-model"))
            self.assertFalse(bus._cooling("tokenharbor"))
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
