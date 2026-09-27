import unittest

import httpx

from netcast3r.config import default_config
from netcast3r.http import Session, StopRun


class SessionTests(unittest.TestCase):
    def _session(self, handler, **overrides):
        config = default_config()
        config.run.retries = overrides.get("retries", 2)
        config.run.max_response_size = overrides.get("max_response_size", 5_000_000)
        config.run.stop_on_rate_limit = overrides.get("stop_on_rate_limit", True)
        client = httpx.Client(transport=httpx.MockTransport(handler))
        return Session(config, client=client)

    def test_retries_then_succeeds(self):
        state = {"calls": 0}

        def handler(request):
            state["calls"] += 1
            if state["calls"] < 3:
                return httpx.Response(503, text="busy")
            return httpx.Response(200, text="ok")

        session = self._session(handler)
        response = session.get("https://example.test/")
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "ok")

    def test_response_size_capped(self):
        def handler(request):
            return httpx.Response(200, text="x" * 1000)

        session = self._session(handler, max_response_size=10)
        response = session.get("https://example.test/")
        self.assertEqual(len(response.text), 10)

    def test_stats_recorded(self):
        def handler(request):
            return httpx.Response(200, text="ok")

        session = self._session(handler)
        session.get("https://example.test/")
        self.assertEqual(session.stats.requests, 1)
        self.assertEqual(session.stats.ok, 1)

    def test_stop_condition_on_rate_limit(self):
        def handler(request):
            return httpx.Response(429, text="slow down")

        session = self._session(handler, retries=0)
        with self.assertRaises(StopRun):
            for _ in range(25):
                session.get("https://example.test/")

    def test_no_response_returns_none(self):
        def handler(request):
            raise httpx.ConnectError("nope")

        session = self._session(handler, retries=0)
        self.assertIsNone(session.get("https://example.test/"))


if __name__ == "__main__":
    unittest.main()
