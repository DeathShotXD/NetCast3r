import unittest

from netcast3r import wsprobe

UPGRADE = (b"HTTP/1.1 101 Switching Protocols\r\n"
           b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
           b"Sec-WebSocket-Accept: abc\r\n\r\n")
REFUSE = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"


def _origin(request: str) -> str:
    for line in request.split("\r\n"):
        if line.lower().startswith("origin:"):
            return line.split(":", 1)[1].strip()
    return ""


class BuildTests(unittest.TestCase):
    def test_upgrade_request_has_required_headers(self):
        request = wsprobe.build_upgrade("app.example.com", "/chat",
                                        origin="https://app.example.com",
                                        port=443, cookie="sid=1")
        self.assertIn("GET /chat HTTP/1.1", request)
        self.assertIn("Upgrade: websocket", request)
        self.assertIn("Sec-WebSocket-Version: 13", request)
        self.assertIn("Origin: https://app.example.com", request)
        self.assertIn("Cookie: sid=1", request)

    def test_origin_omitted_when_none(self):
        request = wsprobe.build_upgrade("app.example.com", "/")
        self.assertNotIn("Origin:", request)


class ParseTests(unittest.TestCase):
    def test_101_is_an_upgrade(self):
        parsed = wsprobe.parse_response(UPGRADE)
        self.assertEqual(parsed["status"], 101)
        self.assertTrue(parsed["upgraded"])

    def test_403_is_not(self):
        self.assertFalse(wsprobe.parse_response(REFUSE)["upgraded"])

    def test_garbage(self):
        self.assertEqual(wsprobe.parse_response(b"nope")["status"], 0)


class ProbeTests(unittest.TestCase):
    def _transport(self, accept_hostile):
        def transport(host, port, path, request, use_tls):
            origin = _origin(request)
            same = origin.startswith("https://app.example.com")
            if same or (accept_hostile and origin):
                return UPGRADE
            return REFUSE
        return transport

    def test_cswsh_when_hostile_origin_accepted(self):
        result = wsprobe.probe("wss://app.example.com/chat",
                               transport=self._transport(True))
        self.assertEqual(result["verdict"], "cswsh")
        self.assertIn("https://nc3r-canary.invalid", result["hijackable_origins"])

    def test_origin_checked_when_hostile_refused(self):
        result = wsprobe.probe("wss://app.example.com/chat",
                               transport=self._transport(False))
        self.assertEqual(result["verdict"], "origin_checked")
        self.assertEqual(result["hijackable_origins"], [])

    def test_not_websocket_when_no_upgrade(self):
        result = wsprobe.probe("wss://app.example.com/",
                               transport=lambda *a: REFUSE)
        self.assertEqual(result["verdict"], "not_websocket")

    def test_transport_error_is_recorded(self):
        def transport(*args):
            raise OSError("connection refused")
        result = wsprobe.probe("wss://app.example.com/", transport=transport)
        self.assertEqual(result["verdict"], "not_websocket")
        self.assertTrue(result["results"][0].get("error"))

    def test_missing_host(self):
        result = wsprobe.probe("", transport=lambda *a: UPGRADE)
        self.assertFalse(result["ok"])

    def test_summary(self):
        self.assertIn("cswsh", wsprobe.summary()["checks"])


if __name__ == "__main__":
    unittest.main()
