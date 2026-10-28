import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import httpx

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import oast


class OastTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.requests = 0

    def tearDown(self):
        for child in self.tmp.rglob("*"):
            if child.is_file():
                child.unlink()
        for child in sorted(self.tmp.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        self.tmp.rmdir()

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/token":
            return httpx.Response(201, json={
                "uuid": "tok-1", "redirect": True})
        if request.method == "GET" and request.url.path == "/token/tok-1/requests":
            self.requests += 1
            return httpx.Response(200, json={"data": [{
                "uuid": "req-1", "method": "GET",
                "url": "https://webhook.site/tok-1/ssrf?url=http://169.254.169.254/",
                "content": "callback-body",
                "headers": {"user-agent": "curl/8"},
                "query": {"url": "http://169.254.169.254/"},
                "ip": "203.0.113.9", "user_agent": "curl/8",
                "created_at": "2026-10-29T02:00:00Z",
            }]})
        if request.method == "DELETE" and request.url.path == "/token/tok-1":
            return httpx.Response(204)
        return httpx.Response(404, json={"message": "not found"})

    def transport(self):
        return httpx.MockTransport(self.handler)

    def test_create_poll_and_delete(self):
        session = oast.create_session(base=self.tmp, label="ssrf", transport=self.transport())
        self.assertEqual(session.url, "https://webhook.site/tok-1")
        self.assertNotIn("token", session.public())
        mode = stat.S_IMODE((self.tmp / oast.STORE_NAME).stat().st_mode)
        self.assertEqual(mode, 0o600)

        client = oast.OastClient(transport=self.transport())
        items = client.poll(session, base=self.tmp)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["path"], "/tok-1/ssrf")
        self.assertEqual(items[0]["query"]["url"], "http://169.254.169.254/")
        self.assertEqual(items[0]["body"], "callback-body")
        self.assertGreater(items[0]["created_at"], 0)

        fresh = client.poll(session, base=self.tmp, since=items[0]["created_at"] + 1)
        self.assertEqual(fresh, [])
        self.assertTrue(client.delete(session, base=self.tmp))
        self.assertEqual(oast.list_sessions(base=self.tmp), [])

    def test_create_requires_a_token(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(200, json={"uuid": "", "url": ""}))
        with self.assertRaises(oast.OastError):
            oast.create_session(base=self.tmp, transport=transport)


if __name__ == "__main__":
    unittest.main()
