import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import httpx

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import tempmail


class MailboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.calls = []

    def tearDown(self):
        for child in self.tmp.rglob("*"):
            if child.is_file():
                child.unlink()
        for child in sorted(self.tmp.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        self.tmp.rmdir()

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        path = request.url.path
        if path == "/domains":
            return httpx.Response(200, json=[{"domain": "maxxspace.com", "isActive": True}])
        if path == "/accounts":
            body = json.loads(request.content or b"{}")
            return httpx.Response(201, json={"id": "box-1", "address": body["address"]})
        if path == "/token":
            return httpx.Response(200, json={"token": "tok-1"})
        if path == "/messages":
            return httpx.Response(200, json={"hydra:member": [{
                "id": "m1", "from": {"address": "noreply@example.com", "name": "Example"},
                "subject": "Confirm your account", "intro": "Click below",
                "createdAt": "2026-10-29T02:00:00+00:00", "seen": False,
            }]})
        if path == "/messages/m1":
            return httpx.Response(200, json={
                "id": "m1", "from": {"address": "noreply@example.com", "name": "Example"},
                "to": [{"address": "box@maxxspace.com"}],
                "subject": "Confirm your account",
                "createdAt": "2026-10-29T02:00:00+00:00",
                "text": "Open https://example.com/verify?token=abc&x=1.",
                "html": ["<p><a href=\"https://example.com/verify?token=abc&amp;x=1\">Verify</a></p>"],
                "attachments": [],
            })
        return httpx.Response(404, json={"message": "not found"})

    def transport(self):
        return httpx.MockTransport(self.handler)

    def test_create_read_and_links(self):
        box = tempmail.create_mailbox(base=self.tmp, transport=self.transport())
        self.assertTrue(box.address.endswith("@maxxspace.com"))
        self.assertNotIn("token", box.public())
        self.assertNotIn("password", box.public())
        state = self.tmp / tempmail.STORE_NAME
        mode = stat.S_IMODE(state.stat().st_mode)
        self.assertEqual(mode, 0o600)

        client = tempmail.MailClient(transport=self.transport())
        rows = client.messages(box, base=self.tmp)
        self.assertEqual(rows[0]["subject"], "Confirm your account")
        message = client.read(box, "m1", base=self.tmp)
        self.assertEqual(message["from"], "noreply@example.com")
        self.assertIn("https://example.com/verify?token=abc&x=1", message["links"])
        self.assertFalse(any(link.endswith(".") for link in message["links"]))

    def test_token_refresh_on_401(self):
        box = tempmail.Mailbox(id="box-1", address="box@maxxspace.com",
                               password="pw", token="stale", created_at=1.0)
        tempmail.save_mailbox(box, base=self.tmp)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/messages":
                if request.headers.get("authorization") != "Bearer fresh":
                    return httpx.Response(401, json={"message": "expired"})
                return httpx.Response(200, json={"hydra:member": []})
            if request.url.path == "/token":
                return httpx.Response(200, json={"token": "fresh"})
            return httpx.Response(404)

        client = tempmail.MailClient(transport=httpx.MockTransport(handler))
        rows = client.messages(box, base=self.tmp)
        self.assertEqual(rows, [])
        self.assertEqual(tempmail.get_mailbox("box-1", base=self.tmp).token, "fresh")

    def test_wait_for_matching_message(self):
        state = {"polls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/token":
                return httpx.Response(200, json={"token": "tok-1"})
            if request.url.path == "/messages":
                state["polls"] += 1
                if state["polls"] < 2:
                    return httpx.Response(200, json={"hydra:member": []})
                return httpx.Response(200, json={"hydra:member": [{
                    "id": "m1", "from": {"address": "noreply@example.com"},
                    "subject": "Confirm your account", "intro": "",
                    "createdAt": "2026-10-29T02:00:00+00:00",
                }]})
            if request.url.path == "/messages/m1":
                return httpx.Response(200, json={
                    "id": "m1", "from": {"address": "noreply@example.com"},
                    "subject": "Confirm your account", "text": "verify me",
                })
            return httpx.Response(404)

        box = tempmail.Mailbox(id="box-1", address="box@maxxspace.com",
                               password="pw", token="tok-1", created_at=1.0)
        client = tempmail.MailClient(transport=httpx.MockTransport(handler))
        message = client.wait(box, base=self.tmp, timeout=6, interval=2,
                              match="confirm")
        self.assertIsNotNone(message)
        self.assertEqual(message["id"], "m1")


if __name__ == "__main__":
    unittest.main()
