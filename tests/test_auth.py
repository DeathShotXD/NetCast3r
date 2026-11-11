import base64
import json
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import dashauth
from netcast3r.server import Server
from netcast3r.server.events import EventBus
from netcast3r.server.index import Index
from netcast3r.server.jobs import JobManager
from netcast3r.server.keys import KeyStore

TOKEN = "test-token"


def fake_runner(run_id, target, options, emit, should_stop):
    return {"target": target, "pages": 0, "findings": 0}


class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_login_is_created_and_hashed(self):
        record = dashauth.ensure_credentials(self.base)
        self.assertEqual(record["username"], "admin")
        self.assertTrue(dashauth.verify(self.base, "admin", "123"))
        self.assertFalse(dashauth.verify(self.base, "admin", "124"))
        self.assertFalse(dashauth.verify(self.base, "root", "123"))

        path = dashauth.credentials_path(self.base)
        self.assertTrue(path.exists())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        # The password must never be written in plain text.
        self.assertNotIn("123", path.read_text(encoding="utf-8"))

    def test_public_reports_default_until_changed(self):
        self.assertTrue(dashauth.public(self.base)["default"])
        dashauth.update_credentials(self.base, "operator", "hunter2")
        state = dashauth.public(self.base)
        self.assertFalse(state["default"])
        self.assertEqual(state["username"], "operator")
        self.assertTrue(dashauth.verify(self.base, "operator", "hunter2"))
        self.assertFalse(dashauth.verify(self.base, "admin", "123"))

    def test_update_rejects_empty_values(self):
        with self.assertRaises(ValueError):
            dashauth.update_credentials(self.base, "", "x")
        with self.assertRaises(ValueError):
            dashauth.update_credentials(self.base, "a", "")


class PasswordLoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.index = Index(self.base / "netcast3r.db")
        self.bus = EventBus()
        self.keys = KeyStore(self.base)
        self.jobs = JobManager(self.index, self.bus, fake_runner, workers=1)
        self.server = Server(self.index, self.bus, self.jobs, self.keys,
                             base=self.base, token=TOKEN)
        dashauth.ensure_credentials(self.base)

    def tearDown(self):
        self.jobs.shutdown()
        self.index.close()
        self.tmp.cleanup()

    def call(self, method, path, body=None, headers=None):
        merged = {"host": "127.0.0.1:7857"}
        merged.update(headers or {})
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, {}, merged, payload)

    def test_password_login_sets_the_session_cookie(self):
        res = self.call("POST", "/api/v1/session",
                        {"username": "admin", "password": "123"})
        self.assertEqual(res.status, 200)
        self.assertIn("netcast3r_token", res.headers.get("Set-Cookie", ""))

    def test_session_probe_is_unauthenticated_and_honest(self):
        res = self.call("GET", "/api/v1/session")
        self.assertEqual(res.status, 200)
        payload = json.loads(res.body)
        self.assertFalse(payload["authenticated"])
        self.assertTrue(payload["auth_required"])

        res = self.call("GET", "/api/v1/session",
                        headers={"x-netcast3r-token": TOKEN})
        self.assertEqual(res.status, 200)
        self.assertTrue(json.loads(res.body)["authenticated"])

    def test_wrong_password_is_rejected(self):
        res = self.call("POST", "/api/v1/session",
                        {"username": "admin", "password": "nope"})
        self.assertEqual(res.status, 401)

    def test_http_basic_auth_reaches_the_api(self):
        raw = base64.b64encode(b"admin:123").decode()
        res = self.call("GET", "/api/v1/meta",
                        headers={"authorization": "Basic " + raw})
        self.assertEqual(res.status, 200)

    def test_http_basic_auth_wrong_password_is_rejected(self):
        raw = base64.b64encode(b"admin:no").decode()
        res = self.call("GET", "/api/v1/meta",
                        headers={"authorization": "Basic " + raw})
        self.assertEqual(res.status, 401)

    def test_token_still_works(self):
        res = self.call("GET", "/api/v1/meta",
                        headers={"x-netcast3r-token": TOKEN})
        self.assertEqual(res.status, 200)

    def test_auth_state_and_credential_change(self):
        res = self.call("GET", "/api/v1/auth",
                        headers={"x-netcast3r-token": TOKEN})
        self.assertEqual(res.status, 200)
        state = json.loads(res.body)
        self.assertEqual(state["username"], "admin")
        self.assertTrue(state["default"])

        res = self.call("POST", "/api/v1/auth/credentials",
                        {"username": "operator", "password": "secret-pass"},
                        headers={"x-netcast3r-token": TOKEN})
        self.assertEqual(res.status, 200)
        self.assertTrue(dashauth.verify(self.base, "operator", "secret-pass"))

        raw = base64.b64encode(b"operator:secret-pass").decode()
        res = self.call("GET", "/api/v1/meta",
                        headers={"authorization": "Basic " + raw})
        self.assertEqual(res.status, 200)

        res = self.call("GET", "/api/v1/auth",
                        headers={"x-netcast3r-token": TOKEN})
        self.assertFalse(json.loads(res.body)["default"])

    def test_credential_change_requires_auth(self):
        res = self.call("POST", "/api/v1/auth/credentials",
                        {"username": "x", "password": "y"})
        self.assertEqual(res.status, 401)


if __name__ == "__main__":
    unittest.main()
