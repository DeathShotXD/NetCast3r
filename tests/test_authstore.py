import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import authstore


class AuthStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        for child in self.tmp.rglob("*"):
            if child.is_file():
                child.unlink()
        for child in sorted(self.tmp.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        self.tmp.rmdir()

    def test_round_trip_and_masking(self):
        public = authstore.set_profile(
            "ig-main", headers={"X-CSRF": "abc"}, cookies={"PHPSESSID": "s3cr3t"},
            note="primary", base=self.tmp)
        self.assertEqual(public["header_names"], ["X-CSRF"])
        self.assertEqual(public["cookie_names"], ["PHPSESSID"])
        self.assertNotIn("s3cr3t", json.dumps(public))

        profile = authstore.get_profile("ig-main", base=self.tmp)
        self.assertEqual(profile.request_headers()["Cookie"], "PHPSESSID=s3cr3t")
        self.assertEqual(profile.request_headers()["X-CSRF"], "abc")

        listed = authstore.list_profiles(base=self.tmp)
        self.assertEqual(listed[0]["name"], "ig-main")
        self.assertNotIn("s3cr3t", json.dumps(listed))
        mode = stat.S_IMODE((self.tmp / authstore.STORE_NAME).stat().st_mode)
        self.assertEqual(mode, 0o600)

        self.assertTrue(authstore.delete_profile("ig-main", base=self.tmp))
        self.assertIsNone(authstore.get_profile("ig-main", base=self.tmp))

    def test_rejects_bad_names_and_header_injection(self):
        with self.assertRaises(authstore.AuthError):
            authstore.set_profile("../evil", cookies={"a": "b"}, base=self.tmp)
        with self.assertRaises(authstore.AuthError):
            authstore.set_profile("ok", headers={"X-Test": "a\r\nX-Evil: 1"}, base=self.tmp)
        with self.assertRaises(authstore.AuthError):
            authstore.set_profile("ok", base=self.tmp)
        with self.assertRaises(authstore.AuthError):
            authstore.set_profile("ok", cookies={"a;b": "c"}, base=self.tmp)

    def test_import_from_storage_state(self):
        state = self.tmp / "state.json"
        state.write_text(json.dumps({"cookies": [
            {"name": "a", "value": "1", "domain": ".example.com"},
            {"name": "b", "value": "2", "domain": ".other.test"},
        ], "origins": []}))
        public = authstore.from_storage_state(
            state, "imported", domain="example.com", base=self.tmp)
        self.assertEqual(public["cookie_names"], ["a"])


if __name__ == "__main__":
    unittest.main()
