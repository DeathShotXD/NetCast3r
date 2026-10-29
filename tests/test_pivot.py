import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

import httpx

from netcast3r import pivot


def transport_with(auth_status=200, base_status=401, auth_body=b'{"uid":1}'):
    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" in {key.lower() for key in request.headers}:
            return httpx.Response(auth_status, content=auth_body)
        return httpx.Response(base_status, content=b"unauthorized")
    return httpx.MockTransport(handler)


class PivotTests(unittest.TestCase):
    def test_401_to_200_is_accepted(self):
        result = pivot.pivot(["https://api.example.com"], "Authorization", "tok",
                             transport=transport_with())
        self.assertEqual(result["tested"], 1)
        self.assertEqual(result["accepted"], 1)
        self.assertTrue(result["hosts"][0]["accepted"])
        self.assertEqual(result["hosts"][0]["baseline_status"], 401)
        self.assertEqual(result["hosts"][0]["auth_status"], 200)
        self.assertNotIn("tok", str(result))

    def test_same_status_different_body_is_accepted(self):
        def handler(request):
            if "x-api-key" in {key.lower() for key in request.headers}:
                return httpx.Response(200, content=b"account A")
            return httpx.Response(200, content=b"public page")
        result = pivot.pivot(["https://example.com"], "X-API-Key", "key",
                             transport=httpx.MockTransport(handler))
        self.assertTrue(result["hosts"][0]["accepted"])

    def test_403_to_403_is_not_accepted(self):
        result = pivot.pivot(["https://example.com"], "Authorization", "tok",
                             transport=transport_with(base_status=403, auth_status=403))
        self.assertFalse(result["hosts"][0]["accepted"])

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            pivot.pivot(["https://example.com"], "Bad:Header", "tok")
        with self.assertRaises(ValueError):
            pivot.pivot(["https://example.com"], "Authorization", "")
        result = pivot.pivot(["not a host"], "Authorization", "tok")
        self.assertFalse(result["hosts"][0]["accepted"])


if __name__ == "__main__":
    unittest.main()
