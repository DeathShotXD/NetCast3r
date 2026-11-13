import unittest

from netcast3r import desync

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
NOT_FOUND = b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nnope!"
SERVER_ERROR = b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n"


class BuildTests(unittest.TestCase):
    def test_request_has_host_and_close(self):
        request = desync.build_request("app.example.com", "/x")
        self.assertIn("GET /x HTTP/1.1", request.decode())
        self.assertIn("Host: app.example.com", request.decode())
        self.assertIn("Connection: close", request.decode())

    def test_signature_parses_status_and_hash(self):
        sig = desync._response_signature(OK)
        self.assertEqual(sig["status"], 200)
        self.assertFalse(sig["empty"])
        self.assertTrue(desync._response_signature(b"")["empty"])


class ProbeTests(unittest.TestCase):
    def _transport(self, unique_hidden=False, te_error=False):
        def transport(target, request, timeout=None):
            text = request.decode("iso-8859-1", "replace")
            if te_error and text.startswith("POST"):
                if "xchunked" in text:
                    return SERVER_ERROR
                return OK
            if unique_hidden and " Host: app.example.com" in text:
                return NOT_FOUND
            if "nc3r-masked.invalid" in text and text.count("Host") == 1:
                return OK
            if "Host:" not in text:
                return OK
            return OK
        return transport

    def test_unique_hidden_header_is_a_discrepancy(self):
        result = desync.probe("https://app.example.com/x",
                              transport=self._transport(unique_hidden=True),
                              include_transfer_encoding=False)
        self.assertEqual(result["verdict"], "parser_discrepancy")
        self.assertIn("leading_space",
                      [row["kind"] for row in result["discrepancies"]])

    def test_uniform_responses_are_no_signal(self):
        result = desync.probe("https://app.example.com/x",
                              transport=self._transport(unique_hidden=False),
                              include_transfer_encoding=False)
        self.assertEqual(result["verdict"], "no_signal")
        self.assertEqual(result["discrepancies"], [])

    def test_te_obfuscation_discrepancy(self):
        result = desync.probe("https://app.example.com/post",
                              transport=self._transport(te_error=True),
                              include_transfer_encoding=True)
        kinds = [row["kind"] for row in result["discrepancies"]]
        self.assertIn("xchunked", kinds)

    def test_missing_host(self):
        result = desync.probe("", transport=self._transport())
        self.assertFalse(result["ok"])

    def test_probe_list_covers_hiders_and_te(self):
        self.assertIn("leading_space", [row["kind"] for row in
                                        desync.hider_probes("a.test")])
        self.assertIn("cl_te_conflict", [row["kind"] for row in
                                         desync.te_probes("a.test")])

    def test_summary(self):
        self.assertIn("hiders", desync.summary())


if __name__ == "__main__":
    unittest.main()
