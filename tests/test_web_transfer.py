import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.mcp.tools import (ToolContext, host_probe, http_upload,
                                 last_byte_race, oracle_extract, race_run)


class TransferHandler(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        TransferHandler.seen.append({
            "path": self.path,
            "content_type": self.headers.get("content-type", ""),
            "body": body,
        })
        payload = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        from urllib.parse import parse_qs, urlsplit
        query = parse_qs(urlsplit(self.path).query)
        value = (query.get("e") or [""])[0]
        payload = b"hit" if value == "1:97" else b"miss"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class RaceHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()
    active = 0
    max_active = 0
    bodies = []

    @classmethod
    def reset(cls):
        with cls.lock:
            cls.active = 0
            cls.max_active = 0
            cls.bodies = []

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length)
        with RaceHandler.lock:
            RaceHandler.active += 1
            RaceHandler.max_active = max(RaceHandler.max_active, RaceHandler.active)
            RaceHandler.bodies.append(body)
        try:
            time.sleep(0.25)
            payload = b'{"ok":true,"seen":' + str(length).encode() + b"}"

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        finally:
            with RaceHandler.lock:
                RaceHandler.active -= 1

    def log_message(self, *args):
        pass


class LastByteRaceTests(unittest.TestCase):
    def setUp(self):
        RaceHandler.reset()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), RaceHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        self.ctx = ToolContext(plane=None, base=Path(self.tmp.name))

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def test_burst_releases_every_final_byte_and_keeps_every_response(self):
        payload = {"coupon": "SAVE10", "cart": "one-item"}
        result = last_byte_race(self.ctx, {
            "target": self.base + "/cart/coupon", "method": "POST",
            "json": payload, "count": 4, "scope": ["127.0.0.1"],
            "timeout": 10,
        })
        self.assertEqual(result["count"], 4)
        self.assertEqual(result["statuses"], {"200": 4})
        self.assertEqual(result["ended"], 4)
        self.assertLess(result["sync_ms"], 250)
        self.assertTrue(all(item["status"] == 200 for item in result["responses"]))
        self.assertTrue(all('"seen":' in item["body"] for item in result["responses"]))
        self.assertEqual(len(RaceHandler.bodies), 4)
        expected = json.dumps(payload).encode()
        self.assertTrue(all(body == expected for body in RaceHandler.bodies))
        # Sequential requests would never overlap; a synchronised burst does.
        self.assertGreaterEqual(RaceHandler.max_active, 2)

    def test_a_bad_scheme_is_refused(self):
        from netcast3r.mcp.tools import ToolError

        with self.assertRaises(ToolError):
            last_byte_race(self.ctx, {
                "target": "ftp://127.0.0.1/file", "count": 4,
                "scope": ["127.0.0.1"],
            })


class WebTransferTests(unittest.TestCase):
    def setUp(self):
        TransferHandler.seen = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), TransferHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.tmp = tempfile.TemporaryDirectory()
        self.ctx = ToolContext(plane=None, base=Path(self.tmp.name))

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def test_upload_builds_multipart_and_keeps_the_file_in_memory(self):
        result = http_upload(self.ctx, {
            "target": self.base + "/upload",
            "field": "file",
            "filename": "probe.php",
            "content": "<?php echo 1; ?>",
            "content_type": "application/x-php",
            "form": {"note": "test"},
            "scope": ["127.0.0.1"],
        })
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["uploaded_bytes"], len("<?php echo 1; ?>"))
        seen = TransferHandler.seen[-1]
        self.assertIn("multipart/form-data", seen["content_type"])
        self.assertIn('filename="probe.php"', seen["body"])
        self.assertIn("<?php echo 1; ?>", seen["body"])
        self.assertIn('name="note"', seen["body"])

    def test_oracle_extract_iterates_candidates(self):
        result = oracle_extract(self.ctx, {
            "target": self.base + "/oracle?e={{expr}}",
            "expr_template": "{pos}:{char}",
            "charset": "a",
            "max_length": 1,
            "true_when": "contains",
            "match": "hit",
            "scope": ["127.0.0.1"],
            "max_requests": 5,
        })
        self.assertEqual(result["value"], "a")
        self.assertEqual(result["requests"], 1)
        self.assertFalse(result["truncated"])

    def test_host_probe_grabs_an_explicit_port(self):
        result = host_probe(self.ctx, {
            "target": "127.0.0.1", "ports": [self.port],
            "timeout": 2, "scope": ["127.0.0.1"],
        })
        self.assertEqual(result["open"], [self.port])

    def test_race_run_returns_every_response(self):
        result = race_run(self.ctx, {
            "target": self.base + "/race",
            "method": "POST",
            "form": {"x": "1"},
            "count": 3,
            "concurrency": 3,
            "scope": ["127.0.0.1"],
        })
        self.assertEqual(result["count"], 3)
        self.assertEqual(len(result["responses"]), 3)
        self.assertTrue(all(item["status"] == 200 for item in result["responses"]))

    def test_oracle_stops_at_a_missing_character(self):
        result = oracle_extract(self.ctx, {
            "target": self.base + "/oracle?e={{expr}}",
            "expr_template": "{pos}:{char}",
            "charset": "b",
            "max_length": 2,
            "true_when": "contains",
            "match": "hit",
            "scope": ["127.0.0.1"],
            "max_requests": 5,
        })
        self.assertEqual(result["value"], "")
        self.assertEqual(result["requests"], 1)


if __name__ == "__main__":
    unittest.main()
