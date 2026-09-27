import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from netcast3r.config import default_config
from netcast3r.recon import Recon
from netcast3r.scope import ScopeManager
from netcast3r.secrets import Extractor, Pattern
from netcast3r.validate import Recipe, Validator

LAB_KEY = "NC3RLABKEY123"


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/app.js":
            body = f'const TOKEN = "{LAB_KEY}"; fetch("/api/v1/users");'
            ctype = "application/javascript"
        elif self.path == "/":
            body = ('<html><body><script src="/app.js"></script>'
                    '<a href="/page2">p2</a>'
                    '<a href="https://evil.example.net/x">out</a></body></html>')
            ctype = "text/html"
        elif self.path == "/page2":
            body = "<html><body>page two</body></html>"
            ctype = "text/html"
        else:
            body = "{}"
            ctype = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class VerifyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        alive = query.get("key", [""])[0] == LAB_KEY
        payload = json.dumps({"alive": alive})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

    def log_message(self, *args):
        pass


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        cls.verify = ThreadingHTTPServer(("127.0.0.1", 0), VerifyHandler)
        cls.target_port = cls.target.server_address[1]
        cls.verify_port = cls.verify.server_address[1]
        for server in (cls.target, cls.verify):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.target.shutdown()
        cls.verify.shutdown()

    def test_crawl_hunt_validate(self):
        config = default_config()
        config.run.depth = 2
        seed = f"http://127.0.0.1:{self.target_port}/"

        scope = ScopeManager(out_of_scope=["evil.example.net"])
        recon = Recon(scope, config)
        result = recon.crawl([seed])

        self.assertIn(seed, result.pages)
        self.assertTrue(any(url.endswith("/app.js") for url in result.js_urls))
        self.assertTrue(any("evil.example.net" in url for url in result.out_of_scope))
        self.assertTrue(any("api/v1/users" in url for url in result.endpoints))

        extractor = Extractor(patterns=[Pattern(id="lab", type="mock", regex=re.compile(r"NC3RLABKEY[0-9A-Z]+"))])
        found = []
        for text in result.js_text.values():
            found.extend(extractor.scan(text))
        self.assertTrue(any(secret.value == LAB_KEY for secret in found))

        recipe = Recipe(
            type="mock",
            provider="NetCast3r Lab",
            method="GET",
            url=f"http://127.0.0.1:{self.verify_port}/verify?key={{value}}",
            success_codes=[200],
            success_match='"alive": true',
            fail_match='"alive": false',
        )
        validator = Validator(recipes={"mock": recipe}, tier="read")
        validation = validator.validate("mock", LAB_KEY)
        self.assertEqual(validation.status, "verified")


if __name__ == "__main__":
    unittest.main()
