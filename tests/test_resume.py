import json
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from netcast3r.config import default_config
from netcast3r.orchestrator import Orchestrator
from netcast3r.scope import ScopeManager
from netcast3r.secrets import Extractor, Pattern
from netcast3r.store import Store
from netcast3r.tui import Console
from netcast3r.validate import Recipe, Validator

LAB_KEY = "NC3RLABKEY123"


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f'const TOKEN = "{LAB_KEY}";' if self.path.startswith("/app.js") else \
            '<html><body><script src="/app.js"></script></body></html>'
        ctype = "application/javascript" if self.path.startswith("/app.js") else "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class VerifyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        alive = parse_qs(urlparse(self.path).query).get("key", [""])[0] == LAB_KEY
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"alive": alive}).encode())

    def log_message(self, *args):
        pass


class ResumeTests(unittest.TestCase):
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

    def test_second_run_reuses_validations(self):
        config = default_config()
        config.egress.use_public = False
        seed = f"http://127.0.0.1:{self.target_port}/"
        scope = ScopeManager()
        workdir = Path(tempfile.mkdtemp())
        store = Store(workdir / "netcast3r.db")

        extractor = Extractor(patterns=[Pattern(id="lab", type="mock", regex=re.compile(r"NC3RLABKEY[0-9A-Z]+"))])
        recipe = Recipe(type="mock", provider="Lab", method="GET",
                        url=f"http://127.0.0.1:{self.verify_port}/verify?key={{value}}",
                        success_codes=[200], success_match='"alive": true')

        def make(resume):
            return Orchestrator(config, scope, store, console=Console(show_reasoning=False),
                                use_agents=False,
                                validator=Validator(recipes={"mock": recipe}, tier="read"),
                                extractor=extractor, resume=resume)

        first = make(False)
        first.run([seed])
        self.assertEqual(store.counts()["validations"], 1)
        self.assertEqual(store.counts()["findings"], 1)

        second = make(True)
        second.run([seed])
        self.assertEqual(store.counts()["validations"], 1)
        self.assertEqual(store.counts()["findings"], 1)
        store.close()


if __name__ == "__main__":
    unittest.main()
