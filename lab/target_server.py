"""Lab target.

A small site that ships JavaScript with planted credentials and a source map,
so the whole pipeline can be exercised without touching anything real.

Run it on its own or through lab/run_lab.sh.
"""

from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX = """<!doctype html>
<html>
<head><title>netcast3r lab</title></head>
<body>
  <h1>lab target</h1>
  <script src="/static/app.js"></script>
  <a href="/about">about</a>
</body>
</html>
"""

APP_JS = """const LAB_TOKEN = "NC3RLABKEY123";
const AWS_EXAMPLE = "AWS_KEY_PLACEHOLDER";
const STRIPE_TEST = "STRIPE_TEST_PLACEHOLDER";
const API_BASE = "/api/v2";

async function loadUsers() {
  const response = await fetch(API_BASE + "/users?limit=10");
  return response.json();
}

loadUsers();
//# sourceMappingURL=app.js.map
"""

APP_JS_MAP = """{"version":3,"file":"app.js","sources":["app.ts"],"mappings":""}"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/app.js.map"):
            body, ctype = APP_JS_MAP, "application/json"
        elif self.path.startswith("/static/app.js"):
            body, ctype = APP_JS, "application/javascript"
        elif self.path.startswith("/app.js"):
            body, ctype = APP_JS, "application/javascript"
        elif self.path == "/about":
            body, ctype = "<html><body>about</body></html>", "text/html"
        elif self.path == "/":
            body, ctype = INDEX, "text/html"
        else:
            body, ctype = "{}", "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    host = os.environ.get("LAB_HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"lab target on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
