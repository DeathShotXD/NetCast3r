"""Lab provider.

Answers the validation request for the lab token so the assayer has something
deterministic to confirm. It knows one key and rejects the rest.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LAB_KEY = "NC3RLABKEY123"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        key = parse_qs(urlparse(self.path).query).get("key", [""])[0]
        payload = json.dumps({"alive": key == LAB_KEY})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

    def log_message(self, *args):
        pass


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"lab provider on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
