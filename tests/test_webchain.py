import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import webchain
from netcast3r.mcp.plane import EmbeddedPlane
from netcast3r.mcp.tools import ToolContext, ToolRegistry, _TOOL_MAP

CONFIG = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <connectionStrings>
    <add name="EPMSConnectionString2" connectionString="Data Source=10.0.0.5;Initial Catalog=epms;User ID=dbuser;Password=SuperSecret123" />
  </connectionStrings>
</configuration>
"""

SOURCE = """<%
Set Conn = Server.CreateObject("ADODB.Connection")
ConString = "Provider=SQLOLEDB;Data Source=localhost;User ID=sa;Password=Allah**;"
Conn.Open ConString
uid = request.cookies("uid")
pwd = request.cookies("pwd")
SQL = "Select * From users Where UserName = '" & uid & "' And Passwrd = '" & pwd & "'"
Set RS = Conn.Execute(SQL)
%>
"""


class ChainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/read":
            value = query.get("file", [""])[0]
            if value == "web.config":
                self._send(200, b"Error: File not found.", "text/html")
            elif value in ("../web.config", "..%2fweb.config", "..%5cweb.config"):
                self._send(200, CONFIG.encode(), "application/octet-stream")
            elif value in ("../HQ/check.asp", "..%2fHQ%2fcheck.asp"):
                self._send(200, SOURCE.encode(), "application/octet-stream")
            else:
                self._send(200, b"Error: File not found.", "text/html")
            return
        if parsed.path == "/HQ/check.asp":
            cookie = self.headers.get("Cookie") or ""
            if "uid=' OR 1=1--" in cookie:
                self._send(500, b"server error", "text/html",
                           {"Set-Cookie": "SID=authed; Path=/; HttpOnly"})
            else:
                self._send(200, b"<html>Admin Login</html>", "text/html")
            return
        if parsed.path == "/public":
            self._send(200, b"<html>Management Console</html>", "text/html")
            return
        if parsed.path == "/HQ/reports_main.asp":
            cookie = self.headers.get("Cookie") or ""
            if "SID=authed" in cookie:
                self._send(200, b"<html><title>Management Console</title></html>",
                           "text/html")
            else:
                self._send(401, b"denied", "text/plain")
            return
        self._send(404, b"not found", "text/plain")

    def _send(self, status, body, content_type, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class WebChainLogicTests(unittest.TestCase):
    def test_a_config_and_a_source_file_are_classified(self):
        self.assertEqual(webchain.classify(CONFIG, "application/octet-stream")["kind"],
                         "config")
        self.assertEqual(webchain.classify(SOURCE, "application/octet-stream")["kind"],
                         "source")
        self.assertEqual(webchain.classify("Error: File not found.")["kind"],
                         "not-found")

    def test_secrets_are_masked_and_sinks_are_found(self):
        scan = webchain.scan(SOURCE)
        kinds = {sink["kind"] for sink in scan["sinks"]}
        self.assertIn("sql-concatenation", kinds)
        self.assertIn("cookie-trust", kinds)
        self.assertTrue(scan["secrets"])
        serialized = json.dumps(scan)
        self.assertNotIn("Allah**", serialized)
        self.assertNotIn("SuperSecret123", serialized)

    def test_summary_requires_approval_for_an_upload(self):
        summary = webchain.summarize([{
            "kind": "source",
            "secrets": [],
            "sinks": [{"kind": "upload", "detail": "type=file"}],
        }])
        self.assertEqual(summary["verdict"], "chain-available-needs-approval")
        self.assertTrue(any(item.get("requires_approval")
                            for item in summary["candidates"]))


class WebChainToolTests(unittest.TestCase):
    def setUp(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), ChainHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"
        self.tmp = Path(tempfile.mkdtemp())
        self.plane = EmbeddedPlane(base=self.tmp, results_dir=str(self.tmp / "results"))
        self.registry = ToolRegistry(ToolContext(
            plane=self.plane, policy="supervised", base=self.tmp))
        self.mission = self.registry.call("missions_create", {
            "title": "chain tests", "target": self.base,
            "scope": ["127.0.0.1"], "status": "active",
        }, actor="test")[0]
        self.read_url = self.base + "/read?file={{path}}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.plane.close()

    def call(self, name, **kwargs):
        kwargs.setdefault("mission_id", self.mission["id"])
        payload, is_error = self.registry.call(name, kwargs, actor="test")
        self.assertFalse(is_error, payload)
        return payload

    def test_tools_are_registered(self):
        for name in ("path_traversal_probe", "source_disclosure_scan",
                     "auth_cookie_probe", "chain_run"):
            self.assertIn(name, _TOOL_MAP)

    def test_traversal_probe_confirms_the_read(self):
        result = self.call("path_traversal_probe", target=self.read_url,
                           paths=["web.config", "../web.config",
                                  "..%2fweb.config"])
        self.assertTrue(result["read_confirmed"])
        self.assertEqual(result["depth"], 1)
        self.assertIn("plain", result["encodings"])

    def test_source_scan_finds_the_sql_and_cookie_sinks(self):
        result = self.call("source_disclosure_scan", read_url=self.read_url,
                           paths=["../HQ/check.asp", "../web.config"],
                           max_files=4)
        self.assertGreaterEqual(result["files_scanned"], 2)
        self.assertIn("sql-concatenation", result["sinks"])
        self.assertIn("cookie-trust", result["sinks"])
        self.assertGreater(result["secrets_total"], 0)
        self.assertNotIn("Allah**", json.dumps(result))

    def test_cookie_probe_proves_the_auth_bypass(self):
        result = self.call(
            "auth_cookie_probe", target=self.base + "/HQ/check.asp",
            protected_url=self.base + "/HQ/reports_main.asp",
            success_marker="Management Console",
            cookie_payloads=[{"uid": "' OR 1=1--", "pwd": "x"}])
        self.assertTrue(result["bypass"])
        self.assertEqual(result["verdict"], "auth-bypass")
        self.assertFalse(result["baseline_authenticated"])

    def test_a_public_protected_page_never_counts_as_a_bypass(self):
        result = self.call(
            "auth_cookie_probe", target=self.base + "/HQ/check.asp",
            protected_url=self.base + "/public",
            success_marker="Management Console",
            cookie_payloads=[{"uid": "' OR 1=1--", "pwd": "x"}])
        self.assertTrue(result["baseline_authenticated"])
        self.assertFalse(result["bypass"])
        self.assertEqual(result["verdict"], "baseline-authenticated")

    def test_chain_run_returns_source_and_auth(self):
        result = self.call(
            "chain_run", read_url=self.read_url,
            probe_paths=["web.config", "../web.config"],
            source_paths=["../HQ/check.asp", "../web.config"],
            cookie_target=self.base + "/HQ/check.asp",
            protected_url=self.base + "/HQ/reports_main.asp",
            success_marker="Management Console",
            cookie_payloads=[{"uid": "' OR 1=1--", "pwd": "x"}])
        self.assertTrue(result["traversal"]["read_confirmed"])
        self.assertTrue(result["auth"]["bypass"])
        self.assertIn("source", result["summary"]["verdict"])


if __name__ == "__main__":
    unittest.main()
