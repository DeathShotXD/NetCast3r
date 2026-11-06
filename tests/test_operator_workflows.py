import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.mcp.plane import EmbeddedPlane
from netcast3r.mcp.tools import ToolContext, ToolRegistry, _TOOL_MAP


NEW_TOOLS = {
    "web_surface_inventory", "auth_flow_inventory", "reset_flow_inventory",
    "session_cookie_audit", "security_headers_audit", "cors_policy_audit",
    "access_control_compare", "idor_sequence_probe", "input_reflection_probe",
    "injection_differential_probe", "upload_policy_probe", "retest_request",
    "evidence_pack",
}


class WorkflowHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path.startswith("/object/"):
            object_id = parsed.path.rsplit("/", 1)[-1]
            body = json.dumps({"application_id": object_id, "owner": "controlled"}).encode()
            self._send(200, body, "application/json")
            return
        if parsed.path == "/cors":
            body = b'{"profile":"controlled"}'
            extra = {
                "Access-Control-Allow-Origin": self.headers.get("Origin", ""),
                "Access-Control-Allow-Credentials": "true",
            }
            self._send(200, body, "application/json", extra)
            return
        if parsed.path == "/reflect":
            value = next(iter(query.values()), [""])[0]
            self._send(200, f"<p>{value}</p>".encode(), "text/html")
            return
        if parsed.path == "/inject":
            value = query.get("id", [""])[0]
            if "'" in value:
                self._send(500, b"SQL syntax error near quote", "text/plain")
            else:
                self._send(200, b"record 1", "text/plain")
            return
        if parsed.path == "/spa":
            # A component framework renders inputs outside any <form>.
            self._send(200, b"""
            <html><body><div>
              <input name="accountId" type="text">
              <input name="search" type="search">
            </div></body></html>
            """, "text/html")
            return
        body = b"""
        <html><body>
          <form action="/login" method="post">
            <input name="email" type="email" required>
            <input name="password" type="password" autocomplete="current-password">
          </form>
          <form action="/forgot-password" method="post">
            <input name="reset_email" type="email">
            <input name="csrf_token" type="hidden">
          </form>
          <form action="/upload" method="post" enctype="multipart/form-data">
            <input name="file" type="file">
          </form>
          <a href="/api/application?id=7&return_url=https%3A%2F%2Fexample.invalid">API</a>
          <a href="/oauth/callback">OAuth</a>
          <script src="/app.js"></script>
        </body></html>
        """
        self._send(200, body, "text/html", {
            "Set-Cookie": "sid=test-value; Path=/; Secure; HttpOnly; SameSite=Lax",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        })

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        self._send(201, json.dumps({"accepted": bool(body)}).encode(), "application/json")

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


class OperatorWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), WorkflowHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.tmp = Path(tempfile.mkdtemp())
        self.plane = EmbeddedPlane(base=self.tmp, results_dir=str(self.tmp / "results"))
        self.registry = ToolRegistry(ToolContext(
            plane=self.plane, policy="supervised", base=self.tmp))
        self.mission = self.registry.call("missions_create", {
            "title": "Workflow tests", "target": self.base_url,
            "scope": ["127.0.0.1"], "status": "active",
        }, actor="test")[0]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.plane.close()

    def call(self, name, **kwargs):
        kwargs.setdefault("mission_id", self.mission["id"])
        payload, is_error = self.registry.call(name, kwargs, actor="test")
        self.assertFalse(is_error, payload)
        return payload

    def test_tools_are_typed_and_registered(self):
        self.assertTrue(NEW_TOOLS.issubset(_TOOL_MAP))
        for name in NEW_TOOLS:
            tool = _TOOL_MAP[name]
            self.assertTrue(tool.description)
            self.assertEqual(tool.input_schema["type"], "object")

    def test_replaying_a_state_changing_method_needs_an_ack(self):
        for tool in ("retest_request", "access_control_compare"):
            payload, is_error = self.registry.call(
                tool, {"target": self.base_url + "/api/delete", "method": "DELETE",
                       "mission_id": self.mission["id"]}, actor="test")
            self.assertTrue(is_error, tool)
            self.assertEqual(payload["error"]["code"], "confirm_required", tool)
        # An idempotent read is unaffected.
        retest = self.call("retest_request", target=self.base_url + "/object/7",
                           count=2, method="GET")
        self.assertTrue(retest["consistent"])

    def test_inputs_outside_a_form_are_still_parameters(self):
        surface = self.call("web_surface_inventory", target=self.base_url + "/spa")
        self.assertIn("accountId", surface["parameters"])
        self.assertEqual(surface["counts"]["orphan_inputs"], 2)
        self.assertIn("accountId", surface["object_candidates"])

    def test_surface_auth_and_reset_inventory(self):
        surface = self.call("web_surface_inventory", target=self.base_url + "/")
        self.assertIn("id", surface["parameters"])
        self.assertIn("return_url", surface["ssrf_candidates"])
        self.assertIn("id", surface["object_candidates"])
        self.assertEqual(surface["counts"]["forms"], 3)

        auth = self.call("auth_flow_inventory", target=self.base_url + "/")
        self.assertTrue(auth["auth_forms"])
        self.assertTrue(any("oauth" in link for link in auth["auth_links"]))

        reset = self.call("reset_flow_inventory", target=self.base_url + "/")
        self.assertTrue(reset["reset_forms"])
        self.assertIn("csrf_token", reset["token_parameters"])

    def test_cookie_headers_and_cors_audits(self):
        cookies = self.call("session_cookie_audit", target=self.base_url + "/")
        self.assertEqual(cookies["cookies"][0]["name"], "sid")
        self.assertEqual(cookies["issue_count"], 0)

        headers = self.call("security_headers_audit", target=self.base_url + "/")
        self.assertIn("content-security-policy", headers["present"])
        self.assertTrue(any(row["header"] == "strict-transport-security"
                            for row in headers["missing"]))

        cors = self.call("cors_policy_audit", target=self.base_url + "/cors",
                         origins=["https://attacker.invalid"])
        self.assertTrue(cors["potential_credential_exposure"])

    def test_authorization_reflection_and_injection_workflows(self):
        compared = self.call("access_control_compare", target=self.base_url + "/object/7")
        self.assertEqual(len(compared["responses"]), 1)

        objects = self.call("idor_sequence_probe",
                            target=self.base_url + "/object/{{id}}",
                            ids=["7", "8"])
        self.assertEqual(objects["successful_objects"], 2)
        self.assertEqual(len(objects["objects"]), 2)

        reflected = self.call("input_reflection_probe",
                              target=self.base_url + "/reflect",
                              parameters=["q", "next"])
        self.assertEqual(set(reflected["reflected"]), {"q", "next"})

        injection = self.call("injection_differential_probe",
                              target=self.base_url + "/inject?id=1",
                              parameter="id")
        self.assertGreaterEqual(injection["database_errors"], 1)
        self.assertGreaterEqual(injection["differentials"], 1)

    def test_upload_retest_and_evidence_pack(self):
        upload = self.call("upload_policy_probe", target=self.base_url + "/upload")
        self.assertEqual(len(upload["uploads"]), 2)
        self.assertEqual(upload["accepted_hints"], 2)

        retest = self.call("retest_request", target=self.base_url + "/object/7",
                           count=3)
        self.assertTrue(retest["consistent"])
        self.assertEqual(len(retest["attempts"]), 3)

        pack = self.call("evidence_pack", title="Portal workflow evidence",
                         observations=[{
                             "status": 200,
                             "headers": {"Authorization": "Bearer secret"},
                             "body": "private response",
                         }])
        path = Path(pack["path"])
        self.assertTrue(path.is_file())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        saved = path.read_text()
        self.assertNotIn("Bearer secret", saved)
        self.assertNotIn("private response", saved)
        self.assertTrue(pack["redacted"])


if __name__ == "__main__":
    unittest.main()
