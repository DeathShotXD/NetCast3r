import json
import os
import unittest
from unittest import mock

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

import httpx

from netcast3r import integrations


class TargetSafetyTests(unittest.TestCase):
    def test_public_hosts_are_accepted(self):
        self.assertEqual(integrations.target_host("example.com"), "example.com")
        self.assertEqual(integrations.target_host("https://api.example.com/x"),
                         "api.example.com")

    def test_private_metadata_and_junk_are_refused(self):
        for target in ("127.0.0.1", "10.0.0.5", "169.254.169.254",
                       "metadata.google.internal", "http://[::1]/",
                       "file:///etc/passwd", "not a host"):
            with self.assertRaises(integrations.ToolRunError, msg=target):
                integrations.target_host(target)

    def test_domain_only_tool_rejects_url(self):
        with self.assertRaises(integrations.ToolRunError):
            integrations.target_host("https://example.com/x", domain_only=True)


class CommandTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(integrations, "_resolve_check", return_value=None)
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_subfinder_command_is_fixed(self):
        command = integrations._command("subfinder", "example.com", 60)
        self.assertEqual(command[0], "subfinder")
        self.assertIn("-d", command)
        self.assertIn("example.com", command)
        self.assertNotIn(";", " ".join(command))

    def test_httpx_command_uses_url(self):
        command = integrations._command("httpx", "example.com", 60)
        self.assertEqual(command[0], "httpx")
        self.assertIn("https://example.com", command)

    def test_unknown_tool_is_refused(self):
        with self.assertRaises(integrations.ToolRunError):
            integrations._command("bash", "example.com", 60)


class RunToolTests(unittest.TestCase):
    def test_run_tool_captures_and_bounds_output(self):
        completed = mock.Mock(returncode=0, stdout="a" * 250000, stderr="")
        with mock.patch.object(integrations.shutil, "which", return_value="/bin/subfinder"), \
                mock.patch.object(integrations, "_resolve_check", return_value=None), \
                mock.patch.object(integrations.subprocess, "run", return_value=completed):
            result = integrations.run_tool("subfinder", "example.com", base="/tmp")
        self.assertEqual(result["tool"], "subfinder")
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["stdout"]), integrations.MAX_OUTPUT)

    def test_missing_binary_is_reported(self):
        with mock.patch.object(integrations.shutil, "which", return_value=None):
            with self.assertRaises(integrations.ToolRunError):
                integrations.run_tool("nuclei", "example.com", base="/tmp")


class BurpClientTests(unittest.TestCase):
    def _handler(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content or b"{}")
        method = payload.get("method")
        if method == "initialize":
            body = {"jsonrpc": "2.0", "id": payload.get("id"), "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "burp", "version": "1"},
            }}
        elif method == "tools/list":
            body = {"jsonrpc": "2.0", "id": payload.get("id"), "result": {
                "tools": [{"name": "get_proxy_history",
                           "description": "Read proxy history"}]}}
        elif method == "tools/call":
            body = {"jsonrpc": "2.0", "id": payload.get("id"), "result": {
                "content": [{"type": "text", "text": "ok"}]}}
        else:
            body = {"jsonrpc": "2.0", "result": {}}
        return httpx.Response(200, json=body,
                              headers={"mcp-session-id": "sess-1"})

    def test_status_and_call(self):
        transport = httpx.MockTransport(self._handler)
        client = integrations.BurpClient("http://127.0.0.1:9876", transport=transport)
        status = client.status()
        self.assertTrue(status["ok"])
        self.assertEqual(status["tool_count"], 1)
        self.assertEqual(status["tools"][0]["name"], "get_proxy_history")
        result = client.call_tool("get_proxy_history", {"limit": 5})
        self.assertEqual(result["content"][0]["text"], "ok")
        self.assertEqual(client.session_id, "sess-1")

    def test_unconfigured_url_is_an_error(self):
        with self.assertRaises(integrations.BurpError):
            integrations.BurpClient("")

    def test_sse_frames_are_parsed(self):
        text = ('event: message\n'
                'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n')
        messages = integrations._parse_sse(text)
        self.assertEqual(messages[0]["result"]["ok"], True)


class ConfigTests(unittest.TestCase):
    def test_config_file_and_environment(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "integrations.json"
            path.write_text(json.dumps({"burp": {"url": "http://127.0.0.1:9876",
                                                "token": "x"}}))
            config = integrations.load_burp_config(tmp)
            self.assertTrue(config["configured"])
            self.assertEqual(config["url"], "http://127.0.0.1:9876")
        with mock.patch.dict(os.environ, {"NETCAST3R_BURP_URL": "http://localhost:9000"}):
            config = integrations.load_burp_config("/definitely/not/here")
        self.assertTrue(config["configured"])


if __name__ == "__main__":
    unittest.main()
