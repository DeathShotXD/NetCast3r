import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import integrations

SERVER = textwrap.dedent('''
    import json, sys
    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        method = message.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18",
                      "serverInfo": {"name": "fake", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "echo", "description": "echo args"}]}
        elif method == "tools/call":
            result = {"content": [{"type": "text",
                                    "text": json.dumps(message["params"].get("arguments") or {})}],
                      "isError": False}
        elif method is None:
            continue
        else:
            result = {}
        if message.get("id") is not None:
            print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}),
                  flush=True)
''')


class StdioClientTests(unittest.TestCase):
    def test_initialize_list_and_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "fake_mcp.py"
            script.write_text(SERVER)
            client = integrations.StdioMCPClient([sys.executable, str(script)])
            try:
                info = client.initialize()
                self.assertEqual(info["serverInfo"]["name"], "fake")
                tools = client.list_tools()
                self.assertEqual(tools[0]["name"], "echo")
                result = client.call_tool("echo", {"hello": "world"})
                payload = json.loads(result["content"][0]["text"])
                self.assertEqual(payload["hello"], "world")
            finally:
                client.close()

    def test_configured_server_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "fake_mcp.py"
            script.write_text(SERVER)
            config = {"transport": "stdio",
                      "command": [sys.executable, str(script)], "args": [],
                      "env": {}, "cwd": ""}
            listing = integrations.mcp_server_tools(config)
            self.assertTrue(listing["ok"])
            self.assertEqual(listing["tool_count"], 1)
            result = integrations.mcp_server_call(config, "echo", {"n": 1})
            self.assertEqual(json.loads(result["content"][0]["text"])["n"], 1)

    def test_config_parser_hides_missing_servers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "integrations.json"
            path.write_text(json.dumps({"mcp_servers": {
                "a": {"transport": "stdio", "command": ["/bin/true"]},
                "b": {"transport": "http", "url": "http://127.0.0.1:9999"},
                "bad": {"transport": "stdio"},
            }}))
            servers = integrations.load_mcp_servers(tmp)
            self.assertIn("a", servers)
            self.assertIn("b", servers)
            self.assertNotIn("bad", servers)


if __name__ == "__main__":
    unittest.main()
