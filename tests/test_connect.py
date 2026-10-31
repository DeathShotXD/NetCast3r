import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server import Server
from netcast3r.server.events import EventBus
from netcast3r.server.index import Index
from netcast3r.server.jobs import JobManager
from netcast3r.server.keys import KeyStore


def _runner(run_id, target, options, emit, should_stop):
    return {"target": target, "pages": 1, "findings": 0}


class ConnectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.index = Index(base / "netcast3r.db")
        self.bus = EventBus()
        self.keys = KeyStore(base)
        self.jobs = JobManager(self.index, self.bus, _runner, workers=1)
        self.server = Server(self.index, self.bus, self.jobs, self.keys,
                             token="test-token")

    def tearDown(self):
        self.jobs.shutdown()
        self.index.close()
        self.tmp.cleanup()

    def call(self, path):
        headers = {"host": "127.0.0.1:7857", "x-netcast3r-token": "test-token"}
        return self.server.route("GET", path, {}, headers, b"")

    def test_connect_lists_harnesses_and_the_tool_surface(self):
        response = self.call("/api/v1/connect")
        self.assertEqual(response.status, 200)
        data = json.loads(response.body.decode())
        workspace = data["workspace"]
        self.assertGreaterEqual(workspace["tools"], 100)
        self.assertEqual(workspace["policy"], "supervised")
        self.assertEqual(workspace["token_header"], "X-NetCast3r-Token")
        self.assertTrue(workspace["token_file"].endswith("control-plane.json"))
        ids = {harness["id"] for harness in data["harnesses"]}
        for expected in ("opencode", "hermes", "deepseek", "agent-zero", "generic", "http"):
            self.assertIn(expected, ids)
        names = {tool["name"] for tool in data["tools"]}
        self.assertIn("http_probe", names)
        self.assertIn("model_solve", names)

    def test_connect_never_returns_the_session_token(self):
        response = self.call("/api/v1/connect")
        body = response.body.decode()
        self.assertNotIn("test-token", body)
        self.assertNotIn(self.server.token, body)

    def test_connect_configs_reference_the_real_python(self):
        response = self.call("/api/v1/connect")
        data = json.loads(response.body.decode())
        opencode = next(item for item in data["harnesses"] if item["id"] == "opencode")
        command = opencode["config"]["mcp"]["servers"]["netcast3r"]["command"]
        self.assertEqual(command[0], data["workspace"]["python"])
        self.assertIn("mcp", command)


if __name__ == "__main__":
    unittest.main()