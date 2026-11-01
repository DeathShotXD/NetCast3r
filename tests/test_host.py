import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import host
from netcast3r.server import build_server


class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)

    def tearDown(self):
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_shell_runs_and_reports(self):
        result = host.shell("printf hi", timeout=10, cwd=self.tmp)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"].strip(), "hi")
        self.assertFalse(result["timed_out"])

    def test_shell_timeout_kills_the_process_group(self):
        result = host.shell("sleep 30", timeout=1, cwd=self.tmp)
        self.assertTrue(result["timed_out"])
        self.assertNotEqual(result["exit_code"], 0)

    def test_file_roundtrip_and_listing(self):
        target = self.tmp / "sub" / "note.txt"
        host.write_file(str(target), "line1\n", base=self.tmp)
        host.write_file(str(target), "line2\n", append=True, base=self.tmp)
        read = host.read_file(str(target), base=self.tmp)
        self.assertIn("line2", read["content"])
        self.assertFalse(read["binary"])
        listing = host.list_dir(str(self.tmp), base=self.tmp)
        names = {entry["name"] for entry in listing["entries"]}
        self.assertIn("sub", names)
        self.assertTrue(host.find_files(str(self.tmp), "*.txt", base=self.tmp)["count"])

    def test_the_secret_store_is_refused(self):
        store = Path.home() / ".netcast3r" / "secrets.json"
        with self.assertRaises(host.HostError):
            host.read_file(str(store))
        with self.assertRaises(host.HostError):
            host.write_file(str(store), "{}")

    def test_stat_and_capabilities(self):
        target = self.tmp / "x.bin"
        target.write_bytes(b"\x00\x01\x02")
        self.assertTrue(host.stat_path(str(target), base=self.tmp)["exists"])
        read = host.read_file(str(target), base=self.tmp)
        self.assertTrue(read["binary"])
        caps = host.capabilities()
        self.assertIn("host", caps)
        self.assertIn("tools", caps)

    def test_kill_refuses_pid_one(self):
        with self.assertRaises(host.HostError):
            host.kill_process(1)


class HostSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)

    def tearDown(self):
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def call(self, method, path, body=None, query=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, query or {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_host_routes(self):
        shell = self.call("POST", "/api/v1/host/shell", {"command": "printf ok"})
        self.assertEqual(shell.status, 200)
        self.assertEqual(self.data(shell)["stdout"].strip(), "ok")
        caps = self.call("GET", "/api/v1/host/capabilities")
        self.assertEqual(caps.status, 200)
        write = self.call("POST", "/api/v1/host/write",
                          {"path": str(self.tmp / "a.txt"), "content": "hi"})
        self.assertEqual(write.status, 200)
        read = self.call("GET", "/api/v1/host/read", None,
                         {"path": str(self.tmp / "a.txt")})
        self.assertEqual(self.data(read)["content"], "hi")
        listing = self.call("GET", "/api/v1/host/list", None, {"path": str(self.tmp)})
        self.assertIn("a.txt", {e["name"] for e in self.data(listing)["entries"]})

    def test_host_tools_are_catalogued(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        names = [tool["name"] for tool in catalog()]
        for name in ("host_shell", "host_read", "host_write", "host_list",
                     "host_find", "host_stat", "host_processes", "host_kill",
                     "host_capabilities"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)

    def test_host_shell_is_high_risk(self):
        from netcast3r.mcp.tools import _TOOL_MAP

        self.assertEqual(_TOOL_MAP["host_shell"].risk, "high")
        self.assertTrue(_TOOL_MAP["host_shell"].destructive)


if __name__ == "__main__":
    unittest.main()
