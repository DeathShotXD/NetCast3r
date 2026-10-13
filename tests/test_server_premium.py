import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server import Server
from netcast3r.server.events import EventBus
from netcast3r.server.index import Index
from netcast3r.server.jobs import JobManager
from netcast3r.server.keys import KeyStore

HOST = {"host": "127.0.0.1"}


def noop_runner(run_id, target, options, emit, should_stop):
    return {}


class PremiumRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        base = Path(self.tmp.name)
        self.index = Index(base / "netcast3r.db")
        self.bus = EventBus()
        self.keys = KeyStore(base)
        self.jobs = JobManager(self.index, self.bus, noop_runner, workers=1)
        self.server = Server(self.index, self.bus, self.jobs, self.keys, auth_required=False)

    def tearDown(self):
        self.jobs.shutdown(wait=True)
        self.index.close()
        self.tmp.cleanup()

    def test_providers_health_reports_models_and_key_state(self):
        self.index.add_provider(name="openrouter", base_url="https://openrouter.ai/api/v1",
                                key_name="openrouter", models=["a:free", "b:free"])
        response = self.server.route("GET", "/api/v1/providers/health", {}, dict(HOST), b"")
        data = json.loads(response.body)
        self.assertEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["models"], ["a:free", "b:free"])
        self.assertFalse(data["items"][0]["key_set"])

    def test_report_route_is_404_before_a_report_exists(self):
        run = self.index.create_run("example.com", {})
        response = self.server.route("GET", f"/api/v1/runs/{run['id']}/report", {}, dict(HOST), b"")
        self.assertEqual(response.status, 404)

    def test_report_route_serves_the_written_report(self):
        run = self.index.create_run("example.com", {})
        out = Path(self.tmp.name) / "results" / run["id"]
        out.mkdir(parents=True)
        (out / "report.md").write_text("# NetCast3r report\n\nhello")
        self.index.update_run(run["id"], counts_json={"results_dir": str(out)})
        response = self.server.route("GET", f"/api/v1/runs/{run['id']}/report", {}, dict(HOST), b"")
        self.assertEqual(response.status, 200)
        self.assertIn(b"hello", response.body)


if __name__ == "__main__":
    unittest.main()
