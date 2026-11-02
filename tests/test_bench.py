import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import bench
from netcast3r.server import build_server


class BenchTests(unittest.TestCase):
    def test_the_corpus_passes_its_own_gate(self):
        result = bench.run()
        self.assertGreater(result["cases"], 0)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 1.0)
        self.assertTrue(bench.gate(result)["passed"])

    def test_every_case_has_a_result_and_no_error(self):
        for result in bench.run()["results"]:
            self.assertEqual(result["error"], "")
            self.assertTrue(result["passed"], result["id"])

    def test_a_kind_filter_only_runs_that_kind(self):
        result = bench.run(kind="sourceflow")
        self.assertGreater(result["cases"], 0)
        self.assertTrue(all(item["kind"] == "sourceflow"
                            for item in result["results"]))

    def test_one_case_filter_runs_one_case(self):
        result = bench.run(case_id="sourceflow.route_to_eval")
        self.assertEqual(result["cases"], 1)
        self.assertIn("critical:eval()", result["results"][0]["actual"])

    def test_an_unknown_filter_is_an_empty_but_valid_run(self):
        result = bench.run(kind="not-a-kind")
        self.assertEqual(result["cases"], 0)
        self.assertFalse(bench.gate(result)["passed"])

    def test_the_gate_rejects_a_regression(self):
        broken = {"failed": 1, "cases": 8, "precision": 0.5, "recall": 0.5}
        gate = bench.gate(broken)
        self.assertFalse(gate["passed"])
        self.assertFalse(gate["checks"]["no_failed_cases"])
        self.assertFalse(gate["checks"]["precision"])

    def test_save_writes_a_json_report(self):
        path = Path(tempfile.mkdtemp()) / "bench.json"
        bench.save(path, bench.run())
        payload = json.loads(path.read_text())
        self.assertIn("results", payload)
        self.assertIn("note", payload)


class BenchRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_bench_route(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        response = self.server.route("GET", "/api/v1/bench",
                                     {"gate": "1"}, headers, b"")
        self.assertEqual(response.status, 200)
        payload = json.loads(response.body.decode())
        self.assertTrue(payload["gate"]["passed"])
        self.assertEqual(payload["failed"], 0)


if __name__ == "__main__":
    unittest.main()