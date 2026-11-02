import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import sourceflow
from netcast3r.server import build_server

FLASK_HEAD = "from flask import Flask, request\napp = Flask(__name__)\n"


class SourceFlowTests(unittest.TestCase):
    def test_direct_eval_of_request_data_is_critical(self):
        result = sourceflow.analyze_text(
            FLASK_HEAD
            + "@app.route('/run')\n"
              "def run():\n"
              "    cmd = request.args.get('cmd')\n"
              "    return eval(cmd)\n",
            "app.py")
        self.assertEqual(result["error"], "")
        self.assertEqual(len(result["leads"]), 1)
        lead = result["leads"][0]
        self.assertEqual(lead["sink"], "eval()")
        self.assertEqual(lead["severity"], "critical")
        self.assertEqual(lead["route"], "ROUTE /run")
        self.assertTrue(any("request.args" in step for step in lead["steps"]))

    def test_taint_follows_a_function_argument(self):
        result = sourceflow.analyze_text(
            "import os\n" + FLASK_HEAD
            + "def execute(cmd):\n"
              "    os.system(cmd)\n"
              "@app.route('/run')\n"
              "def run():\n"
              "    execute(request.args['cmd'])\n",
            "app.py")
        self.assertEqual([lead["sink"] for lead in result["leads"]],
                         ["os.system()"])
        self.assertEqual(result["leads"][0]["severity"], "critical")

    def test_taint_follows_a_return_value(self):
        result = sourceflow.analyze_text(
            "import os\n" + FLASK_HEAD
            + "def get_name():\n"
              "    return request.args['name']\n"
              "@app.route('/run')\n"
              "def run():\n"
              "    name = get_name()\n"
              "    os.system('echo ' + name)\n",
            "app.py")
        self.assertEqual(result["leads"][0]["sink"], "os.system()")
        self.assertTrue(any("returned" in step for step in result["leads"][0]["steps"]))

    def test_parameterised_sql_is_not_a_lead(self):
        result = sourceflow.analyze_text(
            FLASK_HEAD
            + "@app.route('/u')\n"
              "def u():\n"
              "    cur.execute('select * from users where id = ?', (request.args['id'],))\n"
              "    return 'ok'\n",
            "app.py")
        self.assertEqual(result["leads"], [])

    def test_formatted_sql_is_a_lead(self):
        result = sourceflow.analyze_text(
            FLASK_HEAD
            + "@app.route('/u')\n"
              "def u():\n"
              "    uid = request.args['id']\n"
              "    cur.execute(f'select * from users where id = {uid}')\n"
              "    return 'ok'\n",
            "app.py")
        self.assertEqual(result["leads"][0]["sink"], "cur.execute()")
        self.assertEqual(result["leads"][0]["severity"], "high")

    def test_safe_yaml_loader_is_not_flagged(self):
        result = sourceflow.analyze_text(
            "import yaml\n" + FLASK_HEAD
            + "@app.route('/parse')\n"
              "def parse():\n"
              "    return yaml.load(request.data, Loader=yaml.SafeLoader)\n",
            "app.py")
        self.assertEqual(result["leads"], [])

    def test_scan_walks_a_tree_and_returns_relative_files(self):
        root = Path(tempfile.mkdtemp())
        (root / "app.py").write_text(
            FLASK_HEAD
            + "@app.route('/run')\n"
              "def run():\n"
              "    return eval(request.args['x'])\n")
        (root / "safe.py").write_text("def add(a, b):\n    return a + b\n")
        result = sourceflow.scan(root)
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["leads"][0]["file"], "app.py")
        self.assertEqual(result["count"], 1)
        self.assertIn("not a finding", result["note"])

    def test_non_python_and_unknown_paths_are_handled(self):
        with self.assertRaises(ValueError):
            sourceflow.scan("/definitely/not/here")
        self.assertEqual(sourceflow.analyze_text("def broken(:", "bad.py")["leads"], [])


class SourceFlowRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        (self.tmp / "app.py").write_text(
            FLASK_HEAD
            + "@app.route('/run')\n"
              "def run():\n"
              "    return eval(request.args['x'])\n")

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def test_sourceflow_route(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        response = self.server.route(
            "GET", "/api/v1/sourceflow",
            {"path": str(self.tmp), "max_files": "50"}, headers, b"")
        self.assertEqual(response.status, 200)
        payload = json.loads(response.body.decode())
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["leads"][0]["sink"], "eval()")


if __name__ == "__main__":
    unittest.main()
