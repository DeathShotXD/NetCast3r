import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import lab_solver, training
from netcast3r.server import build_server
from netcast3r.server.lab_runner import RECIPES


def fake_complete(messages):
    return {
        "text": json.dumps({
            "thought": "the object id is not bound to the session",
            "action": "done",
            "args": {"summary": "Changed the id parameter to the other user's "
                                "object and read the API key from the response."},
        }),
        "provider": "fake", "model": "fake",
    }


def a_lab_without_a_recipe():
    for lab in training.catalog():
        if lab["slug"] in RECIPES:
            continue
        if (lab.get("source") or "portswigger") == "portswigger":
            return lab
    raise AssertionError("no Academy lab without a recipe")


class LabSolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.lab = a_lab_without_a_recipe()

    def tearDown(self):
        if getattr(self.server, "lab_runner", None) is not None:
            self.server.lab_runner.shutdown(wait=False)
        self.server.index.close()
        self.server.jobs.shutdown(wait=False)

    def test_a_banner_is_required_to_record_a_solve(self):
        result = lab_solver.solve_next(
            self.server, self.index, slug=self.lab["slug"],
            complete=fake_complete,
            provision=lambda server, lab: "https://abc123.web-security-academy.net",
            verify=lambda server, lab: "Congratulations, you solved the lab!")
        self.assertTrue(result["solved"])
        progress = training._progress_map(self.index)[self.lab["slug"]]
        self.assertEqual(progress["status"], "solved")
        mission = self.index.get_mission(result["mission_id"])
        self.assertTrue(mission["training"])
        self.assertIn("web-security-academy.net", " ".join(mission["scope"]))
        lessons, _ = self.index.list_lessons(limit=10)
        self.assertTrue(any("bounded solver" in (row.get("lesson") or "")
                            or "id parameter" in (row.get("lesson") or "")
                            for row in lessons))
        self.assertEqual(self.index.totals().get("findings", 0), 0)

    def test_no_banner_means_in_progress_not_solved(self):
        result = lab_solver.solve_next(
            self.server, self.index, slug=self.lab["slug"],
            complete=fake_complete,
            provision=lambda server, lab: "https://abc123.web-security-academy.net",
            verify=lambda server, lab: "")
        self.assertFalse(result["solved"])
        progress = training._progress_map(self.index)[self.lab["slug"]]
        self.assertEqual(progress["status"], "in_progress")

    def test_a_scripted_lab_goes_to_the_recipe_runner(self):
        slug = next(iter(RECIPES))
        result = lab_solver.solve_next(self.server, self.index, slug=slug)
        self.assertTrue(result["started"])
        self.assertEqual(result["mode"], "recipe")
        self.assertTrue(result.get("run_id"))

    def test_an_unknown_slug_is_refused(self):
        result = lab_solver.solve_next(self.server, self.index,
                                       slug="no-such-lab")
        self.assertFalse(result["started"])


if __name__ == "__main__":
    unittest.main()
