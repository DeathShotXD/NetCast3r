import unittest
from pathlib import Path

from netcast3r.config import RunConfig
from netcast3r.server.runner import apply_run_options, results_dir_for


class RunOptionTests(unittest.TestCase):
    def test_zero_depth_is_applied(self):
        config = RunConfig(depth=2)
        apply_run_options(config, {"depth": 0})
        self.assertEqual(config.depth, 0)

    def test_max_pages_is_a_page_limit_not_a_concurrency_setting(self):
        config = RunConfig(concurrency=20, max_pages=100)
        apply_run_options(config, {"max_pages": 37})
        self.assertEqual(config.max_pages, 37)
        self.assertEqual(config.concurrency, 20)

    def test_blank_or_invalid_values_leave_defaults_alone(self):
        config = RunConfig(depth=2, max_pages=100)
        apply_run_options(config, {"depth": "", "max_pages": "not-a-number"})
        self.assertEqual(config.depth, 2)
        self.assertEqual(config.max_pages, 100)

    def test_results_dir_is_derived_from_the_run_id(self):
        self.assertEqual(results_dir_for("run_abc", {"results_dir": "results"}),
                         Path("results/run_abc"))

    def test_resume_uses_the_parent_directory_only_when_its_store_exists(self):
        from tempfile import TemporaryDirectory

        # results_dir is deliberately relative; the server refuses absolute
        # output roots today, so exercise the helper from a temporary cwd.
        import os

        previous = os.getcwd()
        with TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                parent = Path("results") / "run_parent"
                self.assertEqual(
                    results_dir_for("run_child", {
                        "results_dir": "results", "resume": True,
                        "resume_from": "run_parent",
                    }),
                    Path("results") / "run_child",
                )
                parent.mkdir(parents=True)
                (parent / "netcast3r.db").write_text("")
                self.assertEqual(
                    results_dir_for("run_child", {
                        "results_dir": "results", "resume": True,
                        "resume_from": "run_parent",
                    }),
                    parent,
                )
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
