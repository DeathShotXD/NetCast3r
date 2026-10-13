import json
import os
import tempfile
import unittest
from pathlib import Path

from netcast3r.cli import _apply_options, _load_seeds, build_parser, main
from netcast3r.config import default_config


class CliParserTests(unittest.TestCase):
    def test_no_command_returns_one(self):
        self.assertEqual(main([]), 1)

    def test_run_without_input_returns_one(self):
        self.assertEqual(main(["run"]), 1)

    def test_providers_command_returns_zero(self):
        self.assertEqual(main(["providers"]), 0)

    def test_no_subdomains_flag_is_parsed(self):
        args = build_parser().parse_args(["run", "--no-subdomains", "--input", "example.com"])
        self.assertTrue(args.no_subdomains)
        config = default_config()
        _apply_options(config, args)
        self.assertFalse(config.run.subdomains)

    def test_zero_valued_options_are_applied(self):
        args = build_parser().parse_args(["run", "--depth", "0", "--rate", "0", "--input", "x.com"])
        config = default_config()
        _apply_options(config, args)
        self.assertEqual(config.run.depth, 0)
        self.assertEqual(config.run.requests_per_second, 0.0)

    def test_comment_lines_are_skipped(self):
        workdir = Path(tempfile.mkdtemp())
        path = workdir / "seeds.txt"
        path.write_text("# a comment\n   # an indented comment\nexample.com\n\nreal.test\n")
        seeds = _load_seeds(str(path))
        self.assertEqual(seeds, ["example.com", "real.test"])


if __name__ == "__main__":
    unittest.main()
