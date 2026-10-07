"""The generated frontend tokens must never drift from netcast3r.theme."""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TokenDriftTests(unittest.TestCase):
    def test_generated_tokens_match_theme(self):
        result = subprocess.run(
            [sys.executable, "tools/gen_tokens.py", "--check"],
            cwd=ROOT, capture_output=True, text=True, timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_token_files_are_present(self):
        for path in ("web/src/tokens.css", "web/src/tokens.ts"):
            self.assertTrue((ROOT / path).exists(), f"{path} is missing, run tools/gen_tokens.py")


if __name__ == "__main__":
    unittest.main()
