"""Build the dashboard SPA into package data.

Runs the Node build (a developer-only dependency) and copies the single
self-contained ``index.html`` into ``src/netcast3r/web/`` so the installed
package serves a finished dashboard with no build step at install time.

    python3 tools/build_web.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
OUT = ROOT / "src" / "netcast3r" / "web" / "index.html"


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=WEB, check=True)


def main() -> int:
    if not (WEB / "node_modules").exists():
        print("installing frontend dependencies")
        run(["npm", "install", "--no-audit", "--no-fund"])
    print("building the dashboard")
    run(["npm", "run", "build"])
    source = WEB / "dist" / "index.html"
    if not source.exists():
        print(f"missing build output: {source}", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, OUT)
    size = OUT.stat().st_size
    print(f"wrote {OUT.relative_to(ROOT)} ({size / 1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
