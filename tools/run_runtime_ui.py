#!/usr/bin/env python3
"""Start the control plane against the workspace .runtime mirror.

Cursor's agent sandbox cannot write ~/.netcast3r. This entrypoint keeps the
live hunt on a writable workspace copy so the operator and the agent share one
plane during sandboxed sessions.
"""

from __future__ import annotations

from pathlib import Path

from netcast3r.server import serve

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / ".runtime"


def main() -> None:
    BASE.mkdir(parents=True, exist_ok=True)
    serve(
        host="127.0.0.1",
        port=7857,
        open_browser=False,
        results_dir=ROOT / "results",
        base=BASE,
    )


if __name__ == "__main__":
    main()
