"""Client-side path traversal (CSPT) analysis.

A page that builds a request path from ``location.hash`` or a ``postMessage``
payload hands an attacker the path. ``#/../../api/delete`` then reaches an
endpoint the UI never meant to call, and a GET-to-state-change endpoint turns
that into CSRF.

This is static analysis over JavaScript text: which line combines a
user-controlled source with a request sink. It reports the line, both halves,
and a suggested traversal payload. Nothing is executed or fetched.
"""

from __future__ import annotations

import re
from pathlib import Path

MAX_SOURCE = 4_000_000

SOURCES = (
    ("location.hash", r"location\.hash"),
    ("location.search", r"location\.search"),
    ("location.href", r"location\.href"),
    ("document.URL", r"document\.URL"),
    ("document.referrer", r"document\.referrer"),
    ("window.name", r"window\.name"),
    ("postMessage data", r"\b(?:event|e|ev|msg|message)\.data\b"),
    ("URLSearchParams", r"new\s+URLSearchParams\s*\("),
    ("route param", r"\b(?:this\.)?\$route\.(?:params|query)\b"),
)

SINKS = (
    ("fetch", r"\bfetch\s*\("),
    ("axios", r"\baxios(?:\.[a-z]+)?\s*\("),
    ("xhr.open", r"\.open\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE)"),
    ("jquery", r"\$\.(?:get|post|ajax|getJSON)\s*\("),
    ("new URL", r"\bnew\s+URL\s*\("),
    ("navigate", r"\b(?:navigate|router\.(?:push|replace)|history\.pushState)\s*\("),
)

PATH_BUILD = re.compile(r"(\.\./|\$\{[^}]*\}|/\s*\+|\+\s*['\"`]/|['\"`]/['\"`]|/\[)")
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _line_hits(patterns, line: str) -> list:
    return [name for name, pattern in patterns if re.search(pattern, line)]


def analyze(text: str, filename: str = "bundle.js") -> dict:
    """Find lines that mix a user-controlled source with a request sink."""
    findings: list = []
    lines = str(text or "").splitlines()
    for index, line in enumerate(lines, start=1):
        sources = _line_hits(SOURCES, line)
        sinks = _line_hits(SINKS, line)
        if not sources or not sinks:
            continue
        builds_path = bool(PATH_BUILD.search(line))
        # A source and sink in the same statement that also builds a path is the
        # strong CSPT shape; without path building it is still worth a look.
        severity = "high" if builds_path and "postMessage data" in sources else (
            "medium" if builds_path else "low")
        findings.append({
            "file": filename,
            "line": index,
            "sources": sources,
            "sinks": sinks,
            "builds_path": builds_path,
            "severity": severity,
            "snippet": line.strip()[:300],
            "payload": "../../" if builds_path else "",
            "detail": (f"{', '.join(sources)} reaches {', '.join(sinks)}"
                       + (" while building a path" if builds_path else "")),
        })
    findings.sort(key=lambda row: (SEVERITY_ORDER.get(row["severity"], 9),
                                   row["line"]))
    counts: dict = {}
    for row in findings:
        counts[row["severity"]] = counts.get(row["severity"], 0) + 1
    return {
        "file": filename,
        "lines": len(lines),
        "findings": findings,
        "counts": counts,
        "note": ("A same-line source-to-sink hit is a lead. Confirm the request "
                 "is state-changing and reachable cross-site before reporting."),
    }


def scan(path: str, filename: str = "") -> dict:
    """Analyze one JavaScript file from disk (bounded read)."""
    candidate = Path(path)
    if not candidate.is_file():
        return {"file": path, "findings": [], "counts": {},
                "error": "file not found"}
    try:
        text = candidate.read_text(encoding="utf-8", errors="ignore")[:MAX_SOURCE]
    except OSError as exc:
        return {"file": path, "findings": [], "counts": {}, "error": str(exc)[:200]}
    return analyze(text, filename or candidate.name)


def summary() -> dict:
    return {
        "sources": [name for name, _ in SOURCES],
        "sinks": [name for name, _ in SINKS],
        "note": "Static analysis only; it never issues a request.",
    }
