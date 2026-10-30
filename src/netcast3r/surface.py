"""Attack-surface diff between two runs.

Continuous testing is only valuable if the change is visible. This compares the
per-run inventory SQLite files the runner already writes: subdomains, assets,
JavaScript files, endpoints, secrets, and findings. It does not crawl, guess, or
merge runs; missing input is reported as missing.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


def _run_db(index, run_id: str) -> Path:
    run = index.get_run(run_id)
    if not run:
        raise ValueError(f"run not found: {run_id}")
    results_dir = (run.get("counts") or {}).get("results_dir") or run.get("results_dir") or ""
    if not results_dir:
        raise ValueError(f"run {run_id} has no results directory")
    path = Path(str(results_dir)) / "netcast3r.db"
    if not path.is_file():
        raise ValueError(f"run {run_id} has no inventory database")
    return path


def _rows(path: Path, table: str, column: str) -> set[str]:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return {str(row[0]) for row in conn.execute(
                f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL AND {column} != ''")}
        finally:
            conn.close()
    except sqlite3.Error:
        return set()


def _findings(path: Path) -> dict[str, dict]:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            return {
                str(row["title"]): {"severity": row["severity"],
                                    "secret_type": row["secret_type"],
                                    "status": row["status"]}
                for row in conn.execute("SELECT title, severity, secret_type, status FROM findings")
                if row["title"]
            }
        finally:
            conn.close()
    except sqlite3.Error:
        return {}


def _sample(values: set[str], limit: int = 200) -> list[str]:
    return sorted(values)[:limit]


def diff(index, run_a: str, run_b: str, limit: int = 200) -> dict:
    """Compare run A (base) with run B (newer) and return added/removed items."""
    path_a, path_b = _run_db(index, run_a), _run_db(index, run_b)
    tables = {
        "subdomains": ("subdomains", "host"),
        "assets": ("assets", "url"),
        "js": ("js_files", "url"),
        "endpoints": ("endpoints", "url"),
        "secrets": ("candidates", "value"),
    }
    added: dict[str, list[str]] = {}
    removed: dict[str, list[str]] = {}
    counts: dict[str, dict] = {}
    for name, (table, column) in tables.items():
        old = _rows(path_a, table, column)
        new = _rows(path_b, table, column)
        add, drop = new - old, old - new
        added[name] = _sample(add, limit)
        removed[name] = _sample(drop, limit)
        counts[name] = {"added": len(add), "removed": len(drop),
                        "base": len(old), "new": len(new)}
    findings_a, findings_b = _findings(path_a), _findings(path_b)
    new_findings = [{"title": title, **findings_b[title]}
                    for title in sorted(set(findings_b) - set(findings_a))][:limit]
    gone_findings = [{"title": title, **findings_a[title]}
                     for title in sorted(set(findings_a) - set(findings_b))][:limit]
    changed = []
    for title in sorted(set(findings_a) & set(findings_b)):
        if findings_a[title].get("severity") != findings_b[title].get("severity"):
            changed.append({"title": title, "before": findings_a[title],
                            "after": findings_b[title]})
    return {
        "base_run": run_a,
        "new_run": run_b,
        "counts": counts,
        "added": added,
        "removed": removed,
        "findings": {"new": new_findings[:limit], "gone": gone_findings[:limit],
                     "severity_changed": changed[:limit]},
        "summary": {
            "new_endpoints": counts["endpoints"]["added"],
            "new_subdomains": counts["subdomains"]["added"],
            "new_secrets": counts["secrets"]["added"],
            "new_findings": len(new_findings),
            "changed_findings": len(changed),
        },
        "note": ("The diff reads the two run inventories as they were written. A missing "
                 "run database is an error, not an empty surface."),
    }
