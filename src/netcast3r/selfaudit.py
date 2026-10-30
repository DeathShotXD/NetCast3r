"""Self-audit and diagnostics for the local control plane.

A security framework that does not inspect itself is a liability. These checks
are local and read-only: file permissions, secret-bearing state files, remote
MCP configuration, the MCP remote-access switch, and database integrity. They do
not scan the host or the network.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

SECRET_FILES = ("control-plane.json", "auth-profiles.json", "secrets.json",
                "integrations.json", "config.toml")


def _mode(path: Path) -> int:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return 0


def _world_readable(path: Path) -> bool:
    mode = _mode(path)
    return bool(mode & 0o077)


def audit(base: str | Path, routes: int = 0, tools: int = 0) -> dict:
    base = Path(base)
    findings: list[dict] = []

    def add(severity: str, title: str, detail: str, fix: str) -> None:
        findings.append({"severity": severity, "title": title,
                         "detail": detail, "fix": fix})

    if base.exists() and _world_readable(base):
        add("medium", "base directory is group/world accessible",
            f"{base} has mode {oct(_mode(base))}",
            "chmod 700 the NetCast3r base directory")
    db = base / "netcast3r.db"
    if db.exists() and _world_readable(db):
        add("high", "index database is group/world readable",
            f"{db} has mode {oct(_mode(db))}; it holds findings, audit rows, and lessons",
            "chmod 600 the database")
    for name in SECRET_FILES:
        path = base / name
        if path.exists() and _world_readable(path):
            add("high", f"{name} is group/world readable",
                f"{path} has mode {oct(_mode(path))}",
                f"chmod 600 {name}")
    if os.environ.get("NETCAST3R_MCP_ALLOW_REMOTE"):
        add("high", "remote MCP plane is enabled",
            "NETCAST3R_MCP_ALLOW_REMOTE lets the MCP client reach non-local URLs",
            "unset it unless the deployment is isolated and intentional")
    integrations = base / "integrations.json"
    if integrations.exists():
        try:
            config = json.loads(integrations.read_text() or "{}")
        except (OSError, ValueError):
            config = {}
        for name, server in (config.get("mcp_servers") or {}).items():
            if not isinstance(server, dict):
                continue
            url = str(server.get("url") or "")
            if url and not any(host in url for host in
                               ("127.0.0.1", "localhost", "[::1]")):
                add("medium", f"MCP server {name} points off-host",
                    url[:160], "confirm the host is trusted; prefer loopback or TLS")
        burp = config.get("burp") if isinstance(config.get("burp"), dict) else {}
        burp_url = str(burp.get("url") or "")
        if burp_url and not any(host in burp_url for host in
                                ("127.0.0.1", "localhost", "[::1]")):
            add("medium", "Burp MCP points off-host", burp_url[:160],
                "prefer loopback or a TLS tunnel")

    score = 100
    for finding in findings:
        score -= {"high": 25, "medium": 10, "low": 3}.get(finding["severity"], 5)
    score = max(0, score)
    return {
        "score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else
                 "C" if score >= 55 else "D",
        "findings": findings,
        "checks": {"routes": routes, "tools": tools,
                   "base": str(base), "base_mode": oct(_mode(base)) if base.exists() else ""},
        "note": ("Local posture only. It does not prove the absence of bugs or hostile "
                 "local users."),
    }


def diagnostics(index, base: str | Path, routes: int = 0, tools: int = 0) -> dict:
    base = Path(base)
    db = index.path
    integrity = "unknown"
    try:
        with index._lock:
            integrity = str(index.conn.execute("PRAGMA integrity_check").fetchone()[0])
    except sqlite3.Error as exc:
        integrity = f"error: {exc}"
    counts = {}
    for table in ("runs", "findings", "missions", "lessons", "skills", "expertise",
                  "tool_calls", "submissions"):
        try:
            with index._lock:
                counts[table] = int(index.conn.execute(
                    f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        except sqlite3.Error:
            counts[table] = -1
    return {
        "ok": integrity == "ok",
        "integrity": integrity,
        "database": {"path": str(db), "bytes": db.stat().st_size if db.exists() else 0,
                     "mode": oct(_mode(db)) if db.exists() else "",
                     "wal": (db.parent / (db.name + "-wal")).exists()},
        "counts": counts,
        "routes": routes,
        "tools": tools,
        "python": os.sys.version.split()[0],
        "base_mode": oct(_mode(base)) if base.exists() else "",
        "note": "Diagnostics are read-only and local.",
    }
