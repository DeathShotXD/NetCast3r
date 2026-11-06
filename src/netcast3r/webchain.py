"""File-read chain primitives.

This module turns the manual LFI method into reusable logic:

1. probe one file parameter with traversal depth and encoding variants;
2. classify what came back (server source, config, HTML, not found, binary);
3. scan source for credentials, SQL concatenation, cookie trust, upload and
   command sinks;
4. rank the next chain step, including the boundary where a write or an OS
   command must stop for approval.

It never fetches anything. The MCP tools own scope, audit, and HTTP.
"""

from __future__ import annotations

import re

NOT_FOUND_MARKERS = (
    "file not found", "no such file", "not found", "cannot find",
    "does not exist", "error: file", "404 - file",
)

SOURCE_MARKERS = (
    "<%", "<%@", "server.createobject", "request.form", "request.querystring",
    "request.cookies", "conn.execute", "set conn", "response.redirect",
    "function ", "sub ", "dim ",
)

CONFIG_MARKERS = (
    "<configuration", "<connectionstrings", "appsettings", "<system.webserver",
)

UPLOAD_MARKERS = (
    "multipart/form-data", 'type="file"', "type='file'", "saveas",
    "uploadfile", "fileupload", "request.files",
)

EXEC_MARKERS = (
    "wscript.shell", "shell.application", "server.execute", "server.transfer",
    "eval(", "createobject(\"wscript",
)

DB_EXEC_MARKERS = ("xp_cmdshell", "sp_oacreate", "openrowset", "sp_executesql")

DEFAULT_PATHS = (
    "web.config",
    "../web.config",
    "..%2fweb.config",
    "../global.asa",
    "../index.asp",
    "../default.asp",
    "../login.asp",
    "../admin/default.asp",
    "../includes/conn.asp",
    "../includes/connection.asp",
    "../connection.asp",
    "../config.asp",
    "../upload.asp",
    "../uploadfile.asp",
    "../fileupload.asp",
    "../admin/upload.asp",
    "../HQ/check.asp",
    "../HQ/management_console.asp",
    "../HQ/LocationIssue.asp",
    "../HQ/reports_main.asp",
    "../HQ/upload.asp",
    "../HQ/InBoundEMS.asp",
    "../HQ/newsample.asp",
)

DEFAULT_SOURCE_PATHS = (
    "../HQ/check.asp",
    "../HQ/management_console.asp",
    "../HQ/LocationIssue.asp",
    "../HQ/reports_main.asp",
    "../web.config",
    "../global.asa",
    "../includes/conn.asp",
    "../connection.asp",
    "../config.asp",
    "../upload.asp",
    "../uploadfile.asp",
    "../fileupload.asp",
    "../HQ/upload.asp",
)

_SQL_CONCAT = re.compile(
    r"(?is)\b(select|insert|update|delete)\b[^\n]{0,160}?"
    r"(\"\s*&\s*|&\s*\"\s*)?(request\.|uid|pwd|id|user|name)\b")
_SECRET_PATTERNS = (
    ("connection-string", re.compile(
        r"(?i)(provider|data source|initial catalog|server)\s*=\s*[^;\"']{2,120};"
        r"[^\n\"']{0,200}")),
    ("password", re.compile(r"(?i)\b(password|pwd|passwd)\s*=\s*[^;\"'\s]{3,120}")),
    ("api-key", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|token)\s*[=:]\s*[A-Za-z0-9_\-]{12,}")),
)
_COOKIE_TRUST = re.compile(r"(?i)request\.cookies\(\s*[\"']?(uid|pwd|user|pass)")
_SQL_EXEC = re.compile(r"(?i)\bconn\.execute\s*\(")


def _mask(value: str) -> str:
    text = str(value or "")
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * min(len(text) - 4, 12)}{text[-2:]}"


def _line_of(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return text[start:end if end >= 0 else len(text)].strip()[:200]


_REDACT = re.compile(
    r"(?i)((?:password|pwd|passwd|uid|user\s*id|connectionstring|data source|"
    r"api[_-]?key|secret[_-]?key|token)\s*[=:]\s*)[^;\"'\s]+")


def _redact_line(line: str) -> str:
    return _REDACT.sub(r"\1***", str(line or ""))[:200]


def classify(text: str, content_type: str = "") -> dict:
    """Name what a file-read response actually is."""
    body = str(text or "")
    lowered = body.lower()
    kind = "empty"
    if not body.strip():
        kind = "empty"
    elif any(marker in lowered for marker in NOT_FOUND_MARKERS) and len(body) < 500:
        kind = "not-found"
    elif any(marker in lowered for marker in CONFIG_MARKERS):
        kind = "config"
    elif any(marker in lowered for marker in SOURCE_MARKERS):
        kind = "source"
    elif "<html" in lowered or "<!doctype" in lowered:
        kind = "html"
    elif "application/octet-stream" in str(content_type or "").lower():
        kind = "binary"
    else:
        kind = "text"
    return {"kind": kind, "bytes": len(body),
            "source": kind in {"source", "config"}}


def scan(text: str) -> dict:
    """Find secrets and sinks in one source or config file, never returning values."""
    body = str(text or "")
    secrets = []
    seen = set()
    for name, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(body):
            key = (name, match.start())
            if key in seen:
                continue
            seen.add(key)
            raw = match.group(0)
            secrets.append({"type": name,
                            "masked": _mask(raw.split("=", 1)[-1].strip()),
                            "line": _redact_line(_line_of(body, match.start()))})
    sinks = []
    lower = body.lower()
    if _SQL_CONCAT.search(body) and _SQL_EXEC.search(body):
        sinks.append({"kind": "sql-concatenation",
                      "detail": "SQL text is built from input and executed"})
    if _COOKIE_TRUST.search(body):
        sinks.append({"kind": "cookie-trust",
                      "detail": "authentication reads uid/pwd from cookies"})
    for marker in UPLOAD_MARKERS:
        if marker in lower:
            sinks.append({"kind": "upload", "detail": f"upload marker: {marker}"})
            break
    for marker in EXEC_MARKERS:
        if marker in lower:
            sinks.append({"kind": "exec", "detail": f"exec marker: {marker}"})
            break
    for marker in DB_EXEC_MARKERS:
        if marker in lower:
            sinks.append({"kind": "db-exec", "detail": f"database command marker: {marker}"})
            break
    # De-duplicate by kind, keeping the first detail.
    unique = {}
    for item in sinks:
        unique.setdefault(item["kind"], item)
    return {"secrets": secrets[:20], "sinks": list(unique.values()),
            "lines": len(body.splitlines()), "bytes": len(body)}


def chain_candidates(sources: list[dict], auth_bypass: dict | None = None) -> list[dict]:
    """Rank next steps from the discovered source and the auth result."""
    kinds = {sink.get("kind") for item in sources for sink in item.get("sinks") or []}
    out = []
    if auth_bypass and auth_bypass.get("bypass"):
        out.append({
            "kind": "admin-surface",
            "risk": "medium",
            "reason": "the cookie injection produced an authenticated session",
            "next": "map the authenticated console for upload, export, or query features",
        })
    if "upload" in kinds:
        out.append({
            "kind": "upload-to-rce",
            "risk": "high",
            "reason": "a source file references a file upload",
            "next": "confirm the handler, then request explicit approval before writing a proof file",
            "requires_approval": True,
        })
    if "exec" in kinds:
        out.append({
            "kind": "server-exec",
            "risk": "high",
            "reason": "a source file references a server-side execute primitive",
            "next": "trace whether user input reaches it; proof requires approval",
            "requires_approval": True,
        })
    if "db-exec" in kinds:
        out.append({
            "kind": "db-command-execution",
            "risk": "critical",
            "reason": "a source file references a database command primitive",
            "next": ("this needs a privileged database account and an OS command; "
                     "stop for explicit operator approval"),
            "requires_approval": True,
        })
    if any(item.get("secrets") for item in sources):
        out.append({
            "kind": "credential-review",
            "risk": "low",
            "reason": "source or config contains credential-shaped values",
            "next": "record the exposure as a finding; do not authenticate with the value",
        })
    return out


def summarize(sources: list[dict], auth_bypass: dict | None = None) -> dict:
    """One verdict for a file-read chain."""
    readable = [item for item in sources if item.get("kind") in {"source", "config"}]
    secrets = [secret for item in sources for secret in item.get("secrets") or []]
    sink_kinds = sorted({sink.get("kind") for item in sources
                         for sink in item.get("sinks") or []})
    candidates = chain_candidates(sources, auth_bypass)
    if any(item.get("requires_approval") for item in candidates):
        verdict = "chain-available-needs-approval"
    elif auth_bypass and auth_bypass.get("bypass"):
        verdict = "source-and-auth-bypass"
    elif readable:
        verdict = "source-disclosure"
    else:
        verdict = "read-only-no-source"
    return {
        "verdict": verdict,
        "readable_sources": len(readable),
        "secrets": len(secrets),
        "sink_kinds": sink_kinds,
        "candidates": candidates,
        "note": ("A file read is not code execution. Any upload or OS command step "
                 "is listed for approval and is never fired by this module."),
    }
