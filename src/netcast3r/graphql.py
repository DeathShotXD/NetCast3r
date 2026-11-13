"""GraphQL surface testing.

Beyond introspection, a GraphQL endpoint leaks through its errors, its
transport, and its batching. This module reads an endpoint for the questions
that matter to a hunter: is the schema introspectable, do errors name fields
that exist, is batching enabled, does GET run queries, and is the developer
console exposed.

Every probe is a read-only query. It never issues a mutation.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, urlunsplit

DEFAULT_AGENT = "NetCast3r/graphql-probe (+authorized-testing)"
MAX_BODY = 131072

INTROSPECTION_QUERY = "{__schema{queryType{name} types{name kind}}}"
TRIVIAL_QUERY = "{__typename}"
INVALID_QUERY = "{__typename __nc3r_no_such_field}"
CONSOLE_PATHS = ("/graphiql", "/playground", "/graphql/console/", "/v1/graphiql")

SUGGESTION_RE = re.compile(r"Did you mean (.+?)\?", re.IGNORECASE)


def default_fetch(url: str, method: str = "POST", body: str = "",
                  headers: dict | None = None, timeout: float = 8.0,
                  max_bytes: int = MAX_BODY) -> dict:
    """Send one GraphQL request. Never raises."""
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return {"status": 0, "text": "", "headers": {}, "error": "httpx unavailable"}
    request_headers = {"User-Agent": DEFAULT_AGENT, "Accept": "application/json"}
    if method == "POST":
        request_headers["Content-Type"] = "application/json"
    request_headers.update(headers or {})
    try:
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as client:
            if method == "GET":
                response = client.get(url, headers=request_headers)
            else:
                response = client.post(url, content=body, headers=request_headers)
            return {"status": response.status_code,
                    "text": (response.text or "")[:max_bytes],
                    "headers": dict(response.headers)}
    except Exception as exc:  # httpx raises many transport types
        return {"status": 0, "text": "", "headers": {}, "error": str(exc)[:200]}


def extract_json(text: str):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def analyze_introspection(response: dict) -> dict:
    data = extract_json(response.get("text") or "")
    if isinstance(data, dict) and isinstance(data.get("data"), dict) \
            and data["data"].get("__schema"):
        types = (data["data"]["__schema"] or {}).get("types") or []
        return {"enabled": True, "type_count": len(types),
                "query_type": ((data["data"]["__schema"] or {}).get("queryType") or {}).get("name")}
    errors = data.get("errors") if isinstance(data, dict) else None
    message = ""
    if isinstance(errors, list) and errors:
        message = str((errors[0] or {}).get("message", ""))[:200]
    return {"enabled": False, "type_count": 0, "error": message or
            (response.get("error") or "no schema in response")}


def suggestions(text: str) -> list:
    """Field names a GraphQL error leaks through 'Did you mean' hints."""
    found: list[str] = []
    for match in SUGGESTION_RE.finditer(text or ""):
        for name in re.split(r",\s*or\s*|,\s*", match.group(1)):
            name = name.strip().strip('"\'\\ ')
            if name and name not in found:
                found.append(name)
    return found


def _finding(items, ident, severity, title, detail, evidence=""):
    items.append({"id": ident, "severity": severity, "title": title,
                  "detail": detail, "evidence": evidence})


def probe(endpoint: str, fetch=None, timeout: float = 8.0,
          test_console: bool = True) -> dict:
    """Read one GraphQL endpoint for schema, suggestion, and batching leaks."""
    fetch = fetch or (lambda url, method, body, headers:
                      default_fetch(url, method, body, headers, timeout=timeout))
    findings: list = []
    results: dict = {}

    intro = fetch(endpoint, "POST", json.dumps({"query": INTROSPECTION_QUERY}), {})
    results["introspection"] = {
        "status": intro.get("status"),
        "analysis": analyze_introspection(intro),
        "error": intro.get("error", ""),
    }
    if results["introspection"]["analysis"]["enabled"]:
        _finding(findings, "introspection_enabled", "low",
                 "GraphQL introspection is enabled",
                 "The full schema is readable, which removes enumeration work "
                 "for an attacker.")
    else:
        _finding(findings, "introspection_disabled", "info",
                 "Introspection is disabled",
                 "The schema is hidden; error-based suggestions are the next "
                 "enumeration path.")

    invalid = fetch(endpoint, "POST", json.dumps({"query": INVALID_QUERY}), {})
    leaked = suggestions(invalid.get("text") or "")
    results["suggestions"] = {"found": leaked, "status": invalid.get("status"),
                              "error": invalid.get("error", "")}
    if leaked:
        _finding(findings, "field_suggestions", "medium",
                 "Errors reveal schema field names",
                 "A disabled schema still leaks names through validation "
                 "hints.", ", ".join(leaked[:8]))

    batch_body = json.dumps([{"query": TRIVIAL_QUERY}, {"query": TRIVIAL_QUERY}])
    batch = fetch(endpoint, "POST", batch_body, {})
    batch_data = extract_json(batch.get("text") or "")
    batching = isinstance(batch_data, list) and len(batch_data) >= 1
    results["batching"] = {"enabled": bool(batching), "status": batch.get("status"),
                           "error": batch.get("error", "")}
    if batching:
        _finding(findings, "batching_enabled", "medium",
                 "GraphQL batching is enabled",
                 "Multiple operations run in one request, which enables rate-"
                 "limit bypass and brute force in a single call.")

    get = fetch(endpoint + "?" + "query=" + TRIVIAL_QUERY.replace(" ", "%20") if "?" not in endpoint
                else endpoint, "GET", "", {})
    get_data = extract_json(get.get("text") or "")
    get_runs = isinstance(get_data, dict) and bool(get_data.get("data"))
    results["get"] = {"runs": bool(get_runs), "status": get.get("status"),
                      "error": get.get("error", "")}
    if get_runs:
        _finding(findings, "get_queries", "low", "Queries run over GET",
                 "GET GraphQL is easy to trigger cross-site and cache.")

    console = []
    if test_console:
        parts = urlsplit(endpoint if "://" in endpoint else "https://" + endpoint)
        root = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        for path in CONSOLE_PATHS:
            response = fetch(root + path, "GET", "", {})
            if response.get("status") == 200:
                console.append(path)
    results["console_paths"] = console
    if console:
        _finding(findings, "console_exposed", "medium",
                 "A GraphQL console path answered",
                 "An interactive console exposes the schema and query surface.",
                 ", ".join(console))

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return {
        "endpoint": endpoint,
        "findings": sorted(findings, key=lambda row: order.get(row["severity"], 9)),
        "results": results,
        "note": ("Read-only GraphQL probes. Field-level authorization still "
                 "needs a two-identity comparison."),
    }


def summary() -> dict:
    return {
        "checks": ["introspection", "field_suggestions", "batching",
                   "get_queries", "console_paths"],
        "note": "Read-only queries only; this module never issues a mutation.",
    }
