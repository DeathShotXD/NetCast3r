"""Virtual-host discovery.

One IP can answer for many names. The crawler walks the name the operator gave
it; a vhost audit asks the same address with different ``Host`` values and
labels the ones that answer with a different page, the way reconFTW's
VhostFinder does.

The comparison is deterministic and structure-only: status, body length, a body
hash, and the title. A response that matches a random unclaimed name is a
wildcard, not a discovery, and is called out so a catch-all server does not
inflate the result.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

DEFAULT_AGENT = "NetCast3r/vhost-discovery (+authorized-testing)"
MAX_BODY = 131072
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

DEFAULT_PREFIXES = (
    "www", "dev", "development", "staging", "stage", "test", "testing", "qa",
    "uat", "preprod", "demo", "beta", "old", "legacy", "admin", "internal",
    "intranet", "portal", "api", "app", "apps", "dashboard", "console", "panel",
    "manage", "jenkins", "gitlab", "git", "grafana", "kibana", "prometheus",
    "phpmyadmin", "adminer", "sql", "db", "database", "backup", "mail",
    "webmail", "vpn", "sso", "auth", "login", "jira", "confluence", "wiki",
    "support", "status", "monitor", "shop", "store", "crm", "erp",
)


def _title(body: str) -> str:
    match = TITLE_RE.search(body or "")
    if not match:
        return ""
    return " ".join(match.group(1).split())[:120]


def fingerprint(response: dict) -> tuple:
    """A stable structure-only signature for one response."""
    body = response.get("body") or ""
    digest = hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16]
    return (int(response.get("status") or 0), len(body), digest, _title(body))


def default_fetch(url: str, headers: dict, timeout: float = 8.0,
                  max_bytes: int = MAX_BODY) -> dict:
    """Fetch a URL with an explicit Host header. Never raises."""
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a hard dependency
        return {"status": 0, "body": "", "error": "httpx unavailable"}
    request_headers = {"User-Agent": DEFAULT_AGENT}
    request_headers.update(headers or {})
    try:
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout,
                          headers=request_headers) as client:
            response = client.get(url)
            return {"status": response.status_code,
                    "body": (response.text or "")[:max_bytes],
                    "final_url": str(response.url)}
    except Exception as exc:  # httpx raises many transport types
        return {"status": 0, "body": "", "error": str(exc)[:200]}


def _host_of(url: str) -> str:
    return (urlsplit(url if "://" in url else f"https://{url}").hostname or "").lower()


def candidates(base: str, hosts, prefixes, limit: int) -> list[str]:
    origin = _host_of(base)
    out: list[str] = []
    for value in hosts or []:
        name = str(value).strip().lower().rstrip(".")
        if name and name not in out:
            out.append(name)
    if origin:
        parent = origin
        labels = origin.split(".")
        if len(labels) > 2:
            parent = ".".join(labels[1:])
        for prefix in (DEFAULT_PREFIXES if prefixes is None else prefixes):
            name = f"{prefix}.{parent}"
            if name not in out:
                out.append(name)
    return out[:max(1, int(limit))]


def discover(base_url: str, hosts=None, prefixes=None, fetch=None,
             timeout: float = 8.0, limit: int = 64,
             random_probe: bool = True) -> dict:
    """Compare responses for candidate ``Host`` values against the baseline.

    ``fetch`` takes ``(url, headers)`` and returns ``{"status", "body"}``. It is
    injectable so the engine runs offline in tests.
    """
    fetch = fetch or (lambda url, headers: default_fetch(url, headers,
                                                         timeout=timeout))
    origin = _host_of(base_url)
    result = {
        "base": base_url,
        "origin": origin,
        "baseline": {},
        "wildcard": None,
        "checked": 0,
        "counts": {"virtual_host": 0, "default": 0, "wildcard": 0, "error": 0},
        "virtual_hosts": [],
        "results": [],
        "note": "",
    }
    if not origin:
        return {**result, "note": "base_url must contain a host"}

    base_response = fetch(base_url, {})
    base_fp = fingerprint(base_response)
    result["baseline"] = {"status": base_fp[0], "length": base_fp[1],
                          "title": base_fp[3],
                          "error": base_response.get("error", "")}

    wildcard_fp = None
    if random_probe:
        probe_host = f"nc3r-{hashlib.sha256(origin.encode()).hexdigest()[:10]}.{origin}"
        probe = fetch(base_url, {"Host": probe_host})
        probe_fp = fingerprint(probe)
        if probe_fp != base_fp and probe_fp[0]:
            wildcard_fp = probe_fp
            result["wildcard"] = {"host": probe_host, "status": probe_fp[0],
                                  "length": probe_fp[1], "title": probe_fp[3]}

    names = candidates(base_url, hosts, prefixes, limit)
    rows = []
    for name in names:
        response = fetch(base_url, {"Host": name})
        fp = fingerprint(response)
        if not fp[0]:
            status = "error"
        elif fp == base_fp:
            status = "default"
        elif wildcard_fp is not None and fp == wildcard_fp:
            status = "wildcard"
        else:
            status = "virtual_host"
        row = {
            "host": name, "status": status, "http_status": fp[0],
            "length": fp[1], "title": fp[3],
            "delta": fp[1] - base_fp[1],
            "error": response.get("error", ""),
        }
        rows.append(row)
        result["counts"][status] = result["counts"].get(status, 0) + 1
        if status == "virtual_host":
            result["virtual_hosts"].append(row)
    result["checked"] = len(rows)
    rows.sort(key=lambda row: (row["status"] != "virtual_host", row["host"]))
    result["results"] = rows
    result["note"] = ("A virtual host is a name that answers differently on the "
                      "same address. Confirm it is in scope before probing it "
                      "further.")
    return result
