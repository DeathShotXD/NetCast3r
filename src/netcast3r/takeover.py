"""Dangling-CNAME / subdomain takeover detection.

A subdomain is takeover-ready when its DNS still delegates to a third-party
service that no longer has an owner for that name. The check is deterministic:
resolve the CNAME chain, match the terminal name against a service fingerprint
table, then confirm with the provider's own "not found" response. A match is a
lead, never an exploitation step, and claiming a name is always a human action.

Fingerprints come from the community can-i-take-over-xyz corpus, pinned as data
in ``data/takeover_fingerprints.json`` so a review can diff the table.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

FINGERPRINTS_PATH = Path(__file__).with_name("data") / "takeover_fingerprints.json"
DEFAULT_AGENT = "NetCast3r/subdomain-takeover (+authorized-testing)"
MAX_BODY = 65536
MIN_GLOBAL_FINGERPRINT = 12

VERDICT_ORDER = {"vulnerable": 0, "candidate": 1, "claimed": 2,
                 "unresolvable": 3, "no_match": 4}


@dataclass(frozen=True)
class Fingerprint:
    service: str
    cnames: tuple
    fingerprint: str
    http_status: int | None
    nxdomain: bool
    vulnerable: bool
    status: str
    documentation: str


@lru_cache(maxsize=1)
def fingerprints() -> tuple:
    try:
        raw = json.loads(FINGERPRINTS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    rows = []
    for item in raw.get("services", []):
        if not isinstance(item, dict) or not item.get("service"):
            continue
        cnames = tuple(str(value).lower().strip(".") for value in
                       (item.get("cname") or []) if value)
        rows.append(Fingerprint(
            service=str(item["service"]),
            cnames=cnames,
            fingerprint=str(item.get("fingerprint") or ""),
            http_status=item.get("http_status") if isinstance(
                item.get("http_status"), int) else None,
            nxdomain=bool(item.get("nxdomain")),
            vulnerable=bool(item.get("vulnerable") or item.get("status") == "Vulnerable"),
            status=str(item.get("status") or ""),
            documentation=str(item.get("documentation") or ""),
        ))
    return tuple(rows)


def _suffix_match(target: str, suffix: str) -> bool:
    target = (target or "").lower().rstrip(".")
    suffix = (suffix or "").lower().strip(".")
    return bool(target and suffix) and (target == suffix or target.endswith("." + suffix))


def match_cname(target: str, table: tuple | None = None) -> list:
    """Every fingerprint whose CNAME suffix the target name ends with."""
    table = table if table is not None else fingerprints()
    hits = [row for row in table if any(_suffix_match(target, s) for s in row.cnames)]
    # A vulnerable service outranks a "not vulnerable" one on the same suffix.
    hits.sort(key=lambda row: (not row.vulnerable, row.service.lower()))
    return hits


def _body_contains(body: str, needle: str) -> bool:
    if not body or not needle:
        return False
    return needle.lower() in body.lower()


def _snippet(body: str, needle: str, width: int = 160) -> str:
    if not body:
        return ""
    if not needle:
        return body[:width]
    index = body.lower().find(needle.lower())
    if index < 0:
        return body[:width]
    start = max(0, index - width // 3)
    return body[start:start + width]


def default_fetch(url: str, timeout: float = 8.0, max_bytes: int = MAX_BODY) -> dict:
    """Fetch a URL for fingerprint confirmation. Never raises."""
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a hard dependency
        return {"status": 0, "body": "", "error": "httpx unavailable"}
    try:
        with httpx.Client(verify=False, follow_redirects=True, timeout=timeout,
                          headers={"User-Agent": DEFAULT_AGENT}) as client:
            response = client.get(url)
            text = response.text[:max_bytes] if response.text else ""
            return {"status": response.status_code, "body": text,
                    "final_url": str(response.url), "headers": dict(response.headers)}
    except Exception as exc:  # httpx raises many transport types
        return {"status": 0, "body": "", "error": str(exc)[:200]}


def check(host: str, resolver=None, fetch=None, table: tuple | None = None,
          timeout: float = 8.0, max_bytes: int = MAX_BODY) -> dict:
    """Assess one host name for a dangling-CNAME takeover.

    ``resolver`` takes a name and returns the dict from
    ``netcast3r.dnsq.resolve_chain``. ``fetch`` takes a URL and returns
    ``{"status", "body"}``. Both are injectable so the engine is offline in
    tests.
    """
    from . import dnsq

    host = (host or "").strip().lower().rstrip(".")
    resolver = resolver or (lambda name: dnsq.resolve_chain(name, timeout=timeout))
    fetch = fetch or (lambda url: default_fetch(url, timeout=timeout, max_bytes=max_bytes))
    table = table if table is not None else fingerprints()

    result = {
        "host": host,
        "cname_chain": [],
        "cname": "",
        "addresses": [],
        "service": "",
        "status": "no_match",
        "matched_fingerprint": "",
        "http_status": None,
        "evidence": "",
        "documentation": "",
        "note": "",
    }

    try:
        chain = resolver(host)
    except dnsq.DnsError as exc:
        return {**result, "status": "unresolvable", "note": f"dns error: {exc}"}

    targets = list(chain.get("chain") or [])
    terminal = str(chain.get("cname") or host).rstrip(".")
    if not targets and terminal != host:
        targets = [terminal]
    result["cname_chain"] = targets
    result["cname"] = targets[-1] if targets else terminal
    result["addresses"] = list(chain.get("addresses") or [])
    nxdomain = bool(chain.get("nxdomain")) or not result["addresses"]

    matches: list = []
    for name in targets or [terminal]:
        matches.extend(row for row in match_cname(name, table) if row not in matches)
    if not matches and not targets:
        # No CNAME delegation at all: there is nothing to take over.
        result["note"] = "no CNAME chain to a third-party service"
        return result

    primary = matches[0] if matches else None
    if primary is not None:
        result["service"] = primary.service
        result["documentation"] = primary.documentation
        # The provider itself declares this service dangling by NXDOMAIN.
        if (primary.nxdomain or (primary.vulnerable and not primary.fingerprint)) and nxdomain:
            return {**result, "status": "vulnerable",
                    "matched_fingerprint": "NXDOMAIN",
                    "evidence": f"{primary.service} target {result['cname']} does not resolve",
                    "note": "the CNAME target no longer resolves at the provider"}

    for scheme in ("https", "http"):
        response = fetch(f"{scheme}://{host}/")
        status = response.get("status") or 0
        body = response.get("body") or ""
        result["http_status"] = status or result["http_status"]
        if response.get("error"):
            result["note"] = f"fetch error: {response['error']}"
        hit = ""
        hit_row = None
        for row in matches:
            if row.fingerprint and _body_contains(body, row.fingerprint):
                hit, hit_row = row.fingerprint, row
                break
        if not hit and targets:
            # A service the corpus knows only by its response body.
            for row in table:
                text = row.fingerprint
                if (text and len(text) >= MIN_GLOBAL_FINGERPRINT
                        and _body_contains(body, text)):
                    hit, hit_row = text, row
                    break
        if hit:
            vulnerable = bool(hit_row and hit_row.vulnerable and matches)
            return {**result,
                    "service": (hit_row.service if hit_row else result["service"]),
                    "documentation": (hit_row.documentation if hit_row
                                      else result["documentation"]),
                    "status": "vulnerable" if vulnerable else "candidate",
                    "matched_fingerprint": hit,
                    "evidence": _snippet(body, hit),
                    "note": ("provider fingerprint answered for an unclaimed name"
                             if vulnerable else
                             "fingerprint matched; confirm the name is really unclaimed")}
        if status and status < 500:
            if matches:
                # The service answered normally: it still has an owner.
                return {**result, "status": "claimed",
                        "note": f"service answered HTTP {status}; the name appears claimed"}
            result["status"] = "no_match"
            result["note"] = "the name answers normally; no takeover fingerprint matched"
            return result

    if matches and nxdomain:
        return {**result, "status": "candidate",
                "note": "dangling CNAME but the provider did not confirm a takeover"}
    if matches:
        return {**result, "status": "candidate",
                "note": "known service CNAME; no confirmation response observed"}
    return {**result, "status": "no_match",
            "note": "no takeover fingerprint matched"}


def scan(hosts, resolver=None, fetch=None, table: tuple | None = None,
         limit: int = 200, timeout: float = 8.0) -> dict:
    """Check a bounded list of names and rank the results by verdict."""
    seen: list[str] = []
    for value in hosts or []:
        name = (value or "").strip().lower().rstrip(".")
        if name and name not in seen:
            seen.append(name)
        if len(seen) >= max(1, int(limit)):
            break
    results = [check(name, resolver=resolver, fetch=fetch, table=table, timeout=timeout)
               for name in seen]
    results.sort(key=lambda row: (VERDICT_ORDER.get(row["status"], 9), row["host"]))
    counts: dict[str, int] = {}
    for row in results:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {
        "checked": len(results),
        "counts": counts,
        "vulnerable": [row for row in results if row["status"] == "vulnerable"],
        "candidates": [row for row in results if row["status"] == "candidate"],
        "results": results,
        "note": ("A vulnerable verdict is a dangling delegation, not a claim. "
                 "Confirm ownership before touching the provider, and never "
                 "register a name outside the program's rules."),
    }


def summary() -> dict:
    table = fingerprints()
    return {
        "services": len(table),
        "vulnerable_services": sum(1 for row in table if row.vulnerable),
        "cname_matched_services": sum(1 for row in table if row.cnames),
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "note": "Pinned fingerprint table; a match is a lead, not authorization.",
    }
