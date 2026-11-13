"""Web cache deception and cache poisoning.

Two distinct bugs share a cache:

- **Deception** tricks the cache into storing a private page under a
  static-looking path, so a later anonymous request reads someone else's page.
  The tell is a dynamic response that becomes cached when a file extension or
  path suffix is appended.
- **Poisoning** feeds an unkeyed header that the origin reflects into a cached
  response, so the poisoned copy is served to everyone.

Both checks are response-header and reflection analysis. They read; they never
plant a payload beyond an inert canary, and a hit is a lead to confirm against
the origin's cache rules.
"""

from __future__ import annotations

import hashlib
import os
from urllib.parse import urlsplit, urlunsplit

DEFAULT_AGENT = "NetCast3r/cache-audit (+authorized-testing)"
MAX_BODY = 65536

CACHE_STATE_HEADERS = (
    "x-cache", "cf-cache-status", "x-served-by", "x-cache-hits", "x-varnish",
    "x-fastly-request-id", "x-proxy-cache", "x-cacheable", "x-cache-status",
    "cdn-cache-control", "x-cdn", "akamai-cache-status", "x-akamai-transformed",
)

UNKEYED_HEADERS = (
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Server",
    "X-Forwarded-Port", "X-Host", "X-Original-URL", "X-Rewrite-URL",
    "X-Forwarded-For", "Forwarded",
)
HOST_LIKE = {"X-Forwarded-Host", "X-Forwarded-Server", "X-Host", "Forwarded"}

DECEPTION_SUFFIXES = (
    "/nonexistent.css", "/nonexistent.js", "/nonexistent.ico",
    "/nonexistent.svg", "/nonexistent.woff", "/x;.css", "/x%2f.css",
    "/.css", "/..%2f..%2fstatic.css", "/x.json",
)


def _lower(headers) -> dict:
    return {str(key).lower(): str(value) for key, value in (headers or {}).items()}


def cache_status(headers) -> dict:
    """Read the cache-relevant state out of a response header set."""
    low = _lower(headers)
    control = low.get("cache-control", "").lower()
    age = low.get("age", "")
    state = " ".join(low.get(name, "") for name in CACHE_STATE_HEADERS).lower()
    hits = low.get("x-cache-hits", "")
    cached = (
        (age.isdigit() and int(age) > 0)
        or "hit" in state
        or (hits.isdigit() and int(hits) > 0)
    )
    store_ok = "no-store" not in control and "private" not in control
    cacheable = store_ok or "public" in control
    return {
        "cached": bool(cached),
        "cacheable": bool(cacheable),
        "public": "public" in control,
        "no_store": "no-store" in control,
        "private": "private" in control,
        "age": age,
        "vary": low.get("vary", ""),
        "evidence": (", ".join(f"{name}={low[name]}" for name in CACHE_STATE_HEADERS
                               if name in low) or low.get("cache-control", "")),
    }


def _body_hash(response: dict) -> str:
    body = response.get("body") or ""
    return hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:20]


def _join(base_url: str, suffix: str) -> str:
    parts = urlsplit(base_url)
    path = parts.path
    if suffix.startswith("?"):
        return urlunsplit((parts.scheme, parts.netloc, path, suffix[1:], ""))
    return urlunsplit((parts.scheme, parts.netloc, path.rstrip("/") + suffix, "", ""))


def default_fetch(url: str, headers: dict, timeout: float = 8.0,
                  max_bytes: int = MAX_BODY) -> dict:
    """Fetch a URL and return status, capped body, and headers. Never raises."""
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return {"status": 0, "body": "", "headers": {}, "error": "httpx unavailable"}
    request_headers = {"User-Agent": DEFAULT_AGENT, "Cache-Control": "no-cache"}
    request_headers.update(headers or {})
    try:
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout,
                          headers=request_headers) as client:
            response = client.get(url)
            return {"status": response.status_code,
                    "body": (response.text or "")[:max_bytes],
                    "headers": dict(response.headers)}
    except Exception as exc:  # httpx raises many transport types
        return {"status": 0, "body": "", "headers": {}, "error": str(exc)[:200]}


def deception(base_url: str, variants=None, fetch=None, timeout: float = 8.0) -> dict:
    """Probe static-looking suffixes for cached private content."""
    fetch = fetch or (lambda url, headers: default_fetch(url, headers,
                                                         timeout=timeout))
    base = fetch(base_url, {"Cache-Control": "no-cache"})
    base_hash = _body_hash(base) if base.get("body") else ""
    base_state = cache_status(base.get("headers"))
    rows = []
    for suffix in (variants or DECEPTION_SUFFIXES):
        url = _join(base_url, suffix)
        first = fetch(url, {})
        second = fetch(url, {})
        state = cache_status(second.get("headers"))
        body = second.get("body") or ""
        same_page = bool(body) and bool(base_hash) and _body_hash(second) == base_hash
        if state["cached"] and same_page:
            verdict = "cache_deception"
        elif state["cacheable"] and same_page and not base_state["cacheable"]:
            verdict = "cacheable_private"
        elif state["cached"]:
            verdict = "cached_other"
        else:
            verdict = "not_cached"
        rows.append({
            "suffix": suffix, "url": url, "verdict": verdict,
            "http_status": second.get("status"),
            "cache": state, "same_as_base": same_page,
            "error": second.get("error", ""),
        })
    hits = [row for row in rows if row["verdict"] == "cache_deception"]
    return {
        "target": base_url,
        "baseline": {"status": base.get("status"), "cache": base_state,
                     "error": base.get("error", "")},
        "results": rows,
        "deception": hits,
        "counts": _counts(rows),
        "note": ("A deception lead needs a second, anonymous read to confirm the "
                 "cache served the private page. Keep the canary path inert."),
    }


def _counts(rows) -> dict:
    counts: dict = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    return counts


def _canary(header: str) -> str:
    token = "nc3r" + os.urandom(4).hex()
    return f"{token}.canary.invalid" if header in HOST_LIKE else token


def poisoning(base_url: str, headers=None, fetch=None, timeout: float = 8.0) -> dict:
    """Check whether an unkeyed header is reflected into a cacheable response."""
    fetch = fetch or (lambda url, hdrs: default_fetch(url, hdrs, timeout=timeout))
    candidates = tuple(headers or UNKEYED_HEADERS)
    baseline = fetch(base_url, {"Cache-Control": "no-cache"})
    base_hash = _body_hash(baseline)
    rows = []
    for header in candidates:
        canary = _canary(header)
        first = fetch(base_url, {header: canary})
        body = first.get("body") or ""
        resp_headers = _lower(first.get("headers"))
        reflected_body = canary in body
        echoed = any(canary in value for value in resp_headers.values())
        state = cache_status(first.get("headers"))
        # Re-request without the header: a poisoned cache replays the canary.
        replay = fetch(base_url, {"Cache-Control": "no-cache"})
        replay_body = replay.get("body") or ""
        poisoned = canary in replay_body or any(
            canary in value for value in _lower(replay.get("headers")).values())
        if poisoned:
            verdict = "poisoned"
        elif reflected_body or echoed:
            verdict = "reflected"
        elif state["cacheable"] and _body_hash(first) == base_hash:
            verdict = "cacheable_no_echo"
        else:
            verdict = "ignored"
        rows.append({
            "header": header, "canary": canary, "verdict": verdict,
            "reflected_body": reflected_body, "echoed_header": echoed,
            "cache": state,
            "delta_len": len(body) - len(baseline.get("body") or ""),
            "evidence": _snippet(body, canary),
            "error": first.get("error", ""),
        })
    hits = [row for row in rows if row["verdict"] == "poisoned"]
    return {
        "target": base_url,
        "cache_headers": {"baseline": cache_status(baseline.get("headers"))},
        "results": rows,
        "poisoned": hits,
        "counts": _counts(rows),
        "note": ("Use a unique cache buster so a poison test never touches a "
                 "shared entry. A reflection alone is not poisoning."),
    }


def _snippet(body: str, needle: str, width: int = 160) -> str:
    index = body.lower().find(needle.lower())
    if index < 0:
        return ""
    start = max(0, index - width // 3)
    return body[start:start + width]


def audit(base_url: str, mode: str = "both", headers=None, fetch=None,
          timeout: float = 8.0) -> dict:
    """Run deception, poisoning, or both against one in-scope URL."""
    result = {"target": base_url, "mode": mode}
    if mode in ("both", "deception", "deceive"):
        result["deception"] = deception(base_url, fetch=fetch, timeout=timeout)
    if mode in ("both", "poisoning", "poison"):
        result["poisoning"] = poisoning(base_url, headers=headers, fetch=fetch,
                                        timeout=timeout)
    result["note"] = ("Cache checks read responses and plant inert canaries "
                      "only. Confirm the origin's cache key before reporting.")
    return result
