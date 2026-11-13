"""Redirect-chain analysis for open redirects and SSRF redirect loops.

An SSRF filter that checks only the first URL is defeated by a redirect: the
server fetches an allowed host, which 302s to the internal target. The same
primitive is an open redirect when the chain leaves to an attacker host. This
module follows a bounded redirect chain by hand (no auto-follow), records every
hop, and classifies the result: open redirect to a canary, a redirect loop, an
external hop, or a same-origin chain.

It reads Location headers. It does not fetch the final URL unless it is still
in scope, so a chain can be analysed without the tool itself becoming the SSRF.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urljoin, quote

DEFAULT_AGENT = "NetCast3r/redirect-chain (+authorized-testing)"
REDIRECT_CODES = (301, 302, 303, 307, 308)
MAX_BODY = 16384


def default_fetch(url: str, timeout: float = 8.0, max_bytes: int = MAX_BODY) -> dict:
    """Fetch one hop without following redirects. Never raises."""
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return {"status": 0, "headers": {}, "body": "", "error": "httpx unavailable"}
    try:
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout,
                          headers={"User-Agent": DEFAULT_AGENT}) as client:
            response = client.get(url)
            return {"status": response.status_code,
                    "headers": {str(k).lower(): str(v)
                                for k, v in response.headers.items()},
                    "body": (response.text or "")[:max_bytes]}
    except Exception as exc:  # httpx raises many transport types
        return {"status": 0, "headers": {}, "body": "", "error": str(exc)[:200]}


def open_redirect_payloads(origin: str, canary: str = "nc3r-canary.invalid") -> list:
    """Values that defeat common ``startswith``/``endswith`` redirect checks."""
    return [
        {"kind": "absolute", "value": f"https://{canary}/"},
        {"kind": "protocol_relative", "value": f"//{canary}/"},
        {"kind": "userinfo", "value": f"https://{origin}@{canary}/"},
        {"kind": "suffix_host", "value": f"https://{origin}.{canary}/"},
        {"kind": "backslash", "value": f"https://{canary}\\@{origin}/"},
        {"kind": "encoded_slash", "value": f"https://{canary}%2f..%2f"},
        {"kind": "at_path", "value": f"/{canary}"},
        {"kind": "double_encode", "value": quote(f"https://{canary}/", safe="")},
    ]


def classify_chain(origin: str, hops: list, canary: str = "") -> dict:
    """Classify a recorded hop list."""
    origin_host = (urlsplit(origin).hostname or "").lower()
    loop = False
    external = []
    canary_hit = ""
    for hop in hops:
        location = hop.get("location") or ""
        if not location:
            continue
        host = (urlsplit(urljoin(hop["url"], location)).hostname or "").lower()
        if canary and canary.lower() in host:
            canary_hit = host
        if host and host != origin_host:
            external.append(host)
    urls = [hop.get("url") for hop in hops]
    if len(urls) != len(set(urls)):
        loop = True
    if canary_hit:
        verdict = "open_redirect"
    elif loop:
        verdict = "redirect_loop"
    elif external:
        verdict = "external_redirect"
    elif hops and hops[-1].get("status") not in REDIRECT_CODES:
        verdict = "same_origin"
    else:
        verdict = "no_redirect"
    return {"verdict": verdict, "loop": loop, "external_hosts": sorted(set(external)),
            "canary_host": canary_hit}


def chain(url: str, fetch=None, max_hops: int = 10, timeout: float = 8.0,
          canary: str = "") -> dict:
    """Follow a redirect chain by hand and classify it."""
    fetch = fetch or (lambda target: default_fetch(target, timeout=timeout))
    current = url
    hops: list = []
    for number in range(1, max(1, int(max_hops)) + 1):
        if any(hop["url"] == current for hop in hops):
            hops.append({"hop": number, "url": current, "status": 0,
                         "location": "", "note": "redirect loop closed"})
            break
        response = fetch(current)
        status = int(response.get("status") or 0)
        location = (response.get("headers") or {}).get("location", "")
        hops.append({"hop": number, "url": current, "status": status,
                     "location": location, "error": response.get("error", "")})
        if status not in REDIRECT_CODES or not location:
            break
        current = urljoin(current, location)
    classified = classify_chain(url, hops, canary=canary)
    return {
        "target": url,
        "hops": hops,
        "hops_followed": len(hops),
        **classified,
        "note": ("A chain that leaves the origin is a lead. For SSRF, confirm "
                 "the server (not this tool) followed the redirect to the "
                 "canary, using the OAST callback as the proof."),
    }


def summary() -> dict:
    return {
        "redirect_codes": list(REDIRECT_CODES),
        "verdicts": ["open_redirect", "redirect_loop", "external_redirect",
                     "same_origin", "no_redirect"],
        "note": "Location-only analysis; the tool does not chase out-of-scope hops.",
    }
