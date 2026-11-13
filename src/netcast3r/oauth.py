"""OAuth 2.0 / OIDC misconfiguration analysis.

The OAuth bugs that pay are almost never cryptographic. They are trust
transitions: a redirect_uri the server validates by prefix, an implicit flow
that leaks a token in a fragment, a callback with no state binding, a code that
can be replayed. This module reads an authorize URL and a callback URL and
states those weaknesses plainly.

It is static by default. ``probe_redirect`` will, when explicitly enabled,
substitute mutated redirect_uri values and read where the server sends the
browser, which is the one step that touches the target.
"""

from __future__ import annotations

from urllib.parse import (parse_qsl, urlencode, urlsplit, urlunsplit, quote)

CANARY_HOST = "nc3r-canary.invalid"

IMPLICIT_TYPES = ("token", "id_token", "id_token token")
NESTED_REDIRECT_KEYS = ("next", "url", "redirect", "redirect_uri", "continue",
                        "return", "returnUrl", "return_url", "goto", "target")

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _finding(items, ident, severity, title, detail, evidence=""):
    items.append({"id": ident, "severity": severity, "title": title,
                  "detail": detail, "evidence": evidence})


def params(url: str) -> dict:
    """Query parameters of a URL as a flat dict (last value wins)."""
    parts = urlsplit(url if "://" in url else "https://" + url)
    merged = dict(parse_qsl(parts.query, keep_blank_values=True))
    if parts.fragment:
        merged.update(dict(parse_qsl(parts.fragment, keep_blank_values=True)))
    return merged


def _is_localhost(host: str) -> bool:
    host = (host or "").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def analyze_authorize(url: str) -> dict:
    """Static findings for one authorization request."""
    parsed = params(url)
    parts = urlsplit(url if "://" in url else "https://" + url)
    response_type = str(parsed.get("response_type") or "").lower()
    redirect_uri = str(parsed.get("redirect_uri") or "")
    scope = str(parsed.get("scope") or "")
    findings: list = []

    if not parsed.get("client_id"):
        _finding(findings, "missing_client_id", "info", "No client_id",
                 "The authorize request carries no client_id.")
    if "token" in response_type.split():
        _finding(findings, "implicit_flow", "high", "Implicit flow in use",
                 "response_type returns a token directly to the browser "
                 "fragment, where it can be read by scripts and history.",
                 response_type)
    if not parsed.get("state"):
        _finding(findings, "missing_state", "medium", "No state parameter",
                 "Without state the callback is not bound to the user agent, "
                 "which enables login CSRF and callback replay.")
    if "code" in response_type.split() and not parsed.get("code_challenge"):
        _finding(findings, "missing_pkce", "low", "No PKCE on a code flow",
                 "A public client without code_challenge can have its code "
                 "intercepted and exchanged.")
    if "openid" in scope.split() and not parsed.get("nonce"):
        _finding(findings, "missing_nonce", "low", "OIDC without nonce",
                 "An id_token issued without nonce can be replayed between "
                 "clients.")

    if not redirect_uri:
        _finding(findings, "missing_redirect_uri", "low", "No redirect_uri",
                 "The server will fall back to a registered redirect; confirm "
                 "it is not an open redirect.")
    else:
        rp = urlsplit(redirect_uri)
        host = (rp.hostname or "").lower()
        if rp.scheme == "http" and not _is_localhost(host):
            _finding(findings, "insecure_redirect_uri", "medium",
                     "redirect_uri is plain HTTP",
                     "A code or token can be read on the wire.", redirect_uri)
        if "@" in (rp.netloc or ""):
            _finding(findings, "userinfo_redirect_uri", "high",
                     "redirect_uri carries userinfo",
                     "A host like app.example@evil.example is parsed as "
                     "evil.example by many validators.", redirect_uri)
        if "*" in redirect_uri:
            _finding(findings, "wildcard_redirect_uri", "high",
                     "redirect_uri contains a wildcard", redirect_uri)
        if rp.fragment:
            _finding(findings, "fragment_redirect_uri", "medium",
                     "redirect_uri has a fragment",
                     "Fragments are not validated by prefix checks and can "
                     "smuggle a second URL.", redirect_uri)
        nested = [key for key in NESTED_REDIRECT_KEYS
                  if key in dict(parse_qsl(rp.query))]
        if nested:
            _finding(findings, "nested_redirect", "medium",
                     "redirect_uri embeds another URL parameter",
                     "If the embedded target is an open redirect, the code can "
                     "be forwarded again.", ", ".join(nested))
        if ".." in rp.path:
            _finding(findings, "traversal_redirect_uri", "medium",
                     "redirect_uri contains a traversal segment", redirect_uri)

    return {
        "authorize_endpoint": urlunsplit((parts.scheme, parts.netloc, parts.path,
                                          "", "")),
        "params": {key: ("***" if key in ("client_secret", "code") else value)
                   for key, value in parsed.items()},
        "findings": sorted(findings,
                           key=lambda row: SEVERITY_ORDER.get(row["severity"], 9)),
    }


def redirect_uri_mutations(redirect_uri: str, canary: str = CANARY_HOST) -> list:
    """Candidate redirect_uri values that defeat prefix and suffix checks."""
    rp = urlsplit(redirect_uri if "://" in redirect_uri else "https://" + redirect_uri)
    scheme, host, path = rp.scheme or "https", rp.hostname or "", rp.path or ""
    port = f":{rp.port}" if rp.port else ""
    out = []

    def add(kind, value):
        if value not in [row["value"] for row in out]:
            out.append({"kind": kind, "value": value})

    add("suffix_host", f"{scheme}://{host}.{canary}{port}{path}")
    add("prefix_host", f"{scheme}://{canary}.{host}{port}{path}")
    add("userinfo", f"{scheme}://{host}@{canary}{port}{path}")
    add("append_path", f"{scheme}://{host}{port}{path}/../{canary}")
    add("nested_param", f"{scheme}://{host}{port}{path}?next={scheme}://{canary}/")
    add("fragment", f"{scheme}://{host}{port}{path}#@{canary}")
    if scheme == "https":
        add("downgrade", f"http://{host}{port}{path}")
    add("encoded_slash", f"{scheme}://{host}{port}{path}%2f..%2f{canary}")
    return out


def _set_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != key]
    query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, quote_via=quote), parts.fragment))


def probe_redirect(authorize_url: str, fetch=None, canary: str = CANARY_HOST,
                   redirect_uri: str = "", timeout: float = 8.0,
                   mutations=None) -> dict:
    """Send mutated redirect_uri values and read where the server redirects."""
    from . import cache

    fetch = fetch or (lambda url, headers: cache.default_fetch(url, headers,
                                                               timeout=timeout))
    current = redirect_uri or str(params(authorize_url).get("redirect_uri") or "")
    rows = []
    for row in (mutations or redirect_uri_mutations(current, canary)):
        url = _set_param(authorize_url, "redirect_uri", row["value"])
        response = fetch(url, {})
        location = ""
        headers = {str(k).lower(): str(v)
                   for k, v in (response.get("headers") or {}).items()}
        location = headers.get("location", "")
        accepted = canary in location
        rows.append({"kind": row["kind"], "mutation": row["value"],
                     "location": location, "accepted": accepted,
                     "http_status": response.get("status"),
                     "error": response.get("error", "")})
    hits = [row for row in rows if row["accepted"]]
    return {
        "authorize_endpoint": authorize_url,
        "tested": len(rows),
        "accepted": hits,
        "results": rows,
        "note": ("An accepted mutation means the server followed the redirect "
                 "to the canary host. Confirm a code or token was actually "
                 "delivered before reporting."),
    }


def analyze_callback(url: str) -> dict:
    """Static findings for one OAuth redirect callback."""
    parsed = params(url)
    parts = urlsplit(url if "://" in url else "https://" + url)
    findings: list = []
    if "access_token" in parsed or "id_token" in parsed:
        _finding(findings, "token_in_url", "high", "Token delivered in the URL",
                 "A token in the query or fragment leaks through history, "
                 "referrer, and logs.", ", ".join(
                     key for key in ("access_token", "id_token") if key in parsed))
    if parts.fragment and ("access_token" in parts.fragment or "code" in parts.fragment):
        _finding(findings, "token_in_fragment", "high",
                 "Token or code in the fragment",
                 "Fragment data is readable by any script on the page.")
    if parsed.get("code") and not parsed.get("state"):
        _finding(findings, "code_without_state", "medium",
                 "Callback code with no state",
                 "The callback is not bound to the initiating session.")
    return {
        "callback": urlunsplit((parts.scheme, parts.netloc, parts.path,
                                parts.query, "")),
        "findings": sorted(findings,
                           key=lambda row: SEVERITY_ORDER.get(row["severity"], 9)),
    }


def audit(url: str, business=None, fetch=None, probe: bool = False,
          timeout: float = 8.0) -> dict:
    """Analyze an authorize URL, a callback URL, or return guidance."""
    looks_authorize = "authorize" in (url or "") or "response_type=" in (url or "")
    looks_callback = ("callback" in (url or "") or "access_token=" in (url or "")
                      or "code=" in (url or ""))
    if looks_callback and not looks_authorize:
        return {"kind": "callback", **analyze_callback(url)}
    if not looks_authorize:
        return {"kind": "unknown", "findings": [],
                "note": ("Pass the OAuth authorize URL (contains /authorize or "
                         "response_type=) or the redirect callback URL.")}
    result = {"kind": "authorize", **analyze_authorize(url)}
    result["mutations"] = redirect_uri_mutations(
        str(params(url).get("redirect_uri") or ""))
    if probe:
        result["probe"] = probe_redirect(url, fetch=fetch, timeout=timeout)
    result.setdefault("note", ("Static OAuth analysis. Enable probe to test "
                               "redirect_uri handling against the live server."))
    return result


def summary() -> dict:
    return {
        "checks": ["implicit_flow", "missing_state", "missing_pkce",
                   "missing_nonce", "redirect_uri_validation",
                   "nested_redirect", "token_in_url", "code_reuse"],
        "probe_default": False,
        "note": "Static by default; redirect probing is opt-in and scope-gated.",
    }
