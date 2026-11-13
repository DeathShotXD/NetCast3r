"""Lead taxonomy and dedupe.

An autonomous hunt re-tests the same thing: the same parameter, the same class,
across two runs or two roles. This module gives every lead a stable signature so
duplicates collapse and the loop spends its budget on something new.

A signature is ``host | normalized path | parameter | class``. Object ids and
hex/uuid segments collapse to ``{id}`` so ``/users/1`` and ``/users/2`` group,
and the class comes from an explicit label or a keyword read of the title and
technique.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

CLASSES = (
    ("sql", ("sql injection", "sqli", "sql syntax", "union select", "database error")),
    ("xss", ("xss", "cross-site scripting", "reflected", "stored", "dom")),
    ("ssrf", ("ssrf", "server-side request", "callback", "out-of-band")),
    ("idor", ("idor", "bola", "object reference", "cross-account", "broken object")),
    ("ssti", ("ssti", "template injection")),
    ("xxe", ("xxe", "xml external")),
    ("lfi", ("lfi", "local file", "file read", "path traversal", "directory traversal")),
    ("upload", ("upload", "multipart", "file type")),
    ("crlf", ("crlf", "header injection", "response splitting")),
    ("race", ("race condition", "single packet", "last byte", "check-then-act")),
    ("cache", ("cache poisoning", "cache deception", "web cache", "unkeyed")),
    ("oauth", ("oauth", "oidc", "openid", "redirect_uri", "implicit flow")),
    ("saml", ("saml", "assertion", "xsw")),
    ("jwt", ("jwt", "json web token", "alg confusion", "kid")),
    ("graphql", ("graphql", "introspection", "resolver")),
    ("websocket", ("websocket", "cswsh", "socket.io")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("cors", ("cors", "access-control-allow-origin")),
    ("open_redirect", ("open redirect", "redirect parameter")),
    ("redirect", ("redirect",)),
    ("takeover", ("takeover", "dangling cname", "unclaimed", "subdomain")),
    ("mail", ("spf", "dmarc", "dkim", "zone transfer", "axfr")),
    ("vhost", ("vhost", "virtual host")),
    ("misconfig", ("security header", "tls", "cookie flag", "cors", "configuration")),
    ("info", ("information disclosure", "endpoint", "fingerprint")),
)

PARAM_RE = re.compile(r"\bparam(?:eter)?s?\s+([A-Za-z0-9_.\[\]-]+)", re.IGNORECASE)
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-f]{8,}|\{?[0-9a-f-]{36}\}?)$", re.IGNORECASE)


def classify(text: str) -> str:
    """Map a title or technique to a coarse class."""
    low = str(text or "").lower()
    for klass, needles in CLASSES:
        if any(needle in low for needle in needles):
            return klass
    return "unknown"


def _host_of(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw if "://" in raw else "https://" + raw.lstrip("/"))
    return (parts.hostname or "").lower()


def normalize_path(target: str) -> str:
    """Lowercase the host, keep the path, and collapse object ids to {id}."""
    raw = str(target or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw if "://" in raw else "https://" + raw.lstrip("/"))
    segments = [seg for seg in (parts.path or "/").split("/") if seg != ""]
    out = []
    for segment in segments:
        out.append("{id}" if _ID_SEGMENT.match(segment) else segment.lower())
    path = "/" + "/".join(out)
    return path or "/"


def _param(title: str, target: str) -> str:
    match = PARAM_RE.search(str(title or ""))
    if match:
        return match.group(1).lower()
    raw = str(target or "")
    if "?" in raw:
        keys = [key for key, _ in parse_qsl(urlsplit(raw).query, keep_blank_values=True)]
        if keys:
            return ",".join(sorted(keys)).lower()
    return ""


def signature(title: str = "", target: str = "", technique: str = "",
              klass: str = "") -> str:
    """A stable dedupe key for one lead."""
    group = (klass or classify(f"{title} {technique}")).lower()
    return "|".join([_host_of(target), normalize_path(target),
                     _param(title, target), group])


def signature_of(item: dict) -> str:
    return signature(str(item.get("title") or ""),
                     str(item.get("target") or ""),
                     str(item.get("technique") or ""),
                     str(item.get("class") or item.get("klass") or ""))


def dedupe(items, key=None) -> dict:
    """Group leads by signature; the first in each group is the keeper."""
    groups: dict = {}
    order: list = []
    for item in items or []:
        sig = key(item) if callable(key) else signature_of(item)
        if sig not in groups:
            groups[sig] = []
            order.append(sig)
        groups[sig].append(item)
    unique = [groups[sig][0] for sig in order]
    duplicates = [item for sig in order for item in groups[sig][1:]]
    return {
        "total": len(list(items or [])),
        "unique": len(unique),
        "duplicate_count": len(duplicates),
        "groups": [
            {"signature": sig, "count": len(groups[sig]),
             "titles": [str(item.get("title") or "") for item in groups[sig]],
             "ids": [item.get("id") for item in groups[sig] if item.get("id")]}
            for sig in order if len(groups[sig]) > 1
        ],
        "note": ("Leads that share a signature test the same thing; keep the "
                 "earliest and fold the rest into it."),
    }


def summary() -> dict:
    return {
        "classes": [klass for klass, _ in CLASSES],
        "note": "Signature = host | path | parameter | class; ids collapse to {id}.",
    }
