"""Path-variant differential testing.

Authorization and routing layers routinely disagree about a URL: one reads the
raw bytes, the other decodes them. When that happens a request that is refused
on a literal path can reach the same handler through an encoded one. This
module generates a bounded set of path variants and compares the responses so
the difference is visible in one place.

It does not decide that a target is vulnerable. It reports where the baseline
and a variant disagree, and labels the shape of the disagreement for a human or
an agent to confirm.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import quote, urlsplit, urlunsplit

MAX_VARIANTS = 24


def _split(path: str) -> tuple[str, str]:
    """Return (path, query) with a leading slash on the path."""
    path = path or "/"
    if path.startswith("http://") or path.startswith("https://"):
        parts = urlsplit(path)
        path = parts.path or "/"
    if "?" in path:
        path, query = path.split("?", 1)
        return (path if path.startswith("/") else "/" + path), "?" + query
    return (path if path.startswith("/") else "/" + path), ""


def _segments(path: str) -> list[str]:
    return path.split("/")


def _encode_segment(segment: str, positions: list[int] | None = None) -> str:
    encoded = []
    for index, char in enumerate(segment):
        if positions is None or index in positions:
            if char.isalnum() or char in "-._~":
                encoded.append("%" + format(ord(char), "02x"))
            else:
                encoded.append(char)
        else:
            encoded.append(char)
    return "".join(encoded)


def build_variants(path: str, limit: int = MAX_VARIANTS) -> list[dict]:
    """Generate deterministic, de-duplicated path variants in a stable order."""
    clean, query = _split(path)
    parts = _segments(clean)
    variants: list[dict] = [{"label": "baseline", "path": clean + query}]
    seen = {clean}

    def add(label: str, candidate: str, note: str = "") -> None:
        if candidate in seen or len(variants) >= limit:
            return
        seen.add(candidate)
        variants.append({"label": label, "path": candidate + query, "note": note})

    # The last non-empty segment is the one an authorization rule usually keys
    # on (addons, domains, admin), so it gets the most attention.
    last_index = len(parts) - 1
    while last_index > 0 and parts[last_index] == "":
        last_index -= 1
    last = parts[last_index] if 0 <= last_index < len(parts) else ""

    add("trailing_slash", clean.rstrip("/") + "/")
    add("duplicate_slash", clean.replace("/" + last, "//" + last, 1) if last else clean)
    add("uppercase", clean.upper())
    add("mixed_case", "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(clean)))
    add("semicolon_suffix", clean + ";" + (last or "x"))

    if last:
        add("encode_last_first", "/".join(parts[:last_index] + [_encode_segment(last, [0])]))
        add("encode_last_all", "/".join(parts[:last_index] + [_encode_segment(last)]))
        mixed = list(last)
        if len(mixed) >= 2:
            mixed[-1] = "%" + format(ord(mixed[-1]), "02x")
            add("encode_last_tail", "/".join(parts[:last_index] + ["".join(mixed)]))
        add("double_encode_last", "/".join(
            parts[:last_index] + ["%" + format(ord(c), "02x").replace("%", "%25") for c in last[:1]]
            + [last[1:]]))

    # Encode earlier segments too: /api/services -> /%61pi/services.
    for index in range(1, min(last_index, 4)):
        segment = parts[index]
        if not segment:
            continue
        encoded = parts[:]
        encoded[index] = _encode_segment(segment, [0])
        add(f"encode_segment_{index}", "/".join(encoded))

    add("dot_segment", clean.rstrip("/") + "/." if last else clean)
    add("head_uppercase", "/" + clean.lstrip("/").capitalize())
    return variants[:limit]


def _digest(text: str) -> str:
    normal = re.sub(r"\s+", " ", (text or "")).strip().lower()
    return hashlib.sha256(normal.encode("utf-8", "ignore")).hexdigest()[:16]


def _handler_like(body: str, status: int) -> bool:
    """Distinguish a handler's validation error from a generic router refusal."""
    text = (body or "").lower()
    if any(marker in text for marker in (
            "not found", "could not be understood", "not supported", "unknown route",
            "no route", "bad gateway", "service unavailable")):
        return False
    if any(marker in text for marker in (
            "invalid", "required", "validation", "field", "missing", "subscription",
            "already exists", "must be", "cannot be empty")):
        return True
    return status in {400, 422}


def compare(baseline: dict, variants: list[dict]) -> dict:
    """Label each variant relative to the baseline response."""
    base_status = int(baseline.get("status") or 0)
    base_hash = baseline.get("body_hash") or _digest(baseline.get("body", ""))
    baseline.update({"body_hash": base_hash})
    suspicious: list[dict] = []
    rows: list[dict] = []
    for variant in variants:
        if variant.get("label") == "baseline":
            continue
        status = int(variant.get("status") or 0)
        body_hash = variant.get("body_hash") or _digest(variant.get("body", ""))
        if variant.get("error"):
            delta = "request_error"
        elif status == base_status:
            delta = "same_status" if body_hash == base_hash else "body_diff"
        elif base_status in {401, 403} and status < 400:
            delta = "auth_bypass"
        elif base_status in {401, 403} and status in {400, 422}:
            delta = "check_skipped" if _handler_like(variant.get("body", ""), status) else "routing_error"
        elif base_status == 404 and status < 400:
            delta = "route_confusion"
        elif status >= 500:
            delta = "server_error"
        else:
            delta = "status_changed"
        row = {
            "label": variant.get("label"),
            "path": variant.get("path"),
            "status": status,
            "bytes": variant.get("bytes", 0),
            "delta": delta,
            "body_sample": (variant.get("body") or "")[:280],
        }
        rows.append(row)
        if delta in {"auth_bypass", "check_skipped", "route_confusion", "server_error",
                     "body_diff"}:
            suspicious.append(row)

    return {
        "baseline": {
            "status": base_status,
            "bytes": baseline.get("bytes", 0),
            "body_sample": (baseline.get("body") or "")[:280],
        },
        "variants": rows,
        "suspicious": suspicious,
        "summary": {
            "tested": len(rows),
            "suspicious": len(suspicious),
            "deltas": {name: sum(1 for row in rows if row["delta"] == name)
                       for name in sorted({row["delta"] for row in rows})},
        },
        "interpretation": (
            "A 403 baseline that becomes 400 means the authorization check was skipped and "
            "the request reached the handler. A 403/401 that becomes 2xx is a confirmed "
            "bypass. Confirm the response body before recording a finding."
        ),
    }


def target_for(base_url: str, variant_path: str) -> str:
    parts = urlsplit(base_url)
    path, _, _query = variant_path.partition("?")
    query = variant_path[len(path) + 1:] if "?" in variant_path else ""
    return urlunsplit((parts.scheme, parts.netloc, path, query, ""))


def quote_path(path: str) -> str:
    """Conservative quoting for display only; keeps existing escapes intact."""
    return quote(path, safe="/?&=%:@!$'()*+,;~-._[]")
