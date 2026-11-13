"""ORM leak probes.

When a developer lets the user control a filter *field* or a full filter
expression, an ORM will happily filter on sensitive attributes. The response
then differs: an error names the field, a length changes, or a query slows
down. This module builds those filter-expression probes (Django, Beego,
Prisma, OData/Entity Framework) and reads the differential.

It is detection, not extraction: a lead says one field is filterable. Pulling
the value out stays with ``oracle_extract``.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_AGENT = "NetCast3r/orm-leak (+authorized-testing)"
MAX_BODY = 131072

DJANGO_OPERATORS = ("contains", "icontains", "startswith", "endswith", "regex",
                    "iexact", "exact", "gt", "gte", "lt", "lte", "isnull")
PRISMA_OPERATORS = ("contains", "startsWith", "endsWith", "equals")
ODATA_OPERATORS = ("eq", "ne", "gt", "ge", "lt", "le", "contains")
RELATIONAL = ("{field}__user__username", "{field}__created_by__username",
              "{field}__owner__email", "{field}__user__email",
              "{field}__account__name")

ERROR_MARKERS = (
    "fielderror", "does not exist", "invalid field", "not a valid",
    "unknown field", "cannot resolve", "operator does not exist",
    "prisma", "django", "beego", "sqlalchemy", "odata", "validation failed",
    "invalid lookup", "unrecognized", "no such column",
)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def payloads(field: str) -> list:
    """Filter-expression probes for one user-controlled field name."""
    field = str(field or "").strip()
    out: list = []
    seen: set = set()

    def add(kind, params: dict):
        key = (kind, tuple(sorted(params.items())))
        if key in seen:
            return
        seen.add(key)
        out.append({"kind": kind, "params": params})

    for op in DJANGO_OPERATORS:
        value = "" if op == "isnull" else "nc3r"
        add("django", {f"{field}__{op}": value})
    for template in RELATIONAL:
        add("relational", {template.format(field=field) + "__contains": "nc3r"})
    for op in PRISMA_OPERATORS:
        add("prisma", {f"{field}[{op}]": "nc3r"})
    for op in ODATA_OPERATORS:
        add("odata", {"$filter": f"{field} {op} 'nc3r'"})
    add("odata", {"$orderby": field})
    add("odata", {"$select": field})
    add("nested", {f"{field}[]": "nc3r"})
    return out


def _set_params(url: str, extra: dict) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update({str(key): str(value) for key, value in extra.items()})
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query), parts.fragment))


def default_fetch(url: str, timeout: float = 8.0,
                  max_bytes: int = MAX_BODY) -> dict:
    """Fetch a URL and return status, capped body, and headers. Never raises."""
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return {"status": 0, "body": "", "headers": {}, "error": "httpx unavailable"}
    try:
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout,
                          headers={"User-Agent": DEFAULT_AGENT}) as client:
            response = client.get(url)
            return {"status": response.status_code,
                    "body": (response.text or "")[:max_bytes],
                    "headers": dict(response.headers)}
    except Exception as exc:  # httpx raises many transport types
        return {"status": 0, "body": "", "headers": {}, "error": str(exc)[:200]}


def _classify(response: dict, baseline_len: int, length_delta: int) -> tuple[str, str]:
    status = int(response.get("status") or 0)
    body = str(response.get("body") or "")
    low = body.lower()
    for marker in ERROR_MARKERS:
        if marker in low:
            return "error_leak", marker
    if status >= 500:
        return "error_leak", f"HTTP {status}"
    if status and abs(len(body) - baseline_len) >= length_delta:
        return "length_signal", f"length {len(body)} vs {baseline_len}"
    return "no_signal", ""


def probe(base_url: str, field: str, fetch=None, payload_list=None,
          timeout: float = 8.0, length_delta: int = 8) -> dict:
    """Send filter-expression probes and classify the differential."""
    fetch = fetch or (lambda url: default_fetch(url, timeout=timeout))
    baseline = fetch(base_url)
    baseline_len = len(str(baseline.get("body") or ""))
    rows = []
    for item in (payload_list if payload_list is not None else payloads(field)):
        url = _set_params(base_url, item["params"])
        response = fetch(url)
        verdict, evidence = _classify(response, baseline_len, length_delta)
        rows.append({
            "kind": item["kind"], "params": item["params"], "url": url,
            "verdict": verdict, "evidence": evidence,
            "http_status": response.get("status"),
            "body_len": len(str(response.get("body") or "")),
            "error": response.get("error", ""),
        })
    leaks = [row for row in rows if row["verdict"] != "no_signal"]
    return {
        "target": base_url,
        "field": field,
        "baseline": {"status": baseline.get("status"), "body_len": baseline_len,
                     "error": baseline.get("error", "")},
        "results": rows,
        "leads": leaks,
        "counts": _counts(rows),
        "note": ("A lead means one filter expression changed the response. It "
                 "is not a value; use oracle_extract to pull the value out, and "
                 "only against the mission scope."),
    }


def _counts(rows) -> dict:
    counts: dict = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    return counts


def findings(result: dict) -> list:
    """Turn probe output into ranked findings."""
    out = []
    for row in result.get("leads", []):
        out.append({
            "id": "orm_leak",
            "severity": "high" if row["verdict"] == "error_leak" else "medium",
            "title": "Filter expression reaches the ORM",
            "detail": f"{row['kind']} expression changed the response",
            "evidence": f"{row['params']} -> {row['evidence']}",
        })
    return sorted(out, key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))


def summary() -> dict:
    return {
        "operators": {"django": len(DJANGO_OPERATORS),
                      "prisma": len(PRISMA_OPERATORS),
                      "odata": len(ODATA_OPERATORS)},
        "oracles": ["error", "length"],
        "note": "Detection only; extraction reuses oracle_extract.",
    }
