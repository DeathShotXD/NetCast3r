"""Evidence verdicts.

A recorded probe is not a verdict. The Instant Gaming SSRF lead is the reason
this module exists: six metadata requests returned a Cloudflare 403 with no
callback, yet the run log called one of them "supports" because a *different*
request produced a 301.

This module reads what was actually recorded -- status, headers, body sample,
redirect target, transport error -- and labels each probe. It only says a
technique is proven when the response itself carries the proof. Everything else
is named: edge-blocked, redirect-only, reflected-only, inconclusive, untested.

It never writes a finding, changes a hypothesis status, or changes coverage.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

# A metadata service answers with a document, not a challenge page. These are
# strings that only appear in a real IMDS body.
METADATA_MARKERS = {
    "aws": ("ami-id", "instance-id", "iam/security-credentials",
            "security-credentials/", "accesskeyid", "secretaccesskey",
            "instance-identity/document", "placement/availability-zone"),
    "gcp": ("computemetadata", "metadata-flavor", "service-accounts/default/token",
            "project/project-id", "instance/service-accounts"),
    "azure": ("msi/token", "instance/metadata/instance", "x-ms-azure"),
    # A file-read SSRF proves itself too.
    "file": ("root:x:0:0", "daemon:x:", "[fonts]", "/bin/bash"),
}

EDGE_BODY_MARKERS = ("just a moment", "attention required", "cf-chl",
                     "enable javascript and cookies", "error 1020",
                     "access denied", "request blocked", "captcha",
                     "web application firewall")

EDGE_HEADER_MARKERS = ("cf-ray", "cf-cache-status", "x-sucuri-id",
                       "x-akamai-transformed", "x-iinfo", "x-cdn")

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
BLOCK_STATUSES = {401, 403, 406, 429, 451, 503}

# Only an HTTP-shaped tool can be an SSRF or redirect probe. A knowledge-base
# search that happens to mention "ssrf" is not a request to the target.
PROBE_TOOL_PREFIXES = ("http", "oracle", "race", "single_packet", "last_byte",
                       "upload")

MAX_BODY_SCAN = 40000


def _is_probe(call: dict) -> bool:
    tool = str(call.get("tool") or "")
    return tool.startswith(PROBE_TOOL_PREFIXES)


def _host(url: str) -> str:
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return ""
    return (parts.hostname or "").lower()


def _result(call: dict) -> dict:
    value = call.get("result")
    return value if isinstance(value, dict) else {}


def _args(call: dict) -> dict:
    value = call.get("args")
    return value if isinstance(value, dict) else {}


def _body(result: dict) -> str:
    for key in ("body_sample", "body"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value[:MAX_BODY_SCAN]
    return ""


def _metadata_marker(body: str) -> str:
    lowered = body.lower()
    for provider, markers in METADATA_MARKERS.items():
        for marker in markers:
            if marker in lowered:
                return f"{provider}:{marker}"
    return ""


def _edge_block(result: dict, body: str) -> str:
    headers = result.get("headers")
    headers = {str(key).lower(): str(value).lower()
               for key, value in headers.items()} if isinstance(headers, dict) else {}
    for marker in EDGE_HEADER_MARKERS:
        if marker in headers:
            return marker
    server = headers.get("server", "")
    if "cloudflare" in server or "sucuri" in server or "akamai" in server:
        return f"server:{server[:40]}"
    if str(result.get("status") or "") in {str(item) for item in BLOCK_STATUSES}:
        lowered = body.lower()
        for marker in EDGE_BODY_MARKERS:
            if marker in lowered:
                return marker
    return ""


def _location(result: dict) -> str:
    headers = result.get("headers")
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == "location":
            return str(value)
    return ""


def _int(value) -> int:
    """Coerce a recorded status. A failed call stores the string ``error``."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def probe_signals(result: dict) -> dict:
    """Derive the proof-bearing facts before the body is redacted.

    The audit store never keeps a response body: it can hold another user's
    data or a credential. But a verdict needs to know whether the body was a
    metadata document or a WAF challenge. This small, non-secret digest is
    stored next to the redacted result and read back by the classifier.
    """
    body = _body(result)
    headers = result.get("headers")
    headers = headers if isinstance(headers, dict) else {}
    return {
        "metadata_marker": _metadata_marker(body)[:120],
        "edge_marker": _edge_block(result, body)[:120],
        "location": _location(result)[:400],
        "body_sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
        "body_len": len(body),
        "server": str(headers.get("server") or headers.get("Server") or "")[:80],
    }


def _probe(call: dict) -> dict:
    result = _result(call)
    args = _args(call)
    target = str(args.get("target") or result.get("url") or "")
    body = _body(result)
    status = _int(result.get("status"))
    signals = result.get("signals")
    signals = signals if isinstance(signals, dict) else {}
    location = str(signals.get("location") or "") or _location(result)
    outcome = "other"
    detail = ""

    marker = str(signals.get("metadata_marker") or "") or _metadata_marker(body)
    edge = str(signals.get("edge_marker") or "") or _edge_block(result, body)
    if marker:
        outcome, detail = "metadata-response", marker
    elif edge:
        outcome, detail = "edge-block", edge
    elif status in BLOCK_STATUSES:
        # A refusal is a refusal. Without a CDN header or challenge body the
        # harness cannot claim which layer refused it, so say that plainly.
        outcome, detail = "blocked-response", f"HTTP {status}"
    elif status in REDIRECT_STATUSES and location:
        location_host = _host(location)
        target_host = _host(target)
        if location_host in {"169.254.169.254", "metadata.google.internal",
                             "metadata.goog", "100.100.100.200"}:
            outcome, detail = "metadata-redirect", location[:200]
        elif location_host and target_host and location_host != target_host:
            outcome, detail = "external-redirect", location[:200]
        else:
            outcome, detail = "internal-redirect", location[:200]
    elif call.get("status") == "error" or result.get("error"):
        outcome, detail = "transport-error", str(call.get("error") or "")[:200]
    elif 200 <= status < 300:
        outcome, detail = "body-returned", ""
    elif status:
        outcome = "http-error"

    return {
        "at": str(call.get("created_at") or ""),
        "tool": str(call.get("tool") or ""),
        "target": target[:400],
        "status": status,
        "outcome": outcome,
        "detail": detail,
    }


def _summary(counts: dict) -> str:
    return ", ".join(f"{name}={value}" for name, value in sorted(counts.items())
                     if value)


def _base(technique: str) -> dict:
    return {
        "technique": technique,
        "verdict": "untested",
        "proves_technique": False,
        "summary": "No probe for this technique is recorded.",
        "counts": {},
        "probes": [],
        "next_step": "Run one controlled request and record the raw response.",
        "note": ("A verdict is read from recorded responses. It is not a "
                 "finding and it does not change the hypothesis."),
    }


def classify_ssrf(call_rows: list[dict]) -> dict:
    """Label every recorded SSRF probe and aggregate one honest verdict."""
    out = _base("ssrf")
    probes = [_probe(call) for call in call_rows if _is_probe(call)]
    counts: dict[str, int] = {}
    for probe in probes:
        counts[probe["outcome"]] = counts.get(probe["outcome"], 0) + 1
    out["probes"] = probes[-40:]
    out["counts"] = counts
    out["summary"] = _summary(counts) or "No probe for this technique is recorded."

    if counts.get("metadata-response"):
        out.update({
            "verdict": "supported",
            "proves_technique": True,
            "summary": ("A recorded body contains a cloud metadata document "
                        f"({_summary(counts)})."),
            "next_step": ("Keep the raw request and the metadata body, name the "
                          "identity returned, and make one read-only call to "
                          "prove the credential works."),
        })
        return out
    if counts.get("external-redirect") or counts.get("metadata-redirect"):
        out.update({
            "verdict": "redirect-only",
            "proves_technique": False,
            "related_technique": "open-redirect",
            "summary": ("The target answered with a redirect to an external or "
                        f"metadata host ({_summary(counts)}). That is an open "
                        "redirect, not server-side fetching."),
            "next_step": ("Report or chain the open redirect on its own. An SSRF "
                          "needs a server-side fetch: an OAST callback or a "
                          "metadata body."),
        })
        return out
    if counts.get("edge-block") and not counts.get("body-returned"):
        out.update({
            "verdict": "edge-blocked",
            "proves_technique": False,
            "summary": ("Every probe was stopped by an edge control "
                        f"({_summary(counts)}). The application never saw the "
                        "payload."),
            "next_step": ("Mark the coverage item blocked, not vulnerable. Retry "
                          "only through a permitted egress or a mapped URL sink "
                          "that reaches the application."),
        })
        return out
    if counts.get("blocked-response") and not (counts.get("body-returned")
                                              or counts.get("http-error")):
        out.update({
            "verdict": "blocked",
            "proves_technique": False,
            "summary": ("Every probe was refused before returning data "
                        f"({_summary(counts)}). The harness cannot tell from the "
                        "stored response whether the edge or the application "
                        "refused it."),
            "next_step": ("A refusal is not a negative result. Find a sink that "
                          "reaches the application directly, then record the raw "
                          "response with its headers and body digest."),
        })
        return out
    if counts.get("transport-error") and not (counts.get("body-returned")
                                              or counts.get("http-error")):
        out.update({
            "verdict": "inconclusive",
            "summary": f"Probes failed before a response ({_summary(counts)}).",
            "next_step": ("Resolve the transport error first; a timeout is not a "
                          "negative result."),
        })
        return out
    if counts:
        out.update({
            "verdict": "inconclusive",
            "summary": f"Responses were recorded but none proves a fetch ({_summary(counts)}).",
            "next_step": ("Find a parameter that makes the server fetch a URL you "
                          "control, or use an OAST host and poll for the callback."),
        })
    return out


def classify_open_redirect(call_rows: list[dict]) -> dict:
    """Label recorded redirect probes. Proof is the Location header itself."""
    out = _base("open-redirect")
    probes = [_probe(call) for call in call_rows
              if _is_probe(call) and _args(call).get("target")]
    counts: dict[str, int] = {}
    for probe in probes:
        counts[probe["outcome"]] = counts.get(probe["outcome"], 0) + 1
    out["probes"] = probes[-40:]
    out["counts"] = counts
    out["summary"] = _summary(counts) or "No redirect probe is recorded."

    if counts.get("external-redirect"):
        out.update({
            "verdict": "proven",
            "proves_technique": True,
            "reportability": "low unless chained",
            "summary": ("A recorded response redirects to an external host "
                        f"({_summary(counts)}). The behaviour is proven; its "
                        "impact is not."),
            "next_step": ("Confirm the redirect is reproducible, then show the "
                          "security-relevant flow it enables (OAuth code or "
                          "token theft, SSRF, allowlist bypass). Alone it is "
                          "usually informational or low."),
        })
        return out
    if counts.get("edge-block") and not counts.get("internal-redirect"):
        out.update({
            "verdict": "edge-blocked",
            "proves_technique": False,
            "summary": ("Every redirect probe was stopped by an edge control "
                        f"({_summary(counts)})."),
            "next_step": ("Mark it blocked and retry only from a permitted path. "
                          "Do not report it until a Location header is recorded."),
        })
        return out
    if counts.get("blocked-response") and not (counts.get("internal-redirect")
                                              or counts.get("http-error")):
        out.update({
            "verdict": "blocked",
            "proves_technique": False,
            "summary": ("Every redirect probe was refused before the redirect "
                        f"could be observed ({_summary(counts)})."),
            "next_step": ("Record the refusal, then retry the parameter from a "
                          "permitted path. A refusal is not proof either way."),
        })
        return out
    if counts:
        out.update({
            "verdict": "inconclusive",
            "summary": f"Redirects were recorded but none left the target ({_summary(counts)}).",
            "next_step": ("Try the parameter name the application actually uses "
                          "(next, return, continue, dest, redirect_uri) and keep "
                          "the raw response."),
        })
    return out


def classify(hypothesis: dict, call_rows: list[dict]) -> dict | None:
    """Pick the classifier that matches the hypothesis technique."""
    technique = str(hypothesis.get("technique") or "").lower()
    text = " ".join(str(hypothesis.get(key) or "") for key in
                    ("title", "technique", "rationale")).lower()
    if "ssrf" in technique or "ssrf" in text or "metadata" in technique:
        return classify_ssrf(call_rows)
    if ("redirect" in technique or "open-redirect" in text
            or "open redirect" in text):
        return classify_open_redirect(call_rows)
    return None


def render_lines(verdict: dict) -> list[str]:
    """Markdown block for a case file."""
    if not verdict:
        return []
    lines = [
        "## Verdict",
        "",
        f"- Verdict: **{verdict.get('verdict')}**",
        f"- Proves the technique: **{'yes' if verdict.get('proves_technique') else 'no'}**",
        f"- Evidence: {verdict.get('summary') or ''}",
    ]
    if verdict.get("reportability"):
        lines.append(f"- Reportability: {verdict.get('reportability')}")
    if verdict.get("related_technique"):
        lines.append(f"- Related technique: {verdict.get('related_technique')}")
    lines.extend([
        "",
        str(verdict.get("next_step") or ""),
        "",
        "| time | tool | status | outcome | target |",
        "| --- | --- | --- | --- | --- |",
    ])
    for probe in verdict.get("probes") or []:
        target = str(probe.get("target") or "").replace("|", "%7C")
        lines.append(
            f"| {probe.get('at') or ''} | {probe.get('tool') or ''} | "
            f"{probe.get('status') or ''} | {probe.get('outcome') or ''} | {target} |")
    lines.append("")
    return lines
