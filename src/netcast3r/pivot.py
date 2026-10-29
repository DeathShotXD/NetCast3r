"""Credential pivot checks.

After a token, cookie, or API key is recovered, the next question is where it
is valid. This module sends the credential to a bounded list of in-scope hosts
and compares the response with an unauthenticated baseline. It never follows a
redirect to another host and never writes the credential to a log.

The MCP handler checks every host against the mission scope before this module
is called.
"""

from __future__ import annotations

import hashlib
import time
from urllib.parse import urlsplit

import httpx

MAX_HOSTS = 25
MAX_BYTES = 8192


def normalize_host(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def _digest(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "ignore")).hexdigest()[:16]


def _request(url: str, headers: dict, timeout: float,
             transport: httpx.BaseTransport | None = None) -> dict:
    try:
        client = httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False,
                              transport=transport)
        try:
            response = client.get(url, headers=headers)
            chunks, total = [], 0
            for chunk in response.iter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BYTES:
                    break
            body = b"".join(chunks)[:MAX_BYTES].decode("utf-8", "replace")
            return {
                "status": response.status_code,
                "bytes": len(body),
                "hash": _digest(body),
                "body": body,
                "location": response.headers.get("location", "")[:300],
            }
        finally:
            client.close()
    except httpx.HTTPError as exc:
        return {"status": 0, "bytes": 0, "hash": "", "body": "",
                "location": "", "error": type(exc).__name__}


def _accepted(baseline: dict, authed: dict) -> bool:
    if authed.get("error"):
        return False
    base_status = int(baseline.get("status") or 0)
    status = int(authed.get("status") or 0)
    if base_status in {401, 403} and status < 400:
        return True
    if base_status == 200 and status == 200 and baseline.get("hash") != authed.get("hash"):
        return True
    return False


def pivot(hosts: list[str], header: str, token_value: str, path: str = "/",
          timeout: float = 10.0, delay: float = 0.25,
          transport: httpx.BaseTransport | None = None) -> dict:
    """Check a credential against each host and report where the response changed."""
    header = (header or "Authorization").strip()
    if not header or any(char in header for char in "\r\n:"):
        raise ValueError("invalid header name")
    token_value = (token_value or "").strip()
    if not token_value:
        raise ValueError("token value is required")
    if len(token_value) > 8192:
        raise ValueError("token value is too long")
    value = token_value
    if header.lower() == "authorization" and not value.lower().startswith(
            ("bearer ", "basic ", "token ", "apikey ")):
        value = "Bearer " + value
    path = path if path.startswith("/") else "/" + path
    rows = []
    for index, raw_host in enumerate(hosts[:MAX_HOSTS]):
        if index and delay:
            time.sleep(delay)
        base = normalize_host(raw_host)
        if not base:
            rows.append({"host": raw_host, "accepted": False, "error": "invalid host"})
            continue
        url = base + path
        baseline = _request(url, {"Accept": "*/*"}, timeout, transport)
        authed = _request(url, {"Accept": "*/*", header: value}, timeout, transport)
        rows.append({
            "host": base,
            "baseline_status": baseline.get("status", 0),
            "auth_status": authed.get("status", 0),
            "baseline_bytes": baseline.get("bytes", 0),
            "auth_bytes": authed.get("bytes", 0),
            "accepted": _accepted(baseline, authed),
            "redirect": authed.get("location", ""),
            "error": authed.get("error", ""),
            "body_sample": (authed.get("body") or "")[:180],
        })
    accepted = [row for row in rows if row.get("accepted")]
    return {
        "header": header,
        "path": path,
        "tested": len(rows),
        "accepted": len(accepted),
        "hosts": rows,
        "note": ("A changed response is a lead, not proof of authorization. Confirm the "
                 "body and the account the credential belongs to before recording a finding."),
    }
