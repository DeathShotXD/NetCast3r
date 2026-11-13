"""Parser-discrepancy detection (desync signal).

A desync needs two parsers that disagree on where a message ends. The
detection is a differential: send a request with a header hidden in different
ways, and find a response that none of the baseline, omitted, or masked
requests produce. A unique response is strong evidence of a front-end/back-end
parser discrepancy, without ever sending a smuggled payload.

This module builds those probes, sends one request per fresh connection with
``Connection: close``, and classifies the differential. It is detection: it
never queues a follow-up request on the socket, so it cannot smuggle.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from urllib.parse import urlsplit

DEFAULT_AGENT = "NetCast3r/desync-probe (+authorized-testing)"
MAX_RESPONSE = 65536

# Header-hiding shapes that a front end and a back end may treat differently.
HIDERS = (
    ("leading_space", " {name}: {value}"),
    ("trailing_space", "{name} : {value}"),
    ("tab_before_colon", "{name}\t: {value}"),
    ("double_colon", "{name}::{value}"),
    ("null_after_name", "{name}\x00: {value}"),
    ("newline_only", "{name}:\n{value}"),
)
# Transfer-Encoding obfuscations that stop one parser from seeing chunked.
TE_VARIANTS = (
    ("chunked_upper", "Transfer-Encoding: CHUNKED"),
    ("xchunked", "Transfer-Encoding: xchunked"),
    ("space_before_colon", "Transfer-Encoding : chunked"),
    ("tab_before_colon", "Transfer-Encoding\t: chunked"),
    ("quoted", 'Transfer-Encoding: "chunked"'),
)
CL_TE_CONFLICT = "Transfer-Encoding: chunked"


def _response_signature(raw: bytes) -> dict:
    if not raw:
        return {"status": 0, "length": 0, "hash": "", "empty": True}
    text = raw.decode("iso-8859-1", "replace")
    first = text.split("\r\n", 1)[0]
    status = 0
    parts = first.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
    return {"status": status, "length": len(text),
            "hash": hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16],
            "empty": status == 0}


def build_request(host: str, path: str = "/", method: str = "GET",
                  header_lines=None, body: str = "", port: int | None = None,
                  close: bool = True) -> bytes:
    """Build one HTTP/1.1 request. ``header_lines`` replace the default Host."""
    lines = [f"{method} {path or '/'} HTTP/1.1"]
    if header_lines is None:
        header_lines = [f"Host: {host}"]
    lines.extend(header_lines)
    lines.append(f"User-Agent: {DEFAULT_AGENT}")
    payload = body.encode("utf-8", "ignore")
    if body and not any(line.lower().startswith("content-length")
                        for line in header_lines):
        lines.append(f"Content-Length: {len(payload)}")
    if close:
        lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + payload


def hider_probes(host: str, path: str = "/", name: str = "Host") -> list:
    """Baseline, omitted, masked, and hidden variants for one header."""
    value = host
    probes = [
        {"kind": "baseline", "header_lines": [f"{name}: {value}"]},
        {"kind": "omitted", "header_lines": []},
        {"kind": "masked", "header_lines": [f"{name}: nc3r-masked.invalid"]},
    ]
    for kind, template in HIDERS:
        probes.append({"kind": kind,
                       "header_lines": [template.format(name=name, value=value)]})
    probes.append({"kind": "duplicate_invalid",
                   "header_lines": [f"{name}: {value}",
                                    f"{name}: nc3r-masked.invalid"]})
    return probes


def te_probes(host: str, path: str = "/post") -> list:
    """A short body with a normal length, then Transfer-Encoding variants."""
    body = "nc3r=1"
    probes = [{"kind": "post_baseline",
               "header_lines": [f"Host: {host}",
                                "Content-Type: application/x-www-form-urlencoded",
                                f"Content-Length: {len(body)}"],
               "body": body, "method": "POST"}]
    for kind, line in TE_VARIANTS:
        probes.append({"kind": kind,
                       "header_lines": [f"Host: {host}", line,
                                        f"Content-Length: {len(body)}"],
                       "body": body, "method": "POST"})
    probes.append({"kind": "cl_te_conflict",
                   "header_lines": [f"Host: {host}", CL_TE_CONFLICT,
                                    f"Content-Length: {len(body)}"],
                   "body": body, "method": "POST"})
    return probes


def default_transport(target: str, request: bytes, timeout: float = 8.0) -> bytes:
    """Send one request on a fresh connection and read the response head."""
    parts = urlsplit(target if "://" in target else "https://" + target)
    use_tls = (parts.scheme or "https") in ("https", "wss")
    host = parts.hostname or ""
    port = parts.port or (443 if use_tls else 80)
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = context.wrap_socket(raw, server_hostname=host)
        else:
            conn = raw
        with conn:
            conn.settimeout(timeout)
            conn.sendall(request)
            chunks = bytearray()
            while len(chunks) < MAX_RESPONSE:
                try:
                    piece = conn.recv(4096)
                except (socket.timeout, ssl.SSLError, OSError):
                    break
                if not piece:
                    break
                chunks.extend(piece)
            return bytes(chunks)
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _send(transport, target, request, timeout):
    try:
        return transport(target, request, timeout)
    except TypeError:
        return transport(target, request)
    except Exception as exc:  # transport failures are data
        return b""


def probe(target: str, transport=None, timeout: float = 8.0,
          header: str = "Host", include_transfer_encoding: bool = True) -> dict:
    """Send the differential probes and classify each response."""
    transport = transport or default_transport
    parts = urlsplit(target if "://" in target else "https://" + target)
    host = parts.hostname or ""
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    if not host:
        return {"target": target, "ok": False, "note": "target has no host"}

    rows = []
    for spec in hider_probes(host, path, header):
        request = build_request(host, path, header_lines=spec["header_lines"])
        raw = _send(transport, target, request, timeout)
        signature = _response_signature(raw)
        rows.append({"kind": spec["kind"], "family": "header_hiding",
                     "signature": signature,
                     "request": request.decode("iso-8859-1", "replace")})
    # A unique response that baseline, omitted, and masked do not produce is a
    # parser discrepancy.
    known = {_key(row) for row in rows if row["kind"] in
             ("baseline", "omitted", "masked")}
    discrepancies = [row for row in rows
                     if row["kind"] not in ("baseline", "omitted", "masked")
                     and not row["signature"]["empty"]
                     and _key(row) not in known]

    te_rows = []
    if include_transfer_encoding:
        for spec in te_probes(host, path):
            request = build_request(host, path, method=spec.get("method", "POST"),
                                    header_lines=spec["header_lines"],
                                    body=spec.get("body", ""))
            raw = _send(transport, target, request, timeout)
            te_rows.append({"kind": spec["kind"], "family": "transfer_encoding",
                            "signature": _response_signature(raw),
                            "request": request.decode("iso-8859-1", "replace")})
        base = next((row for row in te_rows if row["kind"] == "post_baseline"), None)
        if base is not None and not base["signature"]["empty"]:
            base_key = _key(base)
            for row in te_rows:
                if row["kind"] == "post_baseline" or row["signature"]["empty"]:
                    continue
                if _key(row) != base_key and row["signature"]["status"] in (400, 501):
                    discrepancies.append(row)

    return {
        "target": target, "host": host, "probes": rows + te_rows,
        "discrepancies": discrepancies,
        "verdict": "parser_discrepancy" if discrepancies else "no_signal",
        "note": ("A unique response to a hidden header is a parser discrepancy, "
                 "not a proven desync. It is a lead to confirm in a lab. No "
                 "smuggled request is ever sent."),
    }


def _key(row: dict) -> tuple:
    sig = row["signature"]
    return (sig["status"], sig["length"], sig["hash"])


def summary() -> dict:
    return {
        "hiders": [name for name, _ in HIDERS],
        "te_variants": [name for name, _ in TE_VARIANTS],
        "note": "Differential detection only; one request per fresh connection.",
    }
