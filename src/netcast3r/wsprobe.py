"""WebSocket handshake and Cross-Site WebSocket Hijacking (CSWSH).

A WebSocket starts life as an HTTP upgrade. If the server completes the
handshake without checking the ``Origin`` header, a hostile page can open the
socket with the victim's cookies and read or drive the session: CSWSH. This
module performs the upgrade from one scoped origin, then repeats it with a
hostile origin and no origin, and reports what the server accepted.

It completes a handshake only. It never sends a frame after the upgrade, so it
does not touch application state.
"""

from __future__ import annotations

import base64
import os
import socket
import ssl
from urllib.parse import urlsplit

DEFAULT_AGENT = "NetCast3r/ws-audit (+authorized-testing)"
HOSTILE_ORIGINS = ("https://nc3r-canary.invalid", "null", "")
MAX_RESPONSE = 65536


def build_upgrade(host: str, path: str = "/", origin: str | None = None,
                  port: int | None = None, extra: dict | None = None,
                  cookie: str = "") -> str:
    """Build an RFC 6455 upgrade request."""
    key = base64.b64encode(os.urandom(16)).decode()
    target = path or "/"
    lines = [
        f"GET {target} HTTP/1.1",
        f"Host: {host}" + (f":{port}" if port and port not in (80, 443) else ""),
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"User-Agent: {DEFAULT_AGENT}",
    ]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    if cookie:
        lines.append(f"Cookie: {cookie}")
    for name, value in (extra or {}).items():
        lines.append(f"{name}: {value}")
    return "\r\n".join(lines) + "\r\n\r\n"


def parse_response(raw: bytes) -> dict:
    """Parse the upgrade response: status line and headers."""
    text = (raw or b"").decode("utf-8", "replace")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return {
        "status": status,
        "headers": headers,
        "upgraded": status == 101
        and headers.get("upgrade", "").lower() == "websocket",
    }


def default_transport(host: str, port: int, path: str, request: str,
                      use_tls: bool, timeout: float = 8.0) -> bytes:
    """Open one connection, send the upgrade, and read the response head."""
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
            conn.sendall(request.encode("utf-8", "ignore"))
            chunks = bytearray()
            while len(chunks) < MAX_RESPONSE:
                try:
                    piece = conn.recv(4096)
                except (socket.timeout, ssl.SSLError, OSError):
                    break
                if not piece:
                    break
                chunks.extend(piece)
                if b"\r\n\r\n" in chunks:
                    break
            return bytes(chunks)
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _target_parts(target: str) -> dict:
    parts = urlsplit(target if "://" in target else "wss://" + target)
    scheme = (parts.scheme or "wss").lower()
    use_tls = scheme in ("wss", "https")
    port = parts.port or (443 if use_tls else 80)
    return {
        "scheme": scheme,
        "host": (parts.hostname or "").lower(),
        "port": port,
        "path": parts.path or "/",
        "query": parts.query,
        "use_tls": use_tls,
    }


def probe(target: str, origins=None, cookie: str = "", transport=None,
          timeout: float = 8.0) -> dict:
    """Handshake from the same origin, then from hostile origins."""
    transport = transport or (lambda host, port, path, request, use_tls:
                              default_transport(host, port, path, request,
                                                use_tls, timeout))
    parts = _target_parts(target)
    host, port, path = parts["host"], parts["port"], parts["path"]
    if parts["query"]:
        path = f"{path}?{parts['query']}"
    if not host:
        return {"target": target, "ok": False, "note": "target has no host"}

    same_origin = f"https://{host}" if parts["use_tls"] else f"http://{host}"

    def attempt(origin):
        request = build_upgrade(host, path, origin=origin, port=port, cookie=cookie)
        try:
            raw = transport(host, port, path, request, parts["use_tls"])
        except Exception as exc:  # transport failures are data
            return {"origin": origin, "error": str(exc)[:160], "status": 0,
                    "upgraded": False, "headers": {}}
        parsed = parse_response(raw)
        parsed["origin"] = origin
        return parsed

    baseline = attempt(same_origin)
    results = [baseline]
    hijack = []
    for origin in (origins if origins is not None else HOSTILE_ORIGINS):
        row = attempt(origin)
        results.append(row)
        if baseline.get("upgraded") and row.get("upgraded"):
            hijack.append(row)

    if not baseline.get("upgraded"):
        verdict = "not_websocket"
        note = "the server did not complete a WebSocket upgrade from the same origin"
    elif hijack:
        verdict = "cswsh"
        note = ("the server accepted a cross-origin upgrade; with a victim's "
                "cookies this is a cross-site WebSocket hijack")
    else:
        verdict = "origin_checked"
        note = "cross-origin upgrades were refused; the origin check held"
    return {
        "target": target,
        "host": host,
        "port": port,
        "path": path,
        "tls": parts["use_tls"],
        "same_origin": same_origin,
        "verdict": verdict,
        "hijackable_origins": [row["origin"] for row in hijack],
        "results": results,
        "note": note,
    }


def summary() -> dict:
    return {
        "checks": ["upgrade_support", "origin_enforced", "cswsh"],
        "hostile_origins": list(HOSTILE_ORIGINS),
        "note": "Completes the handshake only; no frame is sent after upgrade.",
    }
