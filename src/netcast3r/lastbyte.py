"""HTTP/1.1 last-byte-synchronised request bursts.

The HTTP/2 single-packet technique only works against an h2 endpoint. Many
check-then-act bugs live behind plain HTTP/1.1, so this module opens one
connection per request, writes every request except its final byte, then
releases all final bytes in one tight burst. A server that validates a coupon,
a balance, or an OTP before it commits the state change sees the whole set
arrive inside the same scheduling window.

It is a technique primitive, not a scanner. The caller supplies one request
shape; the tool layer scope-checks the target before this runs.
"""

from __future__ import annotations

import re
import selectors
import socket
import ssl
import time
from urllib.parse import urlsplit

STATUS_RE = re.compile(rb"HTTP/\d(?:\.\d)?\s+(\d{3})")


class LastByteError(RuntimeError):
    pass


def _host_header(host: str, port: int, scheme: str) -> str:
    default = 443 if scheme == "https" else 80
    if port == default:
        return host
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _request_bytes(method: str, path: str, host: str, headers: dict,
                   body: bytes | None) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    skip = {"host", "connection", "content-length", "transfer-encoding",
            "upgrade", "keep-alive", "proxy-connection"}
    for name, value in (headers or {}).items():
        if str(name).lower() in skip:
            continue
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1")
    return head + (body or b"")


def _connect(host: str, port: int, scheme: str, timeout: float,
             verify_tls: bool) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if scheme == "http":
        return raw
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    return context.wrap_socket(raw, server_hostname=host)


def _parse(buffer: bytes) -> dict:
    head, _, body = buffer.partition(b"\r\n\r\n")
    match = STATUS_RE.search(head)
    return {
        "status": int(match.group(1)) if match else 0,
        "bytes": len(body),
        "body": body.decode("utf-8", "replace")[:4096],
    }


def send_burst(url: str, method: str, headers: dict, body: bytes | None,
               count: int, timeout: float = 20.0,
               verify_tls: bool = True) -> dict:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise LastByteError("last-byte race needs an http or https URL")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    count = max(2, min(int(count), 50))
    request = _request_bytes(method.upper(), path,
                             _host_header(host, port, parts.scheme),
                             headers, body)

    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            sockets.append(_connect(host, port, parts.scheme, timeout, verify_tls))
        # Everything except the final byte goes first and waits in the server's
        # receive buffer. Then the final byte of every request goes out in one
        # uninterrupted loop, so the requests complete together.
        prefix, final = request[:-1], request[-1:]
        for sock in sockets:
            sock.sendall(prefix)
        synced = time.monotonic()
        for sock in sockets:
            sock.sendall(final)
        sync_ms = int((time.monotonic() - synced) * 1000)
    except (OSError, ssl.SSLError) as exc:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
        raise LastByteError(f"{type(exc).__name__}: {exc}") from exc

    buffers: dict[socket.socket, bytearray] = {sock: bytearray() for sock in sockets}
    closed: set[socket.socket] = set()
    selector = selectors.DefaultSelector()
    for sock in sockets:
        selector.register(sock, selectors.EVENT_READ, sock)
    started = time.monotonic()
    try:
        while len(closed) < len(sockets) and time.monotonic() - started < timeout:
            for key, _ in selector.select(timeout=0.2):
                sock = key.fileobj
                try:
                    chunk = sock.recv(65535)
                except (socket.timeout, ssl.SSLWantReadError):
                    continue
                except OSError:
                    chunk = b""
                if chunk:
                    buffers[sock].extend(chunk)
                else:
                    closed.add(sock)
                    selector.unregister(sock)
    finally:
        selector.close()
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass

    responses = []
    for index, sock in enumerate(sockets, 1):
        item = _parse(bytes(buffers[sock]))
        item["connection"] = index
        item["ended"] = sock in closed
        responses.append(item)
    statuses: dict[str, int] = {}
    for response in responses:
        key = str(response["status"])
        statuses[key] = statuses.get(key, 0) + 1
    return {
        "url": url, "method": method.upper(), "count": count,
        "responses": responses, "statuses": statuses,
        "ended": len(closed), "sync_ms": sync_ms,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "note": ("Every request except its final byte waited in the receive "
                 "buffer; the final bytes went out in one burst. A duplicate "
                 "side effect is the proof; compare the invariant."),
    }
