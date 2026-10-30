"""HTTP/2 single-packet request bursts.

A normal concurrent client opens several connections or writes requests in
separate TCP segments. Some check-then-act bugs only appear when the final
bytes of all requests arrive together. This module opens one TLS/HTTP/2
connection, sends every request's headers and all but the final body byte,
then writes every final DATA frame in one socket write.

It is a technique primitive, not a scanner. The caller supplies one request
shape; the target is scope-checked by the tool layer before this runs.
"""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlsplit

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:  # pragma: no cover - optional dependency
    h2 = None


class SinglePacketError(RuntimeError):
    pass


def send_burst(url: str, method: str, headers: dict, body: bytes | None,
               count: int, timeout: float = 20.0,
               verify_tls: bool = True) -> dict:
    if h2 is None:
        raise SinglePacketError("the h2 package is not installed")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise SinglePacketError("single-packet HTTP/2 needs an https URL")
    host = parts.hostname
    port = parts.port or 443
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    count = max(2, min(int(count), 50))

    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = context.wrap_socket(raw, server_hostname=host)
    sock.settimeout(timeout)
    config = h2.config.H2Configuration(client_side=True,
                                       header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    request_headers = [
        (":method", method.upper()),
        (":authority", host),
        (":scheme", "https"),
        (":path", path),
    ]
    for key, value in (headers or {}).items():
        lower = str(key).lower()
        if lower in {"host", "connection", "content-length", "transfer-encoding",
                     "upgrade", "keep-alive", "proxy-connection"}:
            continue
        request_headers.append((str(key), str(value)))
    if body is not None:
        request_headers.append(("content-length", str(len(body))))

    streams: dict[int, dict] = {}
    finals: list[tuple[int, bytes]] = []
    for _ in range(count):
        stream_id = conn.get_next_available_stream_id()
        streams[stream_id] = {"status": 0, "headers": {}, "body": b""}
        if body:
            conn.send_headers(stream_id, request_headers, end_stream=False)
            if len(body) > 1:
                conn.send_data(stream_id, body[:-1], end_stream=False)
            finals.append((stream_id, body[-1:]))
        else:
            conn.send_headers(stream_id, request_headers, end_stream=True)

    # Flush everything except the final byte of each body.
    pending = conn.data_to_send()
    if pending:
        sock.sendall(pending)
    # The gate: all final DATA frames are built first, then one write.
    for stream_id, last in finals:
        conn.send_data(stream_id, last, end_stream=True)
    gate = conn.data_to_send()
    started = time.monotonic()
    if gate:
        sock.sendall(gate)

    done: set[int] = set()
    while len(done) < count and time.monotonic() - started < timeout:
        try:
            data = sock.recv(65535)
        except socket.timeout:
            break
        if not data:
            break
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                stream = streams.get(event.stream_id)
                if stream:
                    stream["status"] = int(dict(event.headers).get(":status", 0))
                    stream["headers"] = {
                        str(key): str(value) for key, value in event.headers}
            elif isinstance(event, h2.events.DataReceived):
                stream = streams.get(event.stream_id)
                if stream:
                    stream["body"] += event.data
                conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded):
                done.add(event.stream_id)
            elif isinstance(event, h2.events.ConnectionTerminated):
                break
        outbound = conn.data_to_send()
        if outbound:
            sock.sendall(outbound)
    sock.close()
    responses = []
    for stream_id, stream in streams.items():
        body_text = stream["body"].decode("utf-8", "replace")
        responses.append({
            "stream_id": stream_id, "status": stream["status"],
            "bytes": len(stream["body"]), "body": body_text[:4096],
            "ended": stream_id in done,
        })
    statuses: dict[str, int] = {}
    for response in responses:
        key = str(response["status"])
        statuses[key] = statuses.get(key, 0) + 1
    return {
        "url": url, "method": method.upper(), "count": count,
        "responses": responses, "statuses": statuses,
        "ended": len(done),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "note": ("All final DATA frames were sent in one write. A duplicate "
                 "side effect is the proof; compare the invariant."),
    }
