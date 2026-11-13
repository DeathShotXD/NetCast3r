"""Minimal DNS client over UDP and TCP.

NetCast3r has no third-party DNS dependency, so this module speaks the wire
format directly. It exists for two jobs the crawler cannot do: follow a CNAME
chain to see whether a name still points at an unclaimed third-party service,
and read the TXT/MX/NS/CAA records that describe a domain's mail and ownership
posture.

Design rules:

- Pure stdlib, no network calls at import time, no global resolver state.
- Every function that touches the network takes an explicit ``nameserver`` and
  ``timeout`` so tests can drive parsed bytes instead.
- A non-zero rcode is data, not an exception: ``Message.rcode`` says NXDOMAIN,
  REFUSED, and so on. Only transport problems raise ``DnsError``.
- Name decompression follows pointers with a depth guard so a hostile or
  malformed response cannot loop.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass, field

QTYPES: dict[str, int] = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "DS": 43, "AXFR": 252, "ANY": 255, "CAA": 257,
}
QTYPE_NAMES: dict[int, str] = {value: key for key, value in QTYPES.items()}

RCODE_NAMES: dict[int, str] = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}

MAX_NAME_DEPTH = 24
MAX_MESSAGE = 65535


class DnsError(Exception):
    """A transport or framing problem, never a DNS rcode."""

    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: str
    fields: dict = field(default_factory=dict)

    @property
    def type_name(self) -> str:
        return QTYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")


@dataclass
class Message:
    ident: int
    flags: int
    rcode: int
    questions: list = field(default_factory=list)
    answers: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    def records(self, rtype: str | int | None = None) -> list:
        """Answer records, optionally filtered to one type name or number."""
        wanted = None
        if isinstance(rtype, str):
            wanted = QTYPES.get(rtype.upper())
        elif isinstance(rtype, int):
            wanted = rtype
        if wanted is None:
            return list(self.answers)
        return [row for row in self.answers if row.rtype == wanted]


def _label_bytes(label: str) -> bytes:
    try:
        raw = label.encode("idna")
    except (UnicodeError, UnicodeDecodeError):
        raw = label.encode("ascii", "ignore")
    if not raw:
        raise DnsError("empty DNS label", retryable=False)
    if len(raw) > 63:
        raise DnsError("DNS label over 63 bytes", retryable=False)
    return raw


def encode_name(name: str) -> bytes:
    """Encode a domain name as length-prefixed labels ending in a null byte."""
    cleaned = (name or "").strip().rstrip(".")
    if not cleaned:
        return b"\x00"
    out = bytearray()
    for label in cleaned.split("."):
        raw = _label_bytes(label)
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _decode_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a name at ``offset``; return the name and the next offset."""
    if depth > MAX_NAME_DEPTH:
        raise DnsError("DNS compression loop", retryable=False)
    labels: list[str] = []
    pos = offset
    consumed = None
    steps = 0
    while True:
        steps += 1
        if steps > 128 or pos >= len(data):
            raise DnsError("truncated DNS name", retryable=False)
        length = data[pos]
        if length == 0:
            pos += 1
            if consumed is None:
                consumed = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsError("truncated DNS pointer", retryable=False)
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if consumed is None:
                consumed = pos + 2
            tail, _ = _decode_name(data, pointer, depth + 1)
            if tail:
                labels.append(tail)
            break
        if length & 0xC0:
            raise DnsError("reserved DNS label type", retryable=False)
        pos += 1
        chunk = data[pos:pos + length]
        if len(chunk) < length:
            raise DnsError("truncated DNS label", retryable=False)
        labels.append(chunk.decode("utf-8", "replace"))
        pos += length
    return ".".join(part for part in labels if part), (consumed if consumed is not None else pos)


def _parse_rdata(data: bytes, start: int, rtype: int, length: int) -> tuple[str, dict]:
    end = start + length
    if end > len(data):
        raise DnsError("truncated DNS rdata", retryable=False)
    if rtype == 1 and length == 4:
        return socket.inet_ntoa(data[start:end]), {}
    if rtype == 28 and length == 16:
        return socket.inet_ntop(socket.AF_INET6, data[start:end]), {}
    if rtype in (2, 5, 12):
        name, _ = _decode_name(data, start)
        return name, {}
    if rtype == 6:
        mname, pos = _decode_name(data, start)
        rname, pos = _decode_name(data, pos)
        values = struct.unpack("!IIIII", data[pos:pos + 20])
        return f"{mname} {rname}", {
            "mname": mname, "rname": rname, "serial": values[0],
            "refresh": values[1], "retry": values[2], "expire": values[3],
            "minimum": values[4],
        }
    if rtype == 15 and length >= 3:
        pref = struct.unpack("!H", data[start:start + 2])[0]
        exchange, _ = _decode_name(data, start + 2)
        return f"{pref} {exchange}", {"preference": pref, "exchange": exchange}
    if rtype == 16:
        parts = []
        pos = start
        while pos < end:
            size = data[pos]
            pos += 1
            parts.append(data[pos:pos + size].decode("utf-8", "replace"))
            pos += size
        text = "".join(parts)
        return text, {"text": text, "strings": parts}
    if rtype == 33 and length >= 7:
        prio, weight, port = struct.unpack("!HHH", data[start:start + 6])
        target, _ = _decode_name(data, start + 6)
        return f"{prio} {weight} {port} {target}", {
            "priority": prio, "weight": weight, "port": port, "target": target,
        }
    if rtype == 43 and length >= 4:
        keytag, algorithm, digest_type = struct.unpack("!HBB", data[start:start + 4])
        digest = data[start + 4:end].hex()
        return f"{keytag} {algorithm} {digest_type} {digest}", {
            "key_tag": keytag, "algorithm": algorithm,
            "digest_type": digest_type, "digest": digest,
        }
    if rtype == 257 and length >= 2:
        flags = data[start]
        tag_len = data[start + 1]
        tag = data[start + 2:start + 2 + tag_len].decode("utf-8", "replace")
        value = data[start + 2 + tag_len:end].decode("utf-8", "replace")
        return f'{flags} {tag} "{value}"', {
            "flags": flags, "tag": tag, "value": value,
        }
    return data[start:end].hex(), {}


def build_query(name: str, qtype: str | int = "A", qclass: int = 1,
                rd: bool = True, ident: int | None = None) -> bytes:
    """Build one DNS query message."""
    number = QTYPES.get(qtype.upper()) if isinstance(qtype, str) else qtype
    if not number:
        raise DnsError(f"unknown query type: {qtype}", retryable=False)
    if ident is None:
        ident = int.from_bytes(os.urandom(2), "big")
    flags = 0x0100 if rd else 0
    header = struct.pack("!HHHHHH", ident & 0xFFFF, flags, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", number, qclass)


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise DnsError("DNS message shorter than a header", retryable=False)
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    offset = 12
    questions: list = []
    for _ in range(qd):
        name, offset = _decode_name(data, offset)
        if offset + 4 > len(data):
            raise DnsError("truncated DNS question", retryable=False)
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append({"name": name, "qtype": qtype, "qclass": qclass})

    def read_records(count: int) -> list:
        nonlocal offset
        out = []
        for _ in range(count):
            if offset + 10 > len(data):
                raise DnsError("truncated DNS record", retryable=False)
            rname, offset = _decode_name(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            text, fields = _parse_rdata(data, offset, rtype, rdlength)
            offset += rdlength
            out.append(Record(rname, rtype, rclass, ttl, text, fields))
        return out

    answers = read_records(an)
    authority = read_records(ns)
    additional = read_records(ar)
    return Message(ident=ident, flags=flags, rcode=rcode, questions=questions,
                   answers=answers, authority=authority, additional=additional)


def system_nameservers() -> list[str]:
    """Nameservers from /etc/resolv.conf, in order."""
    found: list[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    value = parts[1].strip()
                    if value and value not in found:
                        found.append(value)
    except OSError:
        found = []
    return found


def _pick_nameserver(nameserver: str | None) -> str:
    if nameserver:
        return nameserver
    servers = system_nameservers()
    if not servers:
        raise DnsError("no resolver available", retryable=False)
    return servers[0]


def _udp_query(payload: bytes, nameserver: str, timeout: float) -> bytes | None:
    family = socket.AF_INET6 if ":" in nameserver else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (nameserver, 53))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(MAX_MESSAGE)
            except socket.timeout:
                return None
            if len(data) >= 2 and data[:2] == payload[:2]:
                return data
    finally:
        sock.close()


def _tcp_query(payload: bytes, nameserver: str, timeout: float) -> bytes | None:
    family = socket.AF_INET6 if ":" in nameserver else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((nameserver, 53))
        sock.sendall(struct.pack("!H", len(payload)) + payload)
        header = _recv_exact(sock, 2)
        if header is None:
            return None
        size = struct.unpack("!H", header)[0]
        return _recv_exact(sock, size)
    except OSError:
        return None
    finally:
        sock.close()


def _recv_exact(sock: socket.socket, count: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < count:
        try:
            piece = sock.recv(count - len(chunks))
        except OSError:
            return None
        if not piece:
            return None
        chunks.extend(piece)
    return bytes(chunks)


def query(name: str, qtype: str | int = "A", nameserver: str | None = None,
          timeout: float = 3.0, tcp: bool = False,
          retries: int = 1) -> Message:
    """Query one name and return the parsed response.

    UDP is the default. A truncated answer, or ``tcp=True``, retries over TCP.
    Transport failure after the retries raises ``DnsError``; a SERVFAIL or
    NXDOMAIN response is returned as a ``Message``.
    """
    server = _pick_nameserver(nameserver)
    timeout = max(0.2, min(float(timeout), 30.0))
    payload = build_query(name, qtype)
    attempts = max(1, int(retries) + 1)
    last_error = "no response"
    for attempt in range(attempts):
        if not tcp:
            data = _udp_query(payload, server, timeout)
            if data is not None:
                message = parse_message(data)
                if message.truncated:
                    tcp_data = _tcp_query(payload, server, timeout)
                    if tcp_data is not None:
                        return parse_message(tcp_data)
                    return message
                return message
        else:
            data = _tcp_query(payload, server, timeout)
            if data is not None:
                return parse_message(data)
        last_error = "timeout" if attempt == attempts - 1 else last_error
    raise DnsError(f"no DNS response from {server}: {last_error}")


def resolve_chain(name: str, nameserver: str | None = None,
                  timeout: float = 3.0, max_depth: int = 10) -> dict:
    """Follow a CNAME chain and collect the terminal addresses.

    Returns ``{"name", "chain", "cname", "addresses", "nxdomain", "rcode"}``.
    ``chain`` lists each CNAME target in order. The terminal name is queried
    for A and AAAA so a dangling target with no address is visible.
    """
    current = (name or "").strip().rstrip(".")
    chain: list[str] = []
    seen = {current}
    rcode = "NOERROR"
    for _ in range(max_depth):
        message = query(current, "CNAME", nameserver=nameserver, timeout=timeout)
        if message.rcode != 0:
            rcode = message.rcode_name
            if message.rcode == 3:
                return {"name": name, "chain": chain, "cname": current,
                        "addresses": [], "nxdomain": True, "rcode": rcode}
            return {"name": name, "chain": chain, "cname": current,
                    "addresses": [], "nxdomain": False, "rcode": rcode}
        cnames = message.records("CNAME")
        if not cnames:
            break
        target = cnames[0].data.rstrip(".")
        if not target or target in seen:
            break
        seen.add(target)
        chain.append(target)
        current = target
    addresses: list[str] = []
    nxdomain = False
    for rtype in ("A", "AAAA"):
        message = query(current, rtype, nameserver=nameserver, timeout=timeout)
        if message.rcode == 3:
            nxdomain = True
            rcode = message.rcode_name
        addresses.extend(row.data for row in message.records(rtype))
    return {"name": name, "chain": chain, "cname": current,
            "addresses": addresses, "nxdomain": nxdomain, "rcode": rcode}


def txt_records(name: str, nameserver: str | None = None,
                timeout: float = 3.0) -> list[str]:
    """All TXT strings for a name, one row per record."""
    message = query(name, "TXT", nameserver=nameserver, timeout=timeout)
    return [row.fields.get("text", row.data) for row in message.records("TXT")]


def axfr(domain: str, nameserver: str, timeout: float = 5.0,
         max_records: int = 2000, max_messages: int = 64) -> dict:
    """Attempt a full zone transfer (AXFR) against one nameserver.

    AXFR is always TCP. The zone is considered open only when the server sends
    at least one record and closes the transfer with a second SOA. Anything
    else is recorded as closed or refused.
    """
    server = _pick_nameserver(nameserver)
    payload = build_query(domain, "AXFR")
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    records: list = []
    soa_count = 0
    rcode = 0
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, 53))
        sock.sendall(struct.pack("!H", len(payload)) + payload)
        for _ in range(max_messages):
            header = _recv_exact(sock, 2)
            if header is None:
                break
            size = struct.unpack("!H", header)[0]
            body = _recv_exact(sock, size)
            if body is None:
                break
            message = parse_message(body)
            rcode = message.rcode
            if message.rcode != 0:
                break
            records.extend(message.answers)
            soa_count += sum(1 for row in message.answers if row.rtype == 6)
            if soa_count >= 2 or len(records) >= max_records:
                break
    except OSError as exc:
        return {"nameserver": server, "open": False, "records": [], "rcode": rcode,
                "error": str(exc)[:160]}
    finally:
        sock.close()
    return {"nameserver": server, "open": soa_count >= 2 and len(records) > 1,
            "records": records[:max_records], "rcode": rcode, "soa_count": soa_count,
            "count": len(records)}
