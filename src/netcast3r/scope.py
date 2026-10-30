"""Scope resolution.

In-scope and out-of-scope files take one entry per line, and the out-of-scope
file wins. Supported entry forms:

    example.com            the host and all of its subdomains
    *.example.com          subdomains only
    https://example.com/p  scheme and path prefix
    10.0.0.0/24            an IPv4 network
    re:^api\\.              a regular expression against the host

Blank lines and lines starting with # are ignored. Crawling is only ever
attempted for hosts that resolve in scope, which keeps every request inside
the rules of the engagement.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


@dataclass
class ScopeRule:
    raw: str
    kind: str
    value: str
    path: str = ""
    net: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    regex: re.Pattern | None = None

    def matches(self, host: str, path: str = "") -> bool:
        host = host.lower().rstrip(".")
        if self.kind == "suffix":
            return host == self.value or host.endswith("." + self.value)
        if self.kind == "wildcard":
            return host.endswith("." + self.value) and host != self.value
        if self.kind == "exact":
            return host == self.value
        if self.kind == "net":
            try:
                return self.net is not None and ipaddress.ip_address(host) in self.net
            except ValueError:
                return False
        if self.kind == "regex":
            return bool(self.regex and self.regex.search(host))
        if self.kind == "url_prefix":
            clean = posixpath.normpath("/" + unquote(path).lstrip("/"))
            base = posixpath.normpath(self.path or "/")
            return host == self.value and (clean == base
                                           or clean.startswith(base.rstrip("/") + "/"))
        return False


def parse_rule(entry: str) -> ScopeRule | None:
    raw = entry.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith("!"):
        raw = raw[1:].strip()
    if not raw:
        return None
    if raw.startswith("re:"):
        pattern = raw[3:]
        try:
            return ScopeRule(raw=raw, kind="regex", value=pattern, regex=re.compile(pattern))
        except re.error:
            return None
    if raw.startswith(("http://", "https://")):
        try:
            parts = urlsplit(raw)
        except ValueError:
            return None
        return ScopeRule(raw=raw, kind="url_prefix", value=parts.hostname or "", path=parts.path or "/")
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return ScopeRule(raw=raw, kind="net", value=raw, net=net)
        except ValueError:
            host, _, path = raw.partition("/")
            host = host.lower().rstrip(".")
            if not host:
                return None
            return ScopeRule(raw=raw, kind="url_prefix", value=host, path="/" + path.lstrip("/"))
    if raw.startswith("*."):
        return ScopeRule(raw=raw, kind="wildcard",
                         value=_strip_port(raw[2:].lower().rstrip(".")))
    return ScopeRule(raw=raw, kind="suffix", value=_strip_port(raw.lower().rstrip(".")))


def _strip_port(value: str) -> str:
    """Drop a trailing :port from a host rule, but never from an IPv6 host."""
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and host and ":" not in host:
        return host
    return value


def _split(target: str) -> tuple[str, str]:
    """Return (host, path) using the same parse as the request builder.

    A scheme-less target is parsed as if it carried a scheme, so a value like
    ``example.com@evil.com`` or ``host:8443`` resolves to the host the request
    will actually reach. Checking a different string than the one dialled is how
    a scope rule silently fails open.
    """
    raw = (target or "").strip()
    candidate = raw if "://" in raw else "//" + raw
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return raw.split("/", 1)[0].lower(), "/"
    if not parts.hostname:
        return raw.split("/", 1)[0].lower(), "/"
    return parts.hostname.lower(), parts.path or "/"


class ScopeManager:
    def __init__(self, in_scope=None, out_of_scope=None):
        self.in_rules: list[ScopeRule] = []
        self.out_rules: list[ScopeRule] = [r for r in (parse_rule(x) for x in (out_of_scope or [])) if r]
        # A line that starts with "!" is an exclusion, in either file.
        for entry in (in_scope or []):
            text = entry.strip()
            if text.startswith("!"):
                rule = parse_rule(text[1:])
                if rule:
                    self.out_rules.append(rule)
            else:
                rule = parse_rule(text)
                if rule:
                    self.in_rules.append(rule)

    @classmethod
    def from_files(cls, in_file=None, out_file=None, extra_in=None) -> ScopeManager:
        def read(path):
            if not path:
                return []
            candidate = Path(path)
            if not candidate.exists():
                raise FileNotFoundError(f"scope file not found: {path}")
            return [line.strip() for line in candidate.read_text().splitlines() if line.strip()]

        entries = read(in_file) + [x for x in (extra_in or []) if x]
        return cls(in_scope=entries, out_of_scope=read(out_file))

    def add_seed(self, seed: str) -> None:
        raw = seed.strip()
        if not raw:
            return
        host, _ = _split(raw)
        host = host.lower().rstrip(".")
        if not host:
            return
        try:
            ipaddress.ip_address(host)
            self.in_rules.append(ScopeRule(raw=raw, kind="exact", value=host))
            return
        except ValueError:
            pass
        self.in_rules.append(ScopeRule(raw=raw, kind="suffix", value=host))

    def is_out_of_scope(self, target: str) -> bool:
        host, path = _split(target)
        return any(rule.matches(host, path) for rule in self.out_rules)

    def is_in_scope(self, target: str) -> bool:
        host, path = _split(target)
        if any(rule.matches(host, path) for rule in self.out_rules):
            return False
        if not self.in_rules:
            return True
        return any(rule.matches(host, path) for rule in self.in_rules)

    def classify(self, target: str) -> str:
        host, path = _split(target)
        if any(rule.matches(host, path) for rule in self.out_rules):
            return "out"
        if any(rule.matches(host, path) for rule in self.in_rules):
            return "in"
        return "unknown"
