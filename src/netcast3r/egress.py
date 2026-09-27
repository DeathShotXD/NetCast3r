"""Egress and proxy rotation.

Proxies come from the user first, then from the configured public sources.
Each proxy is health checked before it is handed out, and it is rotated out on
a rate limit or forbidden response. When no proxy is healthy the request goes
direct, so the swarm never stalls.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import httpx


@dataclass
class Proxy:
    url: str
    latency: float = 0.0
    failures: int = 0
    alive: bool = False


def _normalize(entry: str) -> str:
    entry = entry.strip()
    if not entry:
        return ""
    if "://" not in entry:
        entry = "http://" + entry
    return entry


class ProxyPool:
    def __init__(self, config, timeout: float = 8.0):
        self.config = config
        self.timeout = timeout
        self._lock = threading.Lock()
        self._proxies: list[Proxy] = []
        self._index = 0
        self._loaded = False

    def _fetch_public(self) -> list[str]:
        entries: list[str] = []
        for source in self.config.public_sources:
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    text = client.get(source).text
            except Exception:
                continue
            for line in text.splitlines():
                line = line.strip()
                if line and ":" in line and not line.startswith("#"):
                    entries.append(line)
        return entries

    def ensure_loaded(self) -> None:
        with self._lock:
            if self._loaded:
                return
            entries = [_normalize(x) for x in self.config.user_proxies]
            if self.config.use_public and not entries:
                entries += [_normalize(x) for x in self._fetch_public()]
            seen: set[str] = set()
            self._proxies = []
            for url in entries:
                if not url or url in seen:
                    continue
                seen.add(url)
                self._proxies.append(Proxy(url=url))
            self._loaded = True

    def check(self, proxy: Proxy) -> bool:
        start = time.monotonic()
        try:
            with httpx.Client(timeout=self.timeout, proxy=proxy.url) as client:
                response = client.get(self.config.health_url)
            reached = response.status_code < 500
        except Exception:
            reached = False
        proxy.latency = time.monotonic() - start
        proxy.alive = reached
        if not reached:
            proxy.failures += 1
        return reached

    def refresh(self, limit: int = 40) -> int:
        self.ensure_loaded()
        alive = 0
        for proxy in self._proxies[:limit]:
            if self.check(proxy):
                alive += 1
        return alive

    def get(self) -> str | None:
        self.ensure_loaded()
        with self._lock:
            if not self._proxies:
                return None
            for _ in range(len(self._proxies)):
                proxy = self._proxies[self._index % len(self._proxies)]
                self._index += 1
                if proxy.alive:
                    return proxy.url
        return None

    def mark_failed(self, url: str) -> None:
        with self._lock:
            for proxy in self._proxies:
                if proxy.url == url:
                    proxy.failures += 1
                    proxy.alive = False
