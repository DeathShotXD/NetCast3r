"""HTTP session.

One place for every target facing request: rate limiting, retries with
backoff, a response size cap, user agent selection, proxy rotation, and stop
conditions. It also keeps the counters the closing summary prints.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field

import httpx


DEFAULT_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
]


@dataclass
class Response:
    status_code: int
    headers: dict = field(default_factory=dict)
    text: str = ""
    url: str = ""


@dataclass
class Stats:
    requests: int = 0
    ok: int = 0
    errors: int = 0
    status_429: int = 0
    status_403: int = 0
    timeouts: int = 0
    bytes_read: int = 0

    def as_dict(self) -> dict:
        return {
            "requests": self.requests,
            "ok": self.ok,
            "errors": self.errors,
            "status_429": self.status_429,
            "status_403": self.status_403,
            "timeouts": self.timeouts,
            "bytes_read": self.bytes_read,
        }


class StopRun(Exception):
    """Raised when a stop condition is met."""


class Session:
    def __init__(self, config, egress=None, client: httpx.Client | None = None):
        self.config = config
        self.egress = egress
        self.retries = max(config.run.retries, 0)
        self.timeout = config.run.timeout
        self.max_size = config.run.max_response_size
        self.rps = config.run.requests_per_second
        self.delay = config.run.delay
        self.stop_on_rate_limit = config.run.stop_on_rate_limit
        self.stats = Stats()
        self._client = client
        self._lock = threading.Lock()
        self._next_slot = 0.0
        self._clients: dict[str, httpx.Client] = {}

    def _agent(self) -> str:
        if self.config.run.random_user_agent and self.config.run.user_agents:
            return random.choice(self.config.run.user_agents)
        return self.config.run.user_agent

    def _throttle(self) -> None:
        if self.rps and self.rps > 0:
            with self._lock:
                now = time.monotonic()
                wait = max(0.0, 1.0 / self.rps - (now - self._next_slot))
                self._next_slot = max(now, self._next_slot) + 1.0 / self.rps
            if wait > 0:
                time.sleep(wait)
        elif self.delay and self.delay > 0:
            time.sleep(self.delay)

    def _client_for(self, proxy: str | None) -> httpx.Client:
        key = proxy or ""
        with self._lock:
            client = self._clients.get(key)
            if client is None:
                client = httpx.Client(timeout=self.timeout, follow_redirects=True, proxy=proxy)
                self._clients[key] = client
            return client

    def close(self) -> None:
        with self._lock:
            for client in self._clients.values():
                client.close()
            self._clients.clear()

    def _stop_check(self) -> None:
        if not self.stop_on_rate_limit or self.stats.requests < 20:
            return
        if self.stats.status_429 > self.stats.requests * 0.95:
            raise StopRun("more than 95 percent of responses were rate limited")
        if self.stats.status_403 > self.stats.requests * 0.95:
            raise StopRun("more than 95 percent of responses were forbidden")
        if self.stats.timeouts > self.stats.requests * 0.95:
            raise StopRun("more than 95 percent of requests timed out")

    def request(self, method: str, url: str, headers: dict | None = None,
                follow_redirects: bool | None = None, **kw) -> Response | None:
        attempt = 0
        while True:
            attempt += 1
            self._throttle()
            proxy = self.egress.get() if self.egress else None
            merged = {"User-Agent": self._agent()}
            if headers:
                merged.update(headers)
            client = self._client or self._client_for(proxy)
            if follow_redirects is not None:
                kw = {**kw, "follow_redirects": follow_redirects}
            try:
                with client.stream(method, url, headers=merged, **kw) as response:
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= self.max_size:
                            break
                    body = b"".join(chunks)
                    if len(body) > self.max_size:
                        body = body[:self.max_size]
                result = Response(status_code=response.status_code, headers=dict(response.headers),
                                  text=body.decode("utf-8", "ignore"), url=url)
            except httpx.TimeoutException:
                with self._lock:
                    self.stats.timeouts += 1
                    self.stats.errors += 1
                if attempt <= self.retries:
                    time.sleep(0.4 * attempt)
                    continue
                return None
            except Exception:
                with self._lock:
                    self.stats.errors += 1
                if attempt <= self.retries:
                    time.sleep(0.4 * attempt)
                    continue
                return None

            with self._lock:
                self.stats.requests += 1
                self.stats.bytes_read += len(result.text)
                if result.status_code == 429:
                    self.stats.status_429 += 1
                if result.status_code == 403:
                    self.stats.status_403 += 1
                if result.status_code < 400:
                    self.stats.ok += 1
            if result.status_code in (429, 403) and proxy and self.egress:
                self.egress.mark_failed(proxy)
            if result.status_code in (429, 500, 502, 503, 504) and attempt <= self.retries:
                time.sleep(0.4 * attempt)
                continue
            self._stop_check()
            return result

    def get(self, url: str, headers: dict | None = None) -> Response | None:
        return self.request("GET", url, headers=headers)
