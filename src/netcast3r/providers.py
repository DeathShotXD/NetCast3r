"""Provider bus.

One OpenAI-compatible client serves every provider. The model routes decide
which provider and model an agent uses. Providers are tried in priority order,
and on a rate limit the bus rotates the egress proxy, cools the provider down
and moves to the next model or provider so a run keeps going.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _local_endpoint(base_url: str) -> bool:
    """A loopback endpoint needs no key, the way a local ollama does."""
    try:
        return (urlsplit(base_url).hostname or "").lower() in LOCAL_HOSTS
    except ValueError:
        return False


@dataclass
class Chunk:
    kind: str
    text: str = ""


def _redact(text: str, key: str) -> str:
    if key and key in text:
        return text.replace(key, "***")
    return text


def _ms(since: float) -> int:
    return int((time.monotonic() - since) * 1000)


class ProviderBus:
    def __init__(self, config, egress=None, timeout: float = 120.0, observer=None):
        self.config = config
        self.egress = egress
        self.timeout = timeout
        self.observer = observer
        # provider name -> (cooldown_until, strikes): a 429 cools the provider
        # down so the next call rotates away instead of burning the same
        # rate limit over and over
        self._cooldown: dict[str, tuple[float, int]] = {}
        # (provider, model) -> cooldown_until: a model that 400s, 404s, 502s or
        # answers with nothing is retired for a while so a run stops walking a
        # dead catalogue on every call
        self._dead: dict[tuple[str, str], float] = {}
        self._strikes: dict[tuple[str, str], int] = {}
        # the exegete fans out over threads and shares this bus, so every
        # counter below is mutated under one lock
        self._lock = threading.Lock()

    COOLDOWN_BASE = 30.0
    COOLDOWN_MAX = 300.0
    DEAD_TTL = 900.0

    def _model_dead(self, provider: str, model: str) -> bool:
        with self._lock:
            return time.monotonic() < self._dead.get((provider, model), 0.0)

    def _retire(self, provider: str, model: str) -> None:
        with self._lock:
            self._dead[(provider, model)] = time.monotonic() + self.DEAD_TTL

    def _strike(self, provider: str, model: str, fatal: bool = False) -> None:
        with self._lock:
            key = (provider, model)
            count = self._strikes.get(key, 0) + 1
            self._strikes[key] = count
            if fatal or count >= 2:
                self._dead[key] = time.monotonic() + self.DEAD_TTL

    def _penalize(self, name: str) -> None:
        with self._lock:
            strikes = self._cooldown.get(name, (0.0, 0))[1] + 1
            delay = min(self.COOLDOWN_BASE * (2 ** (strikes - 1)), self.COOLDOWN_MAX)
            self._cooldown[name] = (time.monotonic() + delay, strikes)

    def _cooling(self, name: str) -> bool:
        with self._lock:
            record = self._cooldown.get(name)
        return bool(record) and time.monotonic() < record[0]

    def _settle(self, name: str) -> None:
        with self._lock:
            self._cooldown.pop(name, None)

    def _observe(self, data: dict) -> None:
        """Tell the dashboard what the bus is doing, without ever failing a call."""
        if self.observer is None:
            return
        try:
            self.observer(data)
        except Exception:  # noqa: BLE001 - an observer must not break the stream
            pass

    def _candidates(self, agent: str):
        route = self.config.route_for(agent)
        ordered = self.config.ordered_providers()
        if route.provider:
            preferred = [p for p in ordered if p.name == route.provider]
            rest = [p for p in ordered if p.name != route.provider]
            ordered = preferred + rest
        fresh = [p for p in ordered if not self._cooling(p.name)]
        if not fresh:
            # everything is cooling down -- better to try than to stall
            fresh = ordered
        for provider in fresh:
            key = provider.resolve_key()
            if not key and provider.name != "ollama" and not _local_endpoint(provider.base_url):
                continue
            models = list(provider.models)
            if route.model:
                if route.model in models:
                    models.remove(route.model)
                models.insert(0, route.model)
            if not models:
                continue
            for model in models:
                if model and not self._model_dead(provider.name, model):
                    yield provider, model, key

    def chat_stream(self, agent: str, messages: list[dict], on_chunk=None):
        route = self.config.route_for(agent)
        budget = getattr(self.config.run, "max_call_seconds", 90)
        call_timeout = min(self.timeout, budget)
        last_error = "no provider available"
        for provider, model, key in self._candidates(agent):
            attempt = time.monotonic()
            self._observe({"kind": "call", "agent": agent,
                           "provider": provider.name, "model": model})
            proxy = self.egress.get() if self.egress else None
            headers = {"Content-Type": "application/json"}
            if key:
                headers["Authorization"] = f"Bearer {key}"
            if provider.name == "openrouter":
                headers["X-Title"] = "NetCast3r"
            payload = {
                "model": model,
                "messages": messages,
                "temperature": route.temperature,
                "max_tokens": route.max_tokens,
                "stream": True,
            }
            try:
                with httpx.Client(timeout=call_timeout, proxy=proxy) as client:
                    with client.stream("POST", f"{provider.base_url}/chat/completions",
                                       headers=headers, json=payload) as response:
                        if response.status_code in (403, 429):
                            if self.egress and proxy:
                                self.egress.mark_failed(proxy)
                            self._penalize(provider.name)
                            self._strike(provider.name, model)
                            last_error = f"{provider.name} returned {response.status_code}"
                            self._observe({"kind": "done", "agent": agent,
                                           "provider": provider.name, "model": model,
                                           "ok": False, "ms": _ms(attempt),
                                           "error": f"HTTP {response.status_code}"})
                            continue
                        if response.status_code >= 400:
                            self._strike(provider.name, model,
                                         fatal=response.status_code in (400, 404))
                            last_error = f"{provider.name} returned {response.status_code}"
                            self._observe({"kind": "done", "agent": agent,
                                           "provider": provider.name, "model": model,
                                           "ok": False, "ms": _ms(attempt),
                                           "error": f"HTTP {response.status_code}"})
                            continue
                        collected = ""
                        started = time.monotonic()
                        stream_error = False
                        for line in response.iter_lines():
                            if time.monotonic() - started > budget:
                                break
                            if not line or not line.startswith("data:"):
                                continue
                            data = line[5:].strip()
                            if data == "[DONE]":
                                break
                            try:
                                parsed = json.loads(data)
                            except json.JSONDecodeError:
                                continue
                            if isinstance(parsed, dict) and parsed.get("error"):
                                last_error = f"{provider.name}: {str(parsed['error'])[:140]}"
                                stream_error = True
                                break
                            choices = parsed.get("choices") if isinstance(parsed, dict) else None
                            if not choices:
                                continue
                            first = choices[0] if isinstance(choices[0], dict) else {}
                            delta = first.get("delta") or {}
                            reasoning = delta.get("reasoning") or delta.get("reasoning_content")
                            if reasoning and on_chunk:
                                on_chunk(Chunk("reasoning", reasoning))
                            content = delta.get("content")
                            if isinstance(content, list):
                                content = "".join(str(part.get("text", "")) for part in content
                                                  if isinstance(part, dict))
                            if content:
                                collected += content
                                if on_chunk:
                                    on_chunk(Chunk("content", content))
                        if on_chunk:
                            on_chunk(Chunk("done", provider.name))
                        if not collected:
                            if not stream_error:
                                last_error = f"{provider.name}/{model} returned no content"
                            self._strike(provider.name, model)
                            self._observe({"kind": "done", "agent": agent,
                                           "provider": provider.name, "model": model,
                                           "ok": False, "ms": _ms(attempt),
                                           "error": last_error[:140]})
                            continue
                        self._settle(provider.name)
                        self._observe({"kind": "done", "agent": agent,
                                       "provider": provider.name, "model": model,
                                       "ok": True, "ms": _ms(attempt)})
                        return collected
            except Exception as exc:
                last_error = _redact(f"{provider.name}: {type(exc).__name__}", key)
                self._strike(provider.name, model)
                self._observe({"kind": "done", "agent": agent,
                               "provider": provider.name, "model": model,
                               "ok": False, "ms": _ms(attempt),
                               "error": type(exc).__name__})
                if self.egress and proxy:
                    self.egress.mark_failed(proxy)
                continue
        if on_chunk:
            on_chunk(Chunk("error", last_error))
        return ""
