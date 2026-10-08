"""Provider bus.

One OpenAI-compatible client serves every provider. The model routes decide
which provider and model an agent uses. Providers are tried in priority order,
and on a rate limit the bus rotates the egress proxy, cools the provider down
and moves to the next model or provider so a run keeps going.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

import httpx


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

    COOLDOWN_BASE = 30.0
    COOLDOWN_MAX = 300.0

    def _penalize(self, name: str) -> None:
        strikes = self._cooldown.get(name, (0.0, 0))[1] + 1
        delay = min(self.COOLDOWN_BASE * (2 ** (strikes - 1)), self.COOLDOWN_MAX)
        self._cooldown[name] = (time.monotonic() + delay, strikes)

    def _cooling(self, name: str) -> bool:
        record = self._cooldown.get(name)
        return bool(record) and time.monotonic() < record[0]

    def _settle(self, name: str) -> None:
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
            if not key and provider.name != "ollama":
                continue
            models = list(provider.models)
            if route.model:
                if route.model in models:
                    models.remove(route.model)
                models.insert(0, route.model)
            if not models:
                continue
            for model in models:
                if model:
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
                            last_error = f"{provider.name} returned {response.status_code}"
                            self._observe({"kind": "done", "agent": agent,
                                           "provider": provider.name, "model": model,
                                           "ok": False, "ms": _ms(attempt),
                                           "error": f"HTTP {response.status_code}"})
                            continue
                        if response.status_code >= 400:
                            last_error = f"{provider.name} returned {response.status_code}"
                            self._observe({"kind": "done", "agent": agent,
                                           "provider": provider.name, "model": model,
                                           "ok": False, "ms": _ms(attempt),
                                           "error": f"HTTP {response.status_code}"})
                            continue
                        collected = ""
                        started = time.monotonic()
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
                            delta = parsed.get("choices", [{}])[0].get("delta", {})
                            reasoning = delta.get("reasoning") or delta.get("reasoning_content")
                            if reasoning:
                                chunk = Chunk("reasoning", reasoning)
                                if on_chunk:
                                    on_chunk(chunk)
                            content = delta.get("content")
                            if content:
                                collected += content
                                chunk = Chunk("content", content)
                                if on_chunk:
                                    on_chunk(chunk)
                        if on_chunk:
                            on_chunk(Chunk("done", provider.name))
                        if not collected:
                            last_error = f"{provider.name}/{model} returned no content"
                            self._observe({"kind": "done", "agent": agent,
                                           "provider": provider.name, "model": model,
                                           "ok": False, "ms": _ms(attempt),
                                           "error": "no content"})
                            continue
                        self._settle(provider.name)
                        self._observe({"kind": "done", "agent": agent,
                                       "provider": provider.name, "model": model,
                                       "ok": True, "ms": _ms(attempt)})
                        return collected
            except Exception as exc:
                last_error = _redact(f"{provider.name}: {type(exc).__name__}", key)
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
