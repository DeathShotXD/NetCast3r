"""Provider bus.

One OpenAI-compatible client serves every provider. The model routes decide
which provider and model an agent uses. Providers are tried in priority order,
and on a rate limit the bus rotates the egress proxy and moves to the next
model or provider so a run keeps going.
"""

from __future__ import annotations

import json
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


class ProviderBus:
    def __init__(self, config, egress=None, timeout: float = 120.0):
        self.config = config
        self.egress = egress
        self.timeout = timeout

    def _candidates(self, agent: str):
        route = self.config.route_for(agent)
        ordered = self.config.ordered_providers()
        if route.provider:
            preferred = [p for p in ordered if p.name == route.provider]
            rest = [p for p in ordered if p.name != route.provider]
            ordered = preferred + rest
        for provider in ordered:
            key = provider.resolve_key()
            if not key and provider.name != "ollama":
                continue
            model = route.model if route.provider == provider.name and route.model else (
                provider.models[0] if provider.models else route.model
            )
            if not model:
                continue
            yield provider, model, key

    def chat_stream(self, agent: str, messages: list[dict], on_chunk=None):
        route = self.config.route_for(agent)
        last_error = "no provider available"
        for provider, model, key in self._candidates(agent):
            proxy = self.egress.get() if self.egress else None
            headers = {"Content-Type": "application/json"}
            if key:
                headers["Authorization"] = f"Bearer {key}"
            payload = {
                "model": model,
                "messages": messages,
                "temperature": route.temperature,
                "max_tokens": route.max_tokens,
                "stream": True,
            }
            try:
                with httpx.Client(timeout=self.timeout, proxy=proxy) as client:
                    with client.stream("POST", f"{provider.base_url}/chat/completions",
                                       headers=headers, json=payload) as response:
                        if response.status_code in (403, 429):
                            if self.egress and proxy:
                                self.egress.mark_failed(proxy)
                            last_error = f"{provider.name} returned {response.status_code}"
                            continue
                        if response.status_code >= 400:
                            last_error = f"{provider.name} returned {response.status_code}"
                            continue
                        collected = ""
                        for line in response.iter_lines():
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
                        return collected
            except Exception as exc:
                last_error = _redact(f"{provider.name}: {type(exc).__name__}", key)
                if self.egress and proxy:
                    self.egress.mark_failed(proxy)
                continue
        if on_chunk:
            on_chunk(Chunk("error", last_error))
        return ""
