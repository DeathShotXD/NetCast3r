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
from dataclasses import dataclass, field
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


@dataclass
class Completion:
    """One non-streaming completion plus whatever usage the provider sent.

    Token counts and cost stay empty when the provider does not report them;
    the runtime never estimates a price.
    """
    text: str = ""
    provider: str = ""
    model: str = ""
    usage: dict = field(default_factory=dict)
    error: str = ""
    failed: list = field(default_factory=list)
    duration_ms: int = 0


def _redact(text: str, key: str) -> str:
    if key and key in text:
        return text.replace(key, "***")
    return text


def _ms(since: float) -> int:
    return int((time.monotonic() - since) * 1000)


# Mixture-of-Experts: free catalogues ship deepseek / mimo / qwen / nemotron
# with different strengths. Agent roles pick a preferred family, and each
# provider key rotates its primary so sixteen TokenHarbor lanes do not all
# hammer the same free model into a 429 wall.
_EXPERT_FAMILIES = ("deepseek", "mimo", "qwen", "nemotron", "coder", "llama",
                    "mistral", "gemini", "other")

_AGENT_EXPERTS: dict[str, tuple[str, ...]] = {
    "prime": ("deepseek", "nemotron", "qwen", "mimo"),
    "strategist": ("deepseek", "nemotron", "qwen", "mimo"),
    "scout": ("mimo", "deepseek", "qwen", "nemotron"),
    "attacker": ("deepseek", "qwen", "mimo", "nemotron"),
    "validator": ("deepseek", "mimo", "qwen", "nemotron"),
    "verifier": ("deepseek", "mimo", "qwen"),
    "sentinel": ("deepseek", "qwen", "mimo"),
    "exegete": ("qwen", "coder", "deepseek", "mimo"),
    "chainer": ("deepseek", "qwen", "nemotron", "mimo"),
    "scribe": ("mimo", "qwen", "deepseek"),
    "prospector": ("mimo", "deepseek", "qwen"),
    "code": ("qwen", "coder", "deepseek", "mimo"),
    "upgrade": ("qwen", "coder", "deepseek", "nemotron"),
    "train": ("mimo", "deepseek", "qwen"),
    "lab": ("mimo", "deepseek", "qwen"),
}


# Default free MoE catalogue for TokenHarbor hunt/learn lanes. Order is a
# starting hint; ProviderBus MoE reorders per agent and per key at call time.
TOKENHARBOR_MOE_MODELS = [
    "deepseek-v4.1-flash:free",
    "deepseek-v4-flash:free",
    "mimo-v2.6-flash:free",
    "mimo-v2.5:free",
    "qwen3-coder:free",
    "qwen3-8b:free",
    "qwen-2.5-coder-32b:free",
]


def diversify_tokenharbor_catalogs(index) -> dict:
    """Ensure th-hunt/th-learn lanes carry the full free MoE mix.

    Older installs only listed DeepSeek first on every key, which stampeded
    one model into 429s. This merges the MoE catalogue without dropping
    operator-added ids, and rotates the primary per lane.
    """
    updated = []
    for row in index.list_providers():
        name = str(row.get("name") or "")
        if not (name.startswith("th-hunt-") or name.startswith("th-learn-")
                or name in {"tokenharbor"}):
            continue
        current = [str(m) for m in (row.get("models") or []) if str(m).strip()]
        merged = list(current)
        for model in TOKENHARBOR_MOE_MODELS:
            if model not in merged:
                merged.append(model)
        if not merged:
            merged = list(TOKENHARBOR_MOE_MODELS)
        # Rotate primary so lane N prefers a different family.
        offset = abs(hash(name)) % len(merged)
        rotated = merged[offset:] + merged[:offset]
        if rotated != current:
            index.update_provider(row["id"], models=rotated)
            updated.append({"name": name, "models": rotated[:6]})
    return {"updated": updated, "count": len(updated)}


def model_family(model: str) -> str:
    """Classify a catalogue id into an expert family for MoE ordering."""
    name = str(model or "").strip().lower()
    if not name:
        return "other"
    for family in _EXPERT_FAMILIES:
        if family == "other":
            continue
        if family in name:
            return family
    if "code" in name:
        return "coder"
    return "other"


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

    COOLDOWN_BASE = 20.0
    COOLDOWN_MAX = 180.0
    DEAD_TTL = 420.0
    RATE_DEAD_TTL = 90.0

    def _model_dead(self, provider: str, model: str) -> bool:
        with self._lock:
            return time.monotonic() < self._dead.get((provider, model), 0.0)

    def _retire(self, provider: str, model: str, ttl: float | None = None) -> None:
        with self._lock:
            self._dead[(provider, model)] = time.monotonic() + (
                self.DEAD_TTL if ttl is None else float(ttl))

    def _strike(self, provider: str, model: str, fatal: bool = False,
                ttl: float | None = None) -> None:
        with self._lock:
            key = (provider, model)
            count = self._strikes.get(key, 0) + 1
            self._strikes[key] = count
            if fatal or count >= 2:
                self._dead[key] = time.monotonic() + (
                    self.DEAD_TTL if ttl is None else float(ttl))

    @staticmethod
    def _expert_prefs(agent: str, provider_name: str) -> list[str]:
        base = list(_AGENT_EXPERTS.get(str(agent or "").strip().lower(),
                                       ("deepseek", "mimo", "qwen", "nemotron")))
        # Rotate preferred family per provider so th-hunt-1..N diversify.
        if not base:
            return base
        offset = abs(hash(str(provider_name or ""))) % len(base)
        return base[offset:] + base[:offset]

    def _moe_models(self, provider, agent: str, route) -> list[str]:
        """Order this provider's models for the agent (mixture of experts)."""
        models = [m for m in list(provider.models or []) if m]
        # An empty catalogue still accepts the routed model id (local ollama /
        # single-model keys). TokenHarbor lanes always carry an explicit list.
        if not models and route.model:
            models = [route.model]
        if not models:
            return []
        prefs = self._expert_prefs(agent, provider.name)
        routed_here = bool(route.model) and (
            not route.provider or provider.name == route.provider)

        def rank(model: str) -> tuple[int, int]:
            family = model_family(model)
            try:
                pref = prefs.index(family)
            except ValueError:
                pref = len(prefs) + (0 if family == "other" else 1)
            stagger = abs(hash(f"{provider.name}:{agent}")) % len(models)
            try:
                idx = models.index(model)
            except ValueError:
                idx = 0
            return pref, (idx - stagger) % len(models)

        pool = list(models)
        # The routed provider may name a model that is not yet listed (tests /
        # single-id routes). Other providers must never inherit that pin -
        # that was how every th-hunt key stampeded one free DeepSeek into 429.
        if routed_here and route.model and route.model not in pool:
            pool = [route.model] + pool
        ordered = sorted(pool, key=rank)
        if routed_here and route.model and route.model in ordered:
            ordered = [route.model] + [m for m in ordered if m != route.model]
        elif (not route.provider and route.model and route.model in ordered
              and model_family(route.model) == (prefs[0] if prefs else "")):
            # No explicit provider: soft-pin only when the route matches the
            # preferred expert family for this agent.
            ordered = [route.model] + [m for m in ordered if m != route.model]
        return ordered

    def _penalize(self, name: str) -> None:
        with self._lock:
            strikes = self._cooldown.get(name, (0.0, 0))[1] + 1
            delay = min(self.COOLDOWN_BASE * (2 ** (strikes - 1)), self.COOLDOWN_MAX)
            self._cooldown[name] = (time.monotonic() + delay, strikes)

    def _cooling(self, name: str) -> bool:
        with self._lock:
            record = self._cooldown.get(name)
        return bool(record) and time.monotonic() < record[0]

    def _settle(self, name: str, model: str = "") -> None:
        """A real answer clears this provider's cooldown and strikes.

        A strike is a suspicion, not a verdict. Leaving it in place retired a
        healthy provider after one later transient error, so success resets it.
        """
        with self._lock:
            self._cooldown.pop(name, None)
            if model:
                self._strikes.pop((name, model), None)
            else:
                for key in [key for key in self._strikes if key[0] == name]:
                    self._strikes.pop(key, None)

    def _observe(self, data: dict) -> None:
        """Tell the dashboard what the bus is doing, without ever failing a call."""
        if self.observer is None:
            return
        try:
            self.observer(data)
        except Exception:  # noqa: BLE001 - an observer must not break the stream
            pass

    # Lane prefixes keep hunt quota and lab training from starving each other.
    # Providers named th-hunt-* serve live bounty work; th-learn-* serve labs.
    LEARN_AGENTS = frozenset({
        "train", "training", "learn", "learning", "lab", "study", "model-study",
    })

    @staticmethod
    def _lane_for_agent(agent: str) -> str:
        name = str(agent or "").strip().lower()
        if name in ProviderBus.LEARN_AGENTS or name.startswith("train"):
            return "learn"
        return "hunt"

    @staticmethod
    def _order_for_lane(providers: list, lane: str, diversify: bool = False) -> list:
        if lane == "learn":
            primary = [p for p in providers if str(p.name).startswith("th-learn-")]
            shared = [p for p in providers
                      if not str(p.name).startswith(("th-learn-", "th-hunt-"))]
            spare = [p for p in providers if str(p.name).startswith("th-hunt-")]
            return primary + shared + spare
        primary = [p for p in providers if str(p.name).startswith("th-hunt-")]
        shared = [p for p in providers
                  if not str(p.name).startswith(("th-learn-", "th-hunt-"))]
        spare = [p for p in providers if str(p.name).startswith("th-learn-")]
        if diversify and shared:
            # A wall of 20+ tokenharbor lanes can all 429 in one turn. Put the
            # independent catalogues (nvidia, openrouter, local routes) a few
            # lanes in instead of after every hunt key, so one exhausted free
            # quota never silences the brain. The first two lanes keep the
            # primary quota preference.
            head = primary[:2]
            return head + shared + primary[2:] + spare
        return primary + shared + spare

    def _candidates(self, agent: str, exclude_providers=None,
                    diversify: bool = False):
        route = self.config.route_for(agent)
        ordered = self._order_for_lane(
            self.config.ordered_providers(), self._lane_for_agent(agent),
            diversify=diversify)
        if route.provider:
            preferred = [p for p in ordered if p.name == route.provider]
            rest = [p for p in ordered if p.name != route.provider]
            ordered = preferred + rest
        fresh = [p for p in ordered if not self._cooling(p.name)]
        if not fresh:
            # everything is cooling down -- better to try than to stall
            fresh = ordered
        for provider in fresh:
            if exclude_providers and provider.name in exclude_providers:
                continue
            key = provider.resolve_key()
            if not key and provider.name != "ollama" and not _local_endpoint(provider.base_url):
                continue
            models = self._moe_models(provider, agent, route)
            if not models:
                continue
            for model in models:
                if model and not self._model_dead(provider.name, model):
                    yield provider, model, key

    def providers_available(self, agent: str, exclude_providers=None) -> int:
        """How many distinct providers could serve this agent right now."""
        names = {provider.name for provider, _, _ in
                 self._candidates(agent, exclude_providers=exclude_providers)}
        return len(names)

    def chat_stream(self, agent: str, messages: list[dict], on_chunk=None):
        text, _, _ = self.chat_stream_ex(agent, messages, on_chunk=on_chunk)
        return text

    def chat_stream_ex(self, agent: str, messages: list[dict], on_chunk=None,
                       exclude_providers=None):
        """One model call; returns ``(text, provider, model)``.

        ``exclude_providers`` keeps the call off providers that already
        answered a related question, which is how a panel of distinct models
        corroborates a finding.
        """
        route = self.config.route_for(agent)
        budget = getattr(self.config.run, "max_call_seconds", 90)
        call_timeout = min(self.timeout, budget)
        last_error = "no provider available"
        rate_limited: set[str] = set()
        # A 429 soft-retires one model. Allow exactly one sibling on the same
        # catalogue so a key with two real models still rotates, then stop
        # walking the rest: a free catalogue with many aliases would otherwise
        # turn one logical call into a wall of identical 429 attempts.
        siblings_tried: dict[str, int] = {}
        prev_provider = ""
        for provider, model, key in self._candidates(agent,
                                                     exclude_providers=exclude_providers):
            if prev_provider and provider.name != prev_provider and prev_provider in rate_limited:
                self._penalize(prev_provider)
            prev_provider = provider.name
            if provider.name in rate_limited:
                if siblings_tried.get(provider.name, 0) >= 1:
                    continue
                siblings_tried[provider.name] = siblings_tried.get(provider.name, 0) + 1
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
                            # 429 is quota on one free model, not a dead expert.
                            # Soft-retire briefly and walk siblings / other keys.
                            if response.status_code == 429:
                                self._retire(provider.name, model,
                                             ttl=self.RATE_DEAD_TTL)
                                rate_limited.add(provider.name)
                            else:
                                self._strike(provider.name, model, fatal=True)
                                self._penalize(provider.name)
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
                            # An empty reply is rotation, not a dead provider.
                            self._retire(provider.name, model,
                                         ttl=self.RATE_DEAD_TTL)
                            self._observe({"kind": "done", "agent": agent,
                                           "provider": provider.name, "model": model,
                                           "ok": False, "ms": _ms(attempt),
                                           "error": last_error[:140]})
                            continue
                        for name in rate_limited:
                            if name != provider.name:
                                self._penalize(name)
                        self._settle(provider.name, model)
                        self._observe({"kind": "done", "agent": agent,
                                       "provider": provider.name, "model": model,
                                       "ok": True, "ms": _ms(attempt)})
                        return collected, provider.name, model
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
        for name in rate_limited:
            self._penalize(name)
        if on_chunk:
            on_chunk(Chunk("error", last_error))
        return "", "", ""
    def complete(self, agent: str, messages: list[dict], timeout: float = 45.0,
                 exclude_providers=None, max_candidates: int | None = None,
                 validate=None, min_providers: int = 0,
                 max_seconds: float | None = None,
                 diversify: bool = False) -> Completion:
        """One non-streaming call that keeps the provider's usage block.

        The mission runtime needs a bounded call that cannot stream forever and
        that tells it how many tokens a provider reported. Every failure is
        returned, never raised, so a dead provider becomes a recorded error
        instead of a hung agent. ``max_candidates`` caps how far down the
        fallback chain one call may walk. ``min_providers`` keeps that cap from
        cutting the walk before independent catalogues were tried, and
        ``max_seconds`` bounds the whole walk, not just one HTTP request.
        """
        route = self.config.route_for(agent)
        budget = max(1.0, min(float(timeout),
                              float(getattr(self.config.run, "max_call_seconds", 90))))
        started = time.monotonic()
        deadline = (started + float(max_seconds)
                    if max_seconds is not None and float(max_seconds) > 0 else None)
        last_error = "no provider available"
        last_provider = ""
        last_model = ""
        failed: list[str] = []
        rate_limited: set[str] = set()
        siblings_tried: dict[str, int] = {}
        providers_tried: set[str] = set()
        attempts = 0
        prev_provider = ""
        for provider, model, key in self._candidates(
                agent, exclude_providers=exclude_providers,
                diversify=diversify):
            if deadline is not None and time.monotonic() >= deadline:
                last_error = (f"provider budget spent after {float(max_seconds):.0f}s "
                              f"({attempts} attempt(s)); {last_error}")
                break
            if (max_candidates is not None and attempts >= max_candidates
                    and len(providers_tried) >= max(0, int(min_providers))):
                break
            # Cool a rate-limited provider only after we leave it, so sibling
            # models on the same catalogue still get one shot in this walk.
            if prev_provider and provider.name != prev_provider and prev_provider in rate_limited:
                self._penalize(prev_provider)
            prev_provider = provider.name
            # One sibling attempt per catalogue after a 429: enough for a key
            # with two real models, not enough to walk twenty aliases of the
            # same throttled free expert.
            if provider.name in rate_limited:
                if siblings_tried.get(provider.name, 0) >= 1:
                    continue
                siblings_tried[provider.name] = siblings_tried.get(provider.name, 0) + 1
            if self._cooling(provider.name):
                continue
            attempts += 1
            providers_tried.add(provider.name)
            last_provider, last_model = provider.name, model
            attempt = time.monotonic()
            attempt_budget = budget
            if deadline is not None:
                attempt_budget = max(1.0, min(budget, deadline - attempt))
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
                "stream": False,
            }
            self._observe({"kind": "call", "agent": agent,
                           "provider": provider.name, "model": model})
            try:
                with httpx.Client(timeout=attempt_budget, proxy=proxy) as client:
                    response = client.post(f"{provider.base_url}/chat/completions",
                                           headers=headers, json=payload)
                    if response.status_code in (403, 429):
                        if self.egress and proxy:
                            self.egress.mark_failed(proxy)
                        # 429: soft-retire this free model briefly and keep
                        # walking MoE siblings / other keys. Do not treat it
                        # as a hard provider death that gates the whole hunt.
                        if response.status_code == 429:
                            # Soft quota: retire this model briefly and keep
                            # walking siblings. Do not record a hard failure -
                            # that parked the whole key and froze the mission.
                            self._retire(provider.name, model,
                                         ttl=self.RATE_DEAD_TTL)
                            rate_limited.add(provider.name)
                        else:
                            self._strike(provider.name, model, fatal=True)
                            self._penalize(provider.name)
                            failed.append(provider.name)
                        last_error = f"{provider.name} returned {response.status_code}"
                        self._observe({"kind": "done", "agent": agent,
                                       "provider": provider.name, "model": model,
                                       "ok": False, "ms": _ms(attempt),
                                       "error": f"HTTP {response.status_code}"})
                        continue
                    if response.status_code >= 400:
                        self._strike(provider.name, model,
                                     fatal=response.status_code in (400, 404))
                        if response.status_code in (401, 402):
                            failed.append(provider.name)
                        last_error = f"{provider.name} returned {response.status_code}"
                        self._observe({"kind": "done", "agent": agent,
                                       "provider": provider.name, "model": model,
                                       "ok": False, "ms": _ms(attempt),
                                       "error": f"HTTP {response.status_code}"})
                        continue
                    data = response.json()
                    if not isinstance(data, dict):
                        last_error = f"{provider.name} returned a non-object body"
                        self._strike(provider.name, model)
                        continue
                    if data.get("error"):
                        last_error = f"{provider.name}: {str(data['error'])[:140]}"
                        self._strike(provider.name, model)
                        continue
                    choices = data.get("choices") or []
                    first = choices[0] if choices and isinstance(choices[0], dict) else {}
                    message = first.get("message") or {}
                    content = message.get("content")
                    if isinstance(content, list):
                        content = "".join(
                            str(part.get("text", "")) for part in content
                            if isinstance(part, dict))
                    text = str(content or "").strip()
                    if not text:
                        last_error = f"{provider.name}/{model} returned no content"
                        # Empty bodies rotate to the next model immediately.
                        # A short retire keeps the next call off this id too.
                        self._retire(provider.name, model, ttl=self.RATE_DEAD_TTL)
                        self._observe({"kind": "done", "agent": agent,
                                       "provider": provider.name, "model": model,
                                       "ok": False, "ms": _ms(attempt),
                                       "error": last_error[:140]})
                        continue
                    usage = data.get("usage")
                    # A censored, confused, or prose-only model is a failed
                    # candidate, not an answer. When the caller needs a shape,
                    # an invalid reply rotates to the next provider/model
                    # instead of stopping the run.
                    if validate is not None:
                        try:
                            valid = bool(validate(text))
                        except Exception:  # noqa: BLE001 - a bad validator rotates
                            valid = False
                        if not valid:
                            last_error = (f"{provider.name}/{model} reply failed "
                                          "validation")
                            self._strike(provider.name, model)
                            self._observe({"kind": "done", "agent": agent,
                                           "provider": provider.name,
                                           "model": model, "ok": False,
                                           "ms": _ms(attempt),
                                           "error": "invalid reply"})
                            continue
                    # Cool other providers that 429'd; the one that answered
                    # settles so a working catalogue is not locked out.
                    for name in rate_limited:
                        if name != provider.name:
                            self._penalize(name)
                    self._settle(provider.name, model)
                    self._observe({"kind": "done", "agent": agent,
                                   "provider": provider.name, "model": model,
                                   "ok": True, "ms": _ms(attempt)})
                    return Completion(text=text, provider=provider.name, model=model,
                                      usage=usage if isinstance(usage, dict) else {},
                                      duration_ms=_ms(started))
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
        for name in rate_limited:
            self._penalize(name)
        return Completion(error=last_error, provider=last_provider,
                          model=last_model, failed=failed,
                          duration_ms=_ms(started))


_SHARED_BUS: ProviderBus | None = None
_SHARED_BUS_KEY: tuple | None = None
_SHARED_BUS_LOCK = threading.Lock()


def shared_bus(config, timeout: float = 45.0) -> ProviderBus:
    """Reuse one bus while the provider configuration is unchanged.

    A fresh bus on every brain turn forgot every 429 it had just learned, so
    each turn walked the same dead lanes in the same order. A live bus keeps
    the cooldown and retired-model maps useful across turns.
    """
    global _SHARED_BUS, _SHARED_BUS_KEY
    key = tuple(sorted(
        (str(p.name), str(p.base_url), int(p.priority),
         tuple(str(m) for m in (p.models or [])), p.resolve_key())
        for p in config.providers))
    with _SHARED_BUS_LOCK:
        if _SHARED_BUS is None or _SHARED_BUS_KEY != key:
            _SHARED_BUS = ProviderBus(config, timeout=timeout)
            _SHARED_BUS_KEY = key
        else:
            _SHARED_BUS.config = config
        return _SHARED_BUS
