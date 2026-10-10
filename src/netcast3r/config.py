"""Configuration loading.

Settings live in ~/.netcast3r/config.toml. Anything missing falls back to the
built-in defaults, so the tool runs with no configuration at all. API keys are
read from the environment by default so they never sit in the config file.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


HOME = Path.home() / ".netcast3r"
CONFIG_FILE = HOME / "config.toml"

AGENTS = ("recon", "exegete", "prospector", "classifier", "assayer", "chainer", "scribe", "sentinel")


@dataclass
class ProviderConfig:
    name: str
    base_url: str
    api_key: str = ""
    api_key_env: str = ""
    priority: int = 100
    rate_limit_rpm: int = 0
    proxy_policy: str = "rotate"
    models: list[str] = field(default_factory=list)

    def resolve_key(self) -> str:
        if self.api_key:
            return self.api_key
        if self.api_key_env:
            return os.environ.get(self.api_key_env, "")
        return ""


@dataclass
class RouteConfig:
    agent: str
    model: str = ""
    provider: str = ""
    temperature: float = 0.2
    max_tokens: int = 1024
    reasoning: bool = True


@dataclass
class EgressConfig:
    user_proxies: list[str] = field(default_factory=list)
    use_public: bool = True
    public_sources: list[str] = field(default_factory=list)
    health_url: str = "https://api.ipify.org"
    rotate_on: list[int] = field(default_factory=lambda: [403, 429, 500, 502, 503])


@dataclass
class ScopeConfig:
    in_scope: str = ""
    out_of_scope: str = ""


@dataclass
class RunConfig:
    concurrency: int = 20
    timeout: float = 15.0
    depth: int = 2
    action_tier: str = "read"
    user_agent: str = "Mozilla/5.0 (compatible; NetCast3r)"
    patterns_file: str = ""
    recipes_file: str = ""
    requests_per_second: float = 0.0
    delay: float = 0.0
    retries: int = 2
    max_response_size: int = 5_000_000
    stop_on_rate_limit: bool = True
    random_user_agent: bool = False
    user_agents: list[str] = field(default_factory=list)
    verbosity: int = 1
    color: bool = True
    output_format: str = "markdown"
    write_json: bool = False
    write_jsonl: bool = False
    allow_model_checks: bool = True
    max_call_seconds: int = 90
    wayback: bool = True
    wayback_limit: int = 2000
    wayback_js_max: int = 25
    subdomains: bool = True
    subdomain_wordlist: str = ""
    subdomain_limit: int = 300


@dataclass
class Config:
    providers: list[ProviderConfig] = field(default_factory=list)
    routes: list[RouteConfig] = field(default_factory=list)
    egress: EgressConfig = field(default_factory=EgressConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    run: RunConfig = field(default_factory=RunConfig)

    def route_for(self, agent: str) -> RouteConfig:
        for route in self.routes:
            if route.agent == agent:
                return route
        return RouteConfig(agent=agent, model="")

    def provider(self, name: str) -> ProviderConfig | None:
        for provider in self.providers:
            if provider.name == name:
                return provider
        return None

    def ordered_providers(self) -> list[ProviderConfig]:
        return sorted(self.providers, key=lambda item: item.priority)


def default_config() -> Config:
    providers = [
        ProviderConfig(
            name="openrouter",
            base_url="https://openrouter.ai/api/v1",
            api_key_env="NETCAST3R_OPENROUTER_KEY",
            priority=10,
            models=[
                "qwen/qwen3.8-27b:free",
                "nvidia/nemotron-3.5-lightning:free",
                "google/gemma-4-31b-it:free",
            ],
        ),
        ProviderConfig(
            name="ollama",
            base_url="http://127.0.0.1:11434/v1",
            priority=20,
            models=["llama3:8b"],
        ),
        ProviderConfig(
            name="opencode",
            base_url="https://opencode.ai/zen/v1",
            api_key_env="NETCAST3R_OPENCODE_KEY",
            priority=30,
            models=["mimo-v2.6-flash-free", "big-pickle"],
        ),
    ]
    routes = [
        RouteConfig(agent=agent, model="", provider="")
        for agent in AGENTS
    ]
    egress = EgressConfig(
        public_sources=[
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        ]
    )
    return Config(providers=providers, routes=routes, egress=egress)


def _build(cls, data: dict):
    fields = {f.name for f in dataclasses.fields(cls)}
    return cls(**{key: value for key, value in data.items() if key in fields})


def _apply(config: Config, data: dict) -> None:
    if "providers" in data:
        config.providers = [_build(ProviderConfig, row) for row in data["providers"]]
    if "routes" in data:
        config.routes = [_build(RouteConfig, row) for row in data["routes"]]
    if "egress" in data:
        config.egress = _build(EgressConfig, data["egress"])
    if "scope" in data:
        config.scope = _build(ScopeConfig, data["scope"])
    if "run" in data:
        config.run = _build(RunConfig, data["run"])


def load_config(path: Path | None = None) -> Config:
    config = default_config()
    target = path or CONFIG_FILE
    if not target.exists():
        return config
    with open(target, "rb") as handle:
        data = tomllib.load(handle)
    _apply(config, data)
    return config
