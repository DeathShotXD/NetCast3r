"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import inputs
from .config import load_config
from .orchestrator import Orchestrator
from .recon import Recon
from .report import save_sarif
from .scope import ScopeManager
from .store import Store


def _load_seeds(value: str, use_stdin: bool = False) -> list[str]:
    seeds: list[str] = []
    if use_stdin:
        seeds.extend(line.strip() for line in sys.stdin
                     if line.strip() and not line.startswith("#"))
    if value:
        path = Path(value)
        if path.exists() and path.is_file():
            seeds.extend(line.strip() for line in path.read_text().splitlines()
                         if line.strip() and not line.startswith("#"))
        else:
            seeds.append(value)
    return seeds


def _apply_options(config, args) -> None:
    run = config.run
    if getattr(args, "depth", None):
        run.depth = args.depth
    if getattr(args, "tier", None):
        run.action_tier = args.tier
    if getattr(args, "patterns", None):
        run.patterns_file = args.patterns
    if getattr(args, "recipes", None):
        run.recipes_file = args.recipes
    if getattr(args, "rate", None):
        run.requests_per_second = args.rate
    if getattr(args, "delay", None):
        run.delay = args.delay
    if getattr(args, "retries", None) is not None:
        run.retries = args.retries
    if getattr(args, "timeout", None):
        run.timeout = args.timeout
    if getattr(args, "max_response_size", None):
        run.max_response_size = args.max_response_size
    if getattr(args, "user_agent", None):
        run.user_agent = args.user_agent
    if getattr(args, "random_agent", False):
        run.random_user_agent = True
    if getattr(args, "no_color", False):
        run.color = False
    if getattr(args, "jsonl", False):
        run.output_format = "jsonl"
    elif getattr(args, "json", False):
        run.output_format = "json"
    if getattr(args, "silent", False):
        run.verbosity = 0
    elif getattr(args, "verbose", 0) >= 2:
        run.verbosity = 2
    elif getattr(args, "verbose", 0) == 1:
        run.verbosity = 1


def _prepare(args):
    config = load_config(Path(args.config) if getattr(args, "config", None) else None)
    _apply_options(config, args)
    seeds = _load_seeds(getattr(args, "input", "") or "", getattr(args, "stdin", False))
    scope = ScopeManager.from_files(args.scope, args.out_of_scope, extra_in=seeds)
    return config, seeds, scope


def cmd_recon(args) -> int:
    config, seeds, scope = _prepare(args)
    if not seeds:
        print("no input given")
        return 1
    recon = Recon(scope, config)
    result = recon.crawl(seeds)
    result.historical = recon.wayback(seeds[0].split("//")[-1].split("/")[0]) if seeds else []

    out = Path(args.out or "results")
    store = Store(out / "netcast3r.db")
    for url in result.pages:
        store.add_asset(url, "page", 200)
    for url in result.js_urls:
        store.add_js(url, result.js_text.get(url, ""))
    for url in result.endpoints:
        store.add_endpoint(url, "js")
    for url in result.historical:
        store.add_asset(url, "historical", 0)
    counts = store.counts()
    store.close()

    print(f"pages found      : {len(result.pages)}")
    print(f"js files found   : {len(result.js_urls)}")
    print(f"endpoints found  : {len(result.endpoints)}")
    print(f"historical urls  : {len(result.historical)}")
    print(f"skipped out scope: {len(result.out_of_scope)}")
    print(f"evidence store   : {out / 'netcast3r.db'}")
    print(f"rows             : {counts}")
    tools = recon.external_tools()
    print(f"external tools   : {', '.join(tools) if tools else 'none, built-in crawler in use'}")
    return 0


def cmd_run(args) -> int:
    config = load_config(Path(args.config) if getattr(args, "config", None) else None)
    _apply_options(config, args)

    source = None
    if getattr(args, "input", None):
        candidate = Path(args.input)
        if candidate.exists() and candidate.is_file():
            try:
                source = inputs.load(candidate)
            except Exception:
                source = None
    seeds = source.urls if (source and source.urls) else _load_seeds(
        getattr(args, "input", "") or "", getattr(args, "stdin", False))
    if not seeds:
        print("no input given")
        return 1

    scope = ScopeManager.from_files(args.scope, args.out_of_scope, extra_in=seeds)
    out = Path(args.out or "results")
    store = Store(out / "netcast3r.db")
    orchestrator = Orchestrator(config, scope, store,
                                seed_bodies=(source.bodies if source else None))
    summary = orchestrator.run(seeds)
    if getattr(args, "sarif", False):
        save_sarif(out, orchestrator.last_findings)
    store.close()
    if getattr(args, "fail", False) and summary.findings > 0:
        return 1
    return 0


def cmd_providers(args) -> int:
    config = load_config(Path(args.config) if args.config else None)
    print("providers, in priority order:")
    for provider in config.ordered_providers():
        key_state = "key set" if provider.resolve_key() else "no key"
        print(f"  {provider.priority:>4}  {provider.name:<12} {provider.base_url}  ({key_state})")
    print("")
    print("routes:")
    for route in config.routes:
        print(f"  {route.agent:<11} {route.provider:<12} {route.model}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netcast3r",
        description="Cast a net over the web: crawl a target, read its JavaScript, "
                    "hunt secrets, validate them, and write the report.",
    )
    parser.add_argument("--version", action="version", version=f"netcast3r {__version__}")
    sub = parser.add_subparsers(dest="command")

    def common(p):
        p.add_argument("--input", help="a domain, a URL, or a file of them")
        p.add_argument("--stdin", action="store_true", help="read targets from standard input")
        p.add_argument("--scope", help="in-scope file, one entry per line")
        p.add_argument("--out-of-scope", help="out-of-scope file, one entry per line")
        p.add_argument("--out", help="output directory (default: results)")
        p.add_argument("--depth", type=int, help="crawl depth")
        p.add_argument("--tier", choices=["read", "write", "full"], help="action tier")
        p.add_argument("--patterns", help="path to a custom secret patterns file")
        p.add_argument("--recipes", help="path to a custom validation recipes file")
        p.add_argument("--rate", type=float, help="requests per second")
        p.add_argument("--delay", type=float, help="seconds between requests")
        p.add_argument("--retries", type=int, help="retries per request")
        p.add_argument("--timeout", type=float, help="request timeout in seconds")
        p.add_argument("--max-response-size", type=int, help="cap on a single response body")
        p.add_argument("--user-agent", help="custom user agent")
        p.add_argument("--random-agent", action="store_true", help="rotate a browser user agent")
        p.add_argument("--no-color", action="store_true", help="disable colored output")
        p.add_argument("--json", action="store_true", help="also write results.json")
        p.add_argument("--jsonl", action="store_true", help="also write results.jsonl")
        p.add_argument("--sarif", action="store_true", help="also write results.sarif")
        p.add_argument("--silent", action="store_true", help="quiet output")
        p.add_argument("-v", "--verbose", action="count", default=0, help="raise verbosity")
        p.add_argument("--fail", action="store_true", help="exit non-zero when findings exist")
        p.add_argument("--config", help="path to a config file")

    recon_parser = sub.add_parser("recon", help="crawl and collect assets only")
    common(recon_parser)
    recon_parser.set_defaults(func=cmd_recon)

    run_parser = sub.add_parser("run", help="full run: crawl, hunt, validate, report")
    common(run_parser)
    run_parser.set_defaults(func=cmd_run)

    providers_parser = sub.add_parser("providers", help="show providers and routes")
    providers_parser.add_argument("--config", help="path to a config file")
    providers_parser.set_defaults(func=cmd_providers)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
