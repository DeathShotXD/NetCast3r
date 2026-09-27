"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .recon import Recon
from .scope import ScopeManager
from .secrets import Extractor
from .store import Store
from .validate import Validator, load_recipes


def _load_seeds(value: str) -> list[str]:
    path = Path(value)
    if path.exists() and path.is_file():
        return [line.strip() for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#")]
    return [value]


def _prepare(args):
    config = load_config(Path(args.config) if getattr(args, "config", None) else None)
    if getattr(args, "depth", None):
        config.run.depth = args.depth
    if getattr(args, "tier", None):
        config.run.action_tier = args.tier
    seeds = _load_seeds(args.input)
    scope = ScopeManager.from_files(args.scope, args.out_of_scope, extra_in=seeds)
    return config, seeds, scope


def cmd_recon(args) -> int:
    config, seeds, scope = _prepare(args)
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
    config, seeds, scope = _prepare(args)
    recon = Recon(scope, config)
    result = recon.crawl(seeds)

    out = Path(args.out or "results")
    store = Store(out / "netcast3r.db")
    for url in result.pages:
        store.add_asset(url, "page", 200)
    for url in result.js_urls:
        store.add_js(url, result.js_text.get(url, ""))
        store.add_endpoint(url, "js")

    extractor = Extractor()
    validator = Validator(recipes=load_recipes(), tier=config.run.action_tier,
                          timeout=config.run.timeout)

    secrets_found = []
    for url, text in result.js_text.items():
        for secret in extractor.scan(text, source=url):
            secrets_found.append(secret)
            store.add_secret(secret.type, secret.value, secret.source, secret.context)
            store.add_endpoint(secret.value if secret.value.startswith("/") else url, "secret-context")

    print(f"pages found      : {len(result.pages)}")
    print(f"js files found   : {len(result.js_urls)}")
    print(f"candidates found : {len(secrets_found)}")
    print("")

    verified = 0
    for secret in secrets_found:
        validation = validator.validate(secret.type, secret.value, secret.source)
        store.add_validation(secret.type, secret.value, validation.status,
                             validation.provider, validation.detail, validation.evidence)
        marker = {"verified": "LIVE", "unverified": "dead", "unknown": "unknown", "skipped": "held"}.get(
            validation.status, validation.status)
        print(f"  [{marker}] {secret.type}: {secret.value[:16]}...  ({validation.detail})")
        if validation.status == "verified":
            verified += 1
            store.add_finding(
                title=f"{validation.provider} credential exposed in JavaScript",
                severity="high",
                secret_type=secret.type,
                value=secret.value,
                impact=f"live {secret.type} credential found in {secret.source}",
                evidence=validation.evidence,
            )

    counts = store.counts()
    store.close()
    print("")
    print(f"live credentials : {verified}")
    print(f"evidence store   : {out / 'netcast3r.db'}")
    print(f"rows             : {counts}")
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
        p.add_argument("--input", required=True, help="a domain, a URL, or a file of them")
        p.add_argument("--scope", help="in-scope file, one entry per line")
        p.add_argument("--out-of-scope", help="out-of-scope file, one entry per line")
        p.add_argument("--out", help="output directory (default: results)")
        p.add_argument("--depth", type=int, help="crawl depth")
        p.add_argument("--tier", choices=["read", "write", "full"], help="action tier")
        p.add_argument("--config", help="path to a config file")

    recon_parser = sub.add_parser("recon", help="crawl and collect assets only")
    common(recon_parser)
    recon_parser.set_defaults(func=cmd_recon)

    run_parser = sub.add_parser("run", help="full run: crawl, hunt, validate")
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
