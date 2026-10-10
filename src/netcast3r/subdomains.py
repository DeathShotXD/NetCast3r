"""Subdomain mapping.

Before the crawler walks a host, this maps the names that host answers to.
Certificate transparency logs and passive DNS give the names that were ever
published, and a built-in wordlist covers the obvious ones DNS still resolves.
Every candidate is checked against scope, and a wildcard DNS answer is found
first so the brute pass does not report the same catch-all record for every
word.
"""

from __future__ import annotations

import ipaddress
import json
import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
OTX_URL = ("https://otx.alienvault.com/api/v1/indicators/domain/"
           "{domain}/passive_dns")
BRUTE_WORKERS = 16
PROBE_LEN = 20

BUILTIN_WORDS = (
    "www", "api", "app", "apps", "app2", "portal", "dashboard", "console",
    "panel", "manage", "admin", "administrator", "cpanel", "webmail", "mail",
    "smtp", "imap", "pop", "mx", "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "cdn", "static", "assets", "asset", "media", "img", "images", "files",
    "upload", "uploads", "download", "downloads", "docs", "doc", "help",
    "support", "status", "stats", "monitor", "metrics", "grafana", "kibana",
    "prometheus", "jenkins", "ci", "cd", "build", "git", "gitlab", "github",
    "bitbucket", "repo", "registry", "docker", "k8s", "kube", "dev", "develop",
    "development", "stage", "staging", "stg", "test", "testing", "qa", "uat",
    "demo", "sandbox", "beta", "alpha", "canary", "preview", "old", "legacy",
    "vpn", "remote", "gateway", "gw", "proxy", "sso", "auth", "login",
    "signin", "account", "accounts", "id", "identity", "oauth", "internal",
    "intranet", "int", "corp", "wiki", "jira", "confluence", "teams", "vault",
    "secrets", "config", "db", "database", "mysql", "postgres", "redis",
    "mongo", "elastic", "cache", "queue", "mq", "kafka", "v1", "v2", "m",
    "mobile", "wap", "shop", "store", "checkout", "pay", "payments", "billing",
    "invoice", "crm", "erp", "hr", "api-dev", "api-staging", "api-test",
)


def _dns(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


class SubdomainFinder:
    def __init__(self, scope, config, session, resolver=None):
        self.scope = scope
        self.config = config
        self.session = session
        self.resolve = resolver or _dns
        self.limit = max(1, int(getattr(config.run, "subdomain_limit", 300) or 300))

    @staticmethod
    def domains(seeds) -> list[str]:
        found: list[str] = []
        for seed in seeds:
            url = seed if "://" in seed else "https://" + seed
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
            if not host or host in found:
                continue
            try:
                ipaddress.ip_address(host)
                continue
            except ValueError:
                pass
            found.append(host)
        return found

    def _words(self) -> list[str]:
        path = getattr(self.config.run, "subdomain_wordlist", "")
        if path and Path(path).exists():
            lines = Path(path).read_text(errors="ignore").splitlines()
            words = [line.strip().lower() for line in lines
                     if line.strip() and not line.strip().startswith("#")]
            if words:
                return words
        return list(BUILTIN_WORDS)

    def _crt(self, domain: str) -> set[str]:
        if self.session is None:
            return set()
        response = self.session.get(CRT_URL.format(domain=domain))
        if response is None or response.status_code != 200 or not response.text:
            return set()
        try:
            rows = json.loads(response.text)
        except ValueError:
            return set()
        if not isinstance(rows, list):
            return set()
        names: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            for field in ("name_value", "common_name"):
                for name in str(row.get(field) or "").splitlines():
                    name = name.strip().lower().lstrip("*.").rstrip(".")
                    if name == domain or name.endswith("." + domain):
                        names.add(name)
        return names

    def _otx(self, domain: str) -> set[str]:
        if self.session is None:
            return set()
        response = self.session.get(OTX_URL.format(domain=domain))
        if response is None or response.status_code != 200 or not response.text:
            return set()
        try:
            data = json.loads(response.text)
        except ValueError:
            return set()
        if not isinstance(data, dict):
            return set()
        names: set[str] = set()
        for row in data.get("passive_dns") or []:
            if not isinstance(row, dict):
                continue
            host = str(row.get("hostname") or "").strip().lower().rstrip(".")
            if host == domain or host.endswith("." + domain):
                names.add(host)
        return names

    def _wildcard(self, domain: str) -> bool:
        probe = "".join(random.choices(string.ascii_lowercase, k=PROBE_LEN))
        return bool(self.resolve(f"{probe}.{domain}"))

    def _brute(self, domain: str) -> set[str]:
        words = self._words()
        if not words or self._wildcard(domain):
            return set()
        names: set[str] = set()
        workers = min(BRUTE_WORKERS, max(1, len(words)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.resolve, f"{word}.{domain}"): word
                       for word in words}
            for future in as_completed(futures):
                try:
                    if future.result():
                        names.add(f"{futures[future]}.{domain}")
                except Exception:
                    continue
        return names

    def find(self, seeds) -> list[str]:
        hosts = self.domains(seeds)
        names: set[str] = set()
        for domain in hosts:
            names |= self._crt(domain)
            names |= self._otx(domain)
        for domain in hosts:
            names |= self._brute(domain)
        ordered = sorted(
            name for name in names
            if name not in hosts and self.scope.is_in_scope("https://" + name)
        )
        return ordered[: self.limit]
