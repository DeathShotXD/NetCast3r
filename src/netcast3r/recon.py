"""Recon fabric.

Crawls from the seeds, stays inside scope, collects JavaScript, and pulls
historical URLs from the Wayback Machine. External tools (katana, gau,
waybackurls, jsleak) are used when they are installed, otherwise the built-in
crawler runs.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
from dataclasses import dataclass, field
from urllib.parse import unquote, urljoin, urlsplit

from .http import Session
from .subdomains import SubdomainFinder

LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.I)
JS_REF_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""", re.I)
JS_IMPORT_RE = re.compile(r"""(?:import\s*\(\s*|from\s*|require\(\s*)["']([^"']+\.js)(?:\?[^"']*)?["']""")
# any quoted string that names a script, anywhere in the body: webpack chunk
# tables, vite asset maps, service-worker precache lists
QUOTED_JS_RE = re.compile(
    r"""["'`]([^"'\s`\\]{1,240}?\.(?:js|mjs|cjs|jsx)(?:\?[^"'\s`\\]{0,120})?)["'`]""", re.I)
# module specifiers, with or without an extension: static/dynamic imports,
# workers, workers loading their own scripts, and URL constructors
MODULE_REF_RE = re.compile(
    r"""(?:import\s*\(\s*|from\s*|require\(\s*|importScripts\(\s*|"""
    r"""new\s+(?:Shared)?Worker\(\s*|new\s+URL\(\s*)"""
    r"""["']([^"'\s]{1,300})["']""")
ENDPOINT_RE = re.compile(r"""["'](/[A-Za-z0-9_\-./]{2,}(?:\?[A-Za-z0-9_\-=&%]*)?)["']""")
SOURCE_MAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=(\S+)""")
INLINE_SCRIPT_RE = re.compile(r"""<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>""",
                              re.I | re.S)
MAX_SOURCE_MAP = 8_000_000
JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx")


def _is_js_url(url: str) -> bool:
    return url.split("?")[0].lower().endswith(JS_EXTENSIONS)


def js_children(base_url: str, text: str, cap: int = 60) -> list[str]:
    """Every script this body references, resolved to absolute URLs.

    Two passes: any quoted string ending in a script extension (which is how
    bundlers name their chunks), then module specifiers that may carry no
    extension at all -- ``import("./panel")`` -- expanded to the plausible
    file names.
    """
    found: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        if candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)

    for spec in QUOTED_JS_RE.findall(text):
        if spec.startswith(("data:", "blob:", "javascript:", "mailto:", "#")):
            continue
        add(_absolute(base_url, spec))
    for spec in MODULE_REF_RE.findall(text):
        if not spec.startswith((".", "/")) or spec.startswith("//"):
            continue
        resolved = _absolute(base_url, spec)
        if _is_js_url(resolved):
            add(resolved)
            continue
        add(resolved + ".js")
        add(resolved.rstrip("/") + "/index.js")
    return found[:cap]


def inline_scripts(page_text: str, minimum: int = 16) -> list[str]:
    """Bodies of inline ``<script>`` blocks big enough to be worth scanning."""
    blocks = []
    for body in INLINE_SCRIPT_RE.findall(page_text or ""):
        body = body.strip()
        if len(body) >= minimum:
            blocks.append(body[:60000])
    return blocks

SPEC_PATHS = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
              "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
              "/api/openapi.json", "/.well-known/openapi.json")
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graph")
GRAPHQL_QUERY = {"query": "{__schema{queryType{name} mutationType{name}}}"}
WELLKNOWN_PATHS = ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
                   "/sitemap-index.xml")
DISALLOW_RE = re.compile(r"(?im)^\s*disallow:\s*(\S+)")
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
SCHEME_RE = re.compile(r"(?i)^[a-z][a-z0-9+.\-]*:")
REDIRECT_CODES = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 6
MAX_SITEMAP_LOCS = 500
ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2",
             ".ico", ".mp4", ".webm", ".pdf", ".zip")


@dataclass
class ReconResult:
    pages: list = field(default_factory=list)
    js_urls: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    historical: list = field(default_factory=list)
    js_text: dict = field(default_factory=dict)
    page_text: dict = field(default_factory=dict)
    out_of_scope: list = field(default_factory=list)


def _absolute(base: str, link: str) -> str:
    return urljoin(base, link)


class Recon:
    def __init__(self, scope, config, session: Session | None = None, on_fetch=None,
                 resolver=None):
        self.scope = scope
        self.config = config
        self.session = session or Session(config)
        self.max_depth = config.run.depth
        configured_pages = int(getattr(config.run, "max_pages", 0) or 0)
        if configured_pages > 0:
            self.max_pages = configured_pages
        else:
            # Older configs had no max_pages; keep a useful ceiling based on
            # the request concurrency instead of ignoring the crawler limit.
            self.max_pages = max(config.run.concurrency * 25, 100)
        # on_fetch(kind, url, status): kind is page | js | skip. The dashboard
        # feeds this straight into its live crawler panel.
        self.on_fetch = on_fetch
        self.resolver = resolver

    def expand_seeds(self, seeds: list[str]) -> list[str]:
        """Map the subdomains of each seed host and return them as new seeds.

        Returns https roots for every in-scope subdomain, so the crawler walks
        each one and collects its JavaScript. An empty list means the stage is
        off or the target is an address with no names to map.
        """
        if not getattr(self.config.run, "subdomains", False):
            return []
        for seed in seeds:
            self.scope.add_seed(seed if "://" in seed else "https://" + seed)
        finder = SubdomainFinder(self.scope, self.config, self.session,
                                 resolver=self.resolver)
        hosts = finder.find(seeds)
        existing = {urlsplit(s if "://" in s else "https://" + s).hostname
                    for s in seeds}
        return [f"https://{host}" for host in hosts if host not in existing]

    def _fetch(self, url: str):
        current = url
        for _ in range(MAX_REDIRECTS):
            response = self.session.get(current, follow_redirects=False)
            if response is None:
                return 0, "", ""
            content_type = response.headers.get("content-type", "")
            if response.status_code not in REDIRECT_CODES:
                return response.status_code, response.text, content_type
            location = response.headers.get("location", "")
            if not location:
                return response.status_code, response.text, content_type
            nxt = _absolute(current, location)
            if not self.scope.is_in_scope(nxt):
                # a redirect left scope: refuse the body rather than fetch internal
                return 0, "", ""
            current = nxt
        return 0, "", ""

    def _source_map(self, base_url: str, js_text: str):
        """Recover original sources from a source map, when one is referenced.

        The map carries ``sourcesContent``: the pre-build source, with the
        internal paths and string literals that minification keeps out of the
        served file. Inline ``data:`` maps are decoded in place, remote maps
        are fetched only while in scope.
        """
        match = SOURCE_MAP_RE.search(js_text)
        if not match:
            return None
        ref = match.group(1).strip().strip('"').strip("'")
        if ref.startswith("data:"):
            map_url = base_url + "#sourcemap"
            header, _, payload = ref.partition(",")
            try:
                raw = (base64.b64decode(payload).decode("utf-8", "ignore")
                       if "base64" in header else unquote(payload))
            except Exception:
                return None
        else:
            map_url = _absolute(base_url, ref)
            if not self.scope.is_in_scope(map_url):
                return None
            response = self.session.get(map_url, follow_redirects=False)
            if response is None or not response.text:
                return None
            raw = response.text
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        contents = [c for c in (data.get("sourcesContent") or []) if isinstance(c, str)]
        if not contents:
            return None
        return map_url, "\n".join(contents)[:MAX_SOURCE_MAP]

    @staticmethod
    def _roots(seeds: list[str]) -> list[str]:
        roots = []
        for seed in seeds:
            url = seed if "://" in seed else "https://" + seed
            try:
                parts = urlsplit(url)
            except ValueError:
                continue
            if parts.scheme and parts.netloc:
                roots.append(parts.scheme + "://" + parts.netloc)
        return sorted(set(roots))

    def _spec_paths(self, url: str) -> list[str]:
        """Read an OpenAPI document and return the paths it declares."""
        response = self.session.get(url, follow_redirects=False)
        if response is None or response.status_code != 200 or not response.text:
            return []
        try:
            data = json.loads(response.text)
        except ValueError:
            return []
        paths = data.get("paths") if isinstance(data, dict) else None
        if not isinstance(paths, dict):
            return []
        return [_absolute(url, path) for path in paths if isinstance(path, str)]

    def _graphql_open(self, url: str) -> bool:
        """True when the endpoint answers an introspection query."""
        response = self.session.request("POST", url, json=GRAPHQL_QUERY, follow_redirects=False)
        if response is None or not response.text:
            return False
        return "__schema" in response.text or "queryType" in response.text

    def discover_apis(self, seeds: list[str]) -> list[str]:
        """Probe each seed host for an API description or an open GraphQL endpoint.

        An OpenAPI document lists paths that are never linked from the
        JavaScript. An open introspection result means the GraphQL root and its
        mutations are reachable, so the endpoint is worth carrying.
        """
        found: list[str] = []
        for root in self._roots(seeds):
            for path in SPEC_PATHS:
                url = root + path
                if self.scope.is_in_scope(url):
                    found.extend(self._spec_paths(url))
            for path in GRAPHQL_PATHS:
                url = root + path
                if self.scope.is_in_scope(url) and self._graphql_open(url):
                    found.append(url)
        return sorted(set(found))

    def discover_wellknown(self, seeds: list[str]) -> list[str]:
        """Read robots.txt and sitemaps for paths the site does not link.

        A ``Disallow`` line is a written list of the paths an operator would
        rather not advertise, and a sitemap enumerates the rest.
        """
        found: list[str] = []
        for root in self._roots(seeds):
            for path in WELLKNOWN_PATHS:
                url = root + path
                if not self.scope.is_in_scope(url):
                    continue
                response = self.session.get(url, follow_redirects=False)
                if response is None or response.status_code != 200 or not response.text:
                    continue
                text = response.text
                for entry in DISALLOW_RE.findall(text):
                    if entry and entry != "/":
                        candidate = _absolute(url, entry)
                        if self.scope.is_in_scope(candidate):
                            found.append(candidate)
                for loc in LOC_RE.findall(text)[:MAX_SITEMAP_LOCS]:
                    if self.scope.is_in_scope(loc):
                        found.append(loc)
        return sorted(set(found))

    def js_children(self, base_url: str, text: str, cap: int = 60) -> list[str]:
        return js_children(base_url, text, cap=cap)

    def crawl(self, seeds: list[str], should_stop=None, resume=None,
              on_discover=None, on_checkpoint=None) -> ReconResult:
        """Walk the site from the seeds, staying inside scope.

        ``resume`` is a ``(queue, seen, result)`` triple from a checkpoint: the
        result keeps what was already collected and the walk continues where
        it stopped. ``on_discover(kind, url, text)`` fires for each new page,
        script, endpoint, or out-of-scope URL as it lands, and
        ``on_checkpoint(state)`` fires every few fetches with the remaining
        queue and the seen set, so a stopped scan can start again without
        re-fetching anything.
        """
        if resume is not None:
            raw_queue, raw_seen, result = resume
            queue: list[tuple[str, int]] = [(str(url), int(depth)) for url, depth in raw_queue]
            seen: set[str] = set(raw_seen)
        else:
            result = ReconResult()
            queue = []
            for seed in seeds:
                url = seed if "://" in seed else "https://" + seed
                self.scope.add_seed(url)
                queue.append((url, 0))
            seen = set()

        known_endpoints = set(result.endpoints)
        fetched = 0
        tick = 0
        if int(getattr(self.config.run, "max_pages", 0) or 0) <= 0:
            # Auto mode keeps the old behaviour of making room for every seed.
            # An explicit max_pages is a hard cap, even when there are more
            # seeds than pages.
            self.max_pages = max(self.max_pages, len(seeds) * 20)
        while queue and len(seen) < self.max_pages:
            if should_stop is not None:
                try:
                    if should_stop():
                        break
                except Exception:
                    # A broken stop callback must fail safe: treat it as a
                    # stop request rather than crawling on past a cancel.
                    break
            url, depth = queue.pop(0)
            if url in seen:
                continue
            if not self.scope.is_in_scope(url):
                if url not in result.out_of_scope:
                    result.out_of_scope.append(url)
                    if on_discover:
                        on_discover("out-of-scope", url)
                continue
            seen.add(url)
            if self.on_fetch:
                tick += 1
                if tick % 5 == 0:
                    self.on_fetch("progress", url, len(result.pages) + len(result.js_urls))
            status, text, content_type = self._fetch(url)
            if status == 0:
                if self.on_fetch:
                    self.on_fetch("skip", url, 0)
                continue
            fetched += 1

            is_js = _is_js_url(url) or "javascript" in content_type
            if is_js:
                result.js_urls.append(url)
                result.js_text[url] = text
                if on_discover:
                    on_discover("js", url, text)
                if self.on_fetch:
                    self.on_fetch("js", url, status)
                recovered = self._source_map(url, text)
                if recovered is not None and recovered[0] not in result.js_text:
                    map_url, sources = recovered
                    result.js_text[map_url] = sources
                    result.js_urls.append(map_url)
                    if on_discover:
                        on_discover("js", map_url, sources)
                    for endpoint in ENDPOINT_RE.findall(sources):
                        absolute = _absolute(map_url, endpoint)
                        result.endpoints.append(absolute)
                        if absolute not in known_endpoints:
                            known_endpoints.add(absolute)
                            if on_discover:
                                on_discover("endpoint", absolute)
                for child in js_children(url, text):
                    if self.scope.is_in_scope(child):
                        queue.append((child, depth + 1))
                for endpoint in ENDPOINT_RE.findall(text):
                    absolute = _absolute(url, endpoint)
                    result.endpoints.append(absolute)
                    if absolute not in known_endpoints:
                        known_endpoints.add(absolute)
                        if on_discover:
                            on_discover("endpoint", absolute)
            else:
                result.pages.append(url)
                result.page_text[url] = text
                if on_discover:
                    on_discover("page", url, text)
                if self.on_fetch:
                    self.on_fetch("page", url, status)
                for link in LINK_RE.findall(text):
                    trimmed = link.strip()
                    if SCHEME_RE.match(trimmed) and not trimmed.lower().startswith(("http://", "https://")):
                        continue
                    child = _absolute(url, trimmed)
                    if child.split("?")[0].lower().endswith(ASSET_EXT):
                        continue
                    if self.scope.is_in_scope(child):
                        if child.split("?")[0].lower().endswith(".js"):
                            if child not in result.js_urls:
                                queue.append((child, depth))
                        elif depth < self.max_depth:
                            queue.append((child, depth + 1))
                    elif self.scope.is_out_of_scope(child):
                        if child not in result.out_of_scope:
                            result.out_of_scope.append(child)
                            if on_discover:
                                on_discover("out-of-scope", child)
                for absolute in re.findall(r"""https?://[^\s"'<>)\\]+""", text):
                    if absolute.split("?")[0].lower().endswith(".js") and self.scope.is_in_scope(absolute):
                        queue.append((absolute, depth))
            if on_checkpoint and fetched % 10 == 0:
                on_checkpoint({"queue": [[u, d] for u, d in queue], "seen": sorted(seen)})
        if on_checkpoint:
            # the final state: whatever is still queued when the walk stops,
            # so an interrupted crawl can pick up exactly where it left off
            on_checkpoint({"queue": [[u, d] for u, d in queue], "seen": sorted(seen)})
        result.js_urls = sorted(set(result.js_urls))
        result.endpoints = sorted(set(result.endpoints))
        result.out_of_scope = sorted(set(result.out_of_scope))
        return result

    def wayback(self, domain: str, limit: int = 5000) -> list[str]:
        query = (f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
                 f"&output=json&fl=original&collapse=urlkey&limit={limit}")
        response = self.session.get(query)
        if response is None:
            return []
        try:
            rows = json.loads(response.text)
        except json.JSONDecodeError:
            return []
        if not isinstance(rows, list):
            return []
        urls = []
        for row in rows[1:]:
            if isinstance(row, list) and row and isinstance(row[0], str):
                urls.append(row[0])
        return urls

    def fetch(self, url: str):
        return self._fetch(url)

    def historical_js(self, domains: list[str], limit: int = 2000,
                      max_js: int = 25) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for domain in domains:
            try:
                rows = self.wayback(domain, limit=limit)
            except Exception:
                continue
            for url in rows:
                if not url.split("?")[0].lower().endswith(".js"):
                    continue
                if url in seen or not self.scope.is_in_scope(url):
                    continue
                seen.add(url)
                found.append(url)
                if len(found) >= max_js:
                    return found
        return found

    def external_tools(self) -> list[str]:
        return [tool for tool in ("katana", "gau", "waybackurls", "jsleak") if shutil.which(tool)]
