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

LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.I)
JS_REF_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""", re.I)
JS_IMPORT_RE = re.compile(r"""(?:import\s*\(\s*|from\s*|require\(\s*)["']([^"']+\.js[^"']*)["']""")
ENDPOINT_RE = re.compile(r"""["'](/[A-Za-z0-9_\-./]{2,}(?:\?[A-Za-z0-9_\-=&%]*)?)["']""")
SOURCE_MAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=(\S+)""")
MAX_SOURCE_MAP = 8_000_000

SPEC_PATHS = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
              "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
              "/api/openapi.json", "/.well-known/openapi.json")
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graph")
GRAPHQL_QUERY = {"query": "{__schema{queryType{name} mutationType{name}}}"}
WELLKNOWN_PATHS = ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
                   "/sitemap-index.xml")
DISALLOW_RE = re.compile(r"(?im)^\s*disallow:\s*(\S+)")
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
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
    def __init__(self, scope, config, session: Session | None = None, on_fetch=None):
        self.scope = scope
        self.config = config
        self.session = session or Session(config)
        self.max_depth = config.run.depth
        self.max_pages = max(config.run.concurrency * 25, 100)
        # on_fetch(kind, url, status): kind is page | js | skip. The dashboard
        # feeds this straight into its live crawler panel.
        self.on_fetch = on_fetch

    def _fetch(self, url: str):
        response = self.session.get(url)
        if response is None:
            return 0, "", ""
        return response.status_code, response.text, response.headers.get("content-type", "")

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
            response = self.session.get(map_url)
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
            parts = urlsplit(url)
            if parts.scheme and parts.netloc:
                roots.append(parts.scheme + "://" + parts.netloc)
        return sorted(set(roots))

    def _spec_paths(self, url: str) -> list[str]:
        """Read an OpenAPI document and return the paths it declares."""
        response = self.session.get(url)
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
        response = self.session.request("POST", url, json=GRAPHQL_QUERY)
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
                response = self.session.get(url)
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

    def crawl(self, seeds: list[str]) -> ReconResult:
        result = ReconResult()
        queue: list[tuple[str, int]] = []
        for seed in seeds:
            url = seed if "://" in seed else "https://" + seed
            self.scope.add_seed(url)
            queue.append((url, 0))

        seen: set[str] = set()
        tick = 0
        while queue and len(seen) < self.max_pages:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            if not self.scope.is_in_scope(url):
                result.out_of_scope.append(url)
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

            is_js = ".js" in url.split("?")[0].lower() or "javascript" in content_type
            if is_js:
                result.js_urls.append(url)
                result.js_text[url] = text
                if self.on_fetch:
                    self.on_fetch("js", url, status)
                recovered = self._source_map(url, text)
                if recovered is not None and recovered[0] not in result.js_text:
                    map_url, sources = recovered
                    result.js_text[map_url] = sources
                    result.js_urls.append(map_url)
                    for endpoint in ENDPOINT_RE.findall(sources):
                        result.endpoints.append(_absolute(map_url, endpoint))
                for ref in JS_IMPORT_RE.findall(text):
                    child = _absolute(url, ref)
                    if self.scope.is_in_scope(child):
                        queue.append((child, depth + 1))
                for endpoint in ENDPOINT_RE.findall(text):
                    result.endpoints.append(_absolute(url, endpoint))
            else:
                result.pages.append(url)
                result.page_text[url] = text
                if self.on_fetch:
                    self.on_fetch("page", url, status)
                for link in LINK_RE.findall(text):
                    child = _absolute(url, link)
                    if child.endswith(ASSET_EXT):
                        continue
                    if self.scope.is_in_scope(child):
                        if ".js" in child.split("?")[0].lower():
                            if child not in result.js_urls:
                                queue.append((child, depth))
                        elif depth < self.max_depth:
                            queue.append((child, depth + 1))
                    elif self.scope.is_out_of_scope(child):
                        result.out_of_scope.append(child)
                for absolute in re.findall(r"""https?://[^\s"'<>)\\]+""", text):
                    if ".js" in absolute.split("?")[0].lower() and self.scope.is_in_scope(absolute):
                        queue.append((absolute, depth))
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
        urls = []
        for row in rows[1:]:
            if row:
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
                if ".js" not in url.split("?")[0].lower():
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
