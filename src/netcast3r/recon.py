"""Recon fabric.

Crawls from the seeds, stays inside scope, collects JavaScript, and pulls
historical URLs from the Wayback Machine. External tools (katana, gau,
waybackurls, jsleak) are used when they are installed, otherwise the built-in
crawler runs.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.I)
JS_REF_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""", re.I)
JS_IMPORT_RE = re.compile(r"""(?:import\s*\(\s*|from\s*|require\(\s*)["']([^"']+\.js[^"']*)["']""")
ENDPOINT_RE = re.compile(r"""["'](/[A-Za-z0-9_\-./]{2,}(?:\?[A-Za-z0-9_\-=&%]*)?)["']""")


@dataclass
class ReconResult:
    pages: list = field(default_factory=list)
    js_urls: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    historical: list = field(default_factory=list)
    js_text: dict = field(default_factory=dict)
    out_of_scope: list = field(default_factory=list)


def _absolute(base: str, link: str) -> str:
    return urljoin(base, link)


class Recon:
    def __init__(self, scope, config, client: httpx.Client | None = None):
        self.scope = scope
        self.config = config
        self.client = client or httpx.Client(
            timeout=config.run.timeout,
            follow_redirects=True,
            headers={"User-Agent": config.run.user_agent},
        )
        self.max_depth = config.run.depth
        self.max_pages = config.run.concurrency * 25

    def _fetch(self, url: str):
        try:
            response = self.client.get(url)
            return response.status_code, response.text, response.headers.get("content-type", "")
        except Exception:
            return 0, "", ""

    def crawl(self, seeds: list[str]) -> ReconResult:
        result = ReconResult()
        queue: list[tuple[str, int]] = []
        for seed in seeds:
            url = seed if "://" in seed else "https://" + seed
            self.scope.add_seed(url)
            queue.append((url, 0))

        seen: set[str] = set()
        while queue and len(seen) < self.max_pages:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            if not self.scope.is_in_scope(url):
                result.out_of_scope.append(url)
                continue
            seen.add(url)
            status, text, content_type = self._fetch(url)
            if status == 0:
                continue

            is_js = ".js" in url.split("?")[0].lower() or "javascript" in content_type
            if is_js:
                result.js_urls.append(url)
                result.js_text[url] = text
                for ref in JS_IMPORT_RE.findall(text):
                    child = _absolute(url, ref)
                    if self.scope.is_in_scope(child):
                        queue.append((child, depth + 1))
                for endpoint in ENDPOINT_RE.findall(text):
                    result.endpoints.append(_absolute(url, endpoint))
            else:
                result.pages.append(url)
                links = LINK_RE.findall(text)
                for link in links:
                    child = _absolute(url, link)
                    if child.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2")):
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
        try:
            with httpx.Client(timeout=self.config.run.timeout) as client:
                rows = client.get(query).json()
        except Exception:
            return []
        urls = []
        for row in rows[1:]:
            if row:
                urls.append(row[0])
        return urls

    def external_tools(self) -> list[str]:
        return [tool for tool in ("katana", "gau", "waybackurls", "jsleak") if shutil.which(tool)]
