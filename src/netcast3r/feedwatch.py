"""Public security-report watcher.

This is a bounded feed reader, not a search engine. It fetches a curated list
of public advisory and research feeds (MSRC, Project Zero, Google Security,
GitHub Advisories, PortSwigger Research, Bugcrowd, CISA KEV), stores new items
with their source URL, and lets an agent read one item before writing a lesson.

The list is deliberately explicit. A feed item is a lead, not a finding, and
nothing here touches an authorised target.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

import httpx

SOURCES_PATH = Path(__file__).with_name("data") / "knowledge_sources.json"
ATOM = "{http://www.w3.org/2005/Atom}"
MAX_BYTES = 2_000_000
MAX_ITEMS = 40
# Public feeds are fetched together, not one after another: a single hung feed
# must not stall a training plan for the sum of every feed's timeout.
FEED_TIMEOUT = 8.0
FETCH_WORKERS = 6


@lru_cache(maxsize=1)
def sources() -> tuple[dict, ...]:
    try:
        raw = json.loads(SOURCES_PATH.read_text())
    except (OSError, ValueError):
        return ()
    items = []
    for source in raw.get("sources", []):
        if not isinstance(source, dict):
            continue
        if not source.get("id") or not source.get("url"):
            continue
        items.append({
            "id": str(source["id"]),
            "name": str(source.get("name") or source["id"]),
            "url": str(source["url"]),
            "kind": str(source.get("kind") or "rss"),
            "tags": [str(tag) for tag in source.get("tags") or []],
        })
    return tuple(items)


def _clean(text: str, limit: int = 600) -> str:
    text = re.sub(r"<script[\s\S]*?</script>", " ", text or "", flags=re.I)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def parse_rss(text: str) -> list[dict]:
    """Parse RSS 2.0 or Atom into title/link/published/summary records."""
    try:
        root = ElementTree.fromstring(text or "")
    except ElementTree.ParseError:
        return []
    records = []
    for node in root.iter():
        if node.tag not in {"item", f"{ATOM}entry"}:
            continue
        title = ""
        link = ""
        published = ""
        summary = ""
        for child in list(node):
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "title":
                title = _clean(child.text or "", 300)
            elif tag == "link":
                link = child.attrib.get("href") or (child.text or "")
            elif tag in {"pubDate", "updated", "published"}:
                published = (child.text or "").strip()
            elif tag in {"description", "summary", "content"}:
                summary = _clean(child.text or "", 600)
        if link and title:
            records.append({"title": title, "url": link.strip(),
                            "published": published, "summary": summary})
        if len(records) >= MAX_ITEMS:
            break
    return records


def parse_kev(text: str) -> list[dict]:
    try:
        payload = json.loads(text or "{}")
    except ValueError:
        return []
    records = []
    for item in payload.get("vulnerabilities", []):
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip()
        if not cve:
            continue
        records.append({
            "title": f"{cve} - {item.get('vulnerabilityName') or 'known exploited vulnerability'}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "published": str(item.get("dateAdded") or ""),
            "summary": _clean(str(item.get("shortDescription") or ""), 600),
        })
        if len(records) >= MAX_ITEMS:
            break
    return records


def _public_url(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parts.hostname, None)
    except OSError:
        return False
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast):
            return False
    return True


def _fetch(url: str, timeout: float = FEED_TIMEOUT) -> str:
    if not _public_url(url):
        raise ValueError("source must resolve to a public address")
    with httpx.Client(timeout=timeout, trust_env=False,
                      follow_redirects=True) as client:
        with client.stream("GET", url, headers={
                "user-agent": "NetCast3r-Knowledge/0.1",
                "accept": "application/rss+xml, application/atom+xml, "
                          "application/json, text/xml, */*"}) as response:
            response.raise_for_status()
            chunks, read = [], 0
            for chunk in response.iter_bytes():
                if read + len(chunk) > MAX_BYTES:
                    chunks.append(chunk[:MAX_BYTES - read])
                    break
                chunks.append(chunk)
                read += len(chunk)
            return b"".join(chunks).decode("utf-8", "replace")


def _load(source: dict, limit: int) -> tuple[dict, list[dict], str]:
    """Fetch and parse one feed. Returns (source, records, error)."""
    try:
        body = _fetch(source["url"])
        records = (parse_kev(body) if source["kind"] == "json"
                   else parse_rss(body))
        return source, records[:max(1, min(int(limit or 20), MAX_ITEMS))], ""
    except Exception as exc:  # noqa: BLE001 - one dead feed must not stop the rest
        return source, [], str(exc)[:200]


def refresh(index, source_id: str = "", limit: int = 20) -> dict:
    """Fetch one or all curated feeds and store new items.

    Feeds are fetched concurrently and parsed off the calling thread; every
    database write still happens here, in order, so the index is only touched
    by one thread.
    """
    selected = [source for source in sources()
                if not source_id or source["id"] == source_id]
    if not selected:
        raise ValueError(f"unknown knowledge source: {source_id}")
    known = {item["url"] for item in index.list_knowledge(limit=500)}
    results: list[tuple[dict, list[dict], str]] = []
    if selected:
        workers = max(1, min(FETCH_WORKERS, len(selected)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda source: _load(source, limit), selected))
    new_items, errors = [], []
    for source, records, error in results:
        if error:
            errors.append({"source": source["id"], "error": error})
            continue
        for record in records:
            if record["url"] in known:
                continue
            item = index.add_knowledge_item(
                source=source["id"], title=record["title"],
                url=record["url"], published=record["published"],
                summary=record["summary"], tags=source["tags"])
            known.add(record["url"])
            new_items.append(item)
    return {
        "sources": [source["id"] for source in selected],
        "new": len(new_items),
        "items": new_items[:50],
        "errors": errors,
        "note": ("A feed item is a lead. Read it, extract the technique, and "
                 "record a lesson; it is not a finding."),
    }


def recent(index, source: str = "", limit: int = 50) -> dict:
    items = index.list_knowledge(source=source, limit=limit)
    return {"items": items, "total": len(items),
            "sources": [source["id"] for source in sources()]}


def read(index, item_id: str, max_chars: int = 8000) -> dict:
    item = index.get_knowledge(item_id)
    if not item:
        raise ValueError("knowledge item not found")
    text = _fetch(item["url"])
    cleaned = _clean(text, max(500, min(int(max_chars or 8000), 20000)))
    index.mark_knowledge(item_id, "read")
    return {
        "item": item, "text": cleaned, "chars": len(cleaned),
        "note": ("Read the source, then use research_ingest to store a distilled "
                 "technique if it is reusable."),
    }
