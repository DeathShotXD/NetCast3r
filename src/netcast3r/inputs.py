"""Saved traffic readers.

Reads URLs and response bodies from a plain list, a HAR file, a Burp XML
export, a ZAP message file, or a Caido CSV export, so a run can start from
history instead of from the wire.
"""

from __future__ import annotations

import base64
import csv
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

URL_RE = re.compile(r"https?://[^\s\"'<>)\\]+")


@dataclass
class Source:
    urls: list = field(default_factory=list)
    bodies: dict = field(default_factory=dict)


def _har(path: Path) -> Source:
    data = json.loads(path.read_text(errors="ignore"))
    source = Source()
    for entry in data.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url", "")
        if not url:
            continue
        source.urls.append(url)
        body = entry.get("response", {}).get("content", {}).get("text", "")
        if body:
            source.bodies[url] = body
    return source


def _burp(path: Path) -> Source:
    tree = ET.parse(path)
    source = Source()
    for item in tree.iter("item"):
        url = (item.findtext("url") or "").strip()
        if not url:
            continue
        source.urls.append(url)
        response = item.find("response")
        if response is not None and response.text:
            text = response.text
            if response.attrib.get("base64", "false") == "true":
                try:
                    text = base64.b64decode(text).decode("utf-8", "ignore")
                except Exception:
                    text = ""
            if text:
                source.bodies[url] = text
    return source


def _zap(path: Path) -> Source:
    text = path.read_text(errors="ignore")
    source = Source()
    for url in URL_RE.findall(text):
        source.urls.append(url)
    blocks = re.split(r"={3,}\s*\d+\s*={3,}", text)
    for block in blocks:
        found = URL_RE.search(block)
        if found:
            source.bodies[found.group(0)] = block[:20000]
    return source


def _caido(path: Path) -> Source:
    source = Source()
    with open(path, newline="", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            url = row.get("url")
            if not url:
                host = row.get("host", "")
                path_value = row.get("path", "/")
                if host:
                    url = f"https://{host}{path_value}"
            if url:
                source.urls.append(url)
    return source


def _plain(path: Path) -> Source:
    source = Source()
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and ("://" in line or "." in line):
            source.urls.append(line)
    return source


def load(path: str | Path) -> Source:
    target = Path(path)
    text = target.read_text(errors="ignore")[:2000] if target.exists() else ""
    name = target.name.lower()
    if name.endswith(".har") or text.lstrip().startswith("{") and "\"log\"" in text:
        return _har(target)
    if text.lstrip().startswith("<?xml") or name.endswith(".xml"):
        return _burp(target)
    if re.search(r"={3,}\s*\d+\s*={3,}", text):
        return _zap(target)
    if text.lstrip().startswith("id,host,method") or name.endswith(".csv"):
        return _caido(target)
    return _plain(target)
