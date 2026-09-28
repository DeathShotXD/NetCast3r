"""Target specific wordlist.

Collects the words a target actually uses in its paths, parameter names, and
page text so the next stage can fuzz with names that are known to exist on this
host. The idea follows the way xnLinkFinder builds a wordlist for a target.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_\-]{2,}")
SEGMENT_RE = re.compile(r"[A-Za-z0-9_\-]{3,}")

STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "you", "your", "are",
    "was", "were", "will", "can", "has", "have", "not", "but", "all", "any",
    "get", "new", "use", "via", "per", "out", "off", "one", "two", "html",
    "http", "https", "www", "com", "org", "net", "true", "false", "null",
    "var", "let", "const", "function", "return", "class", "async", "await",
}


class Wordlist:
    def __init__(self):
        self._words: set[str] = set()

    def add_token(self, token: str) -> None:
        token = token.strip()
        if len(token) < 3:
            return
        lowered = token.lower()
        if lowered in STOPWORDS:
            return
        if not re.fullmatch(r"[A-Za-z0-9_\-]+", token):
            return
        self._words.add(token)
        if token != lowered:
            self._words.add(lowered)

    def add_text(self, text: str) -> None:
        for token in TOKEN_RE.findall(text or ""):
            self.add_token(token)

    def add_url(self, url: str) -> None:
        parts = urlsplit(url)
        for segment in parts.path.split("/"):
            for token in SEGMENT_RE.findall(segment or ""):
                self.add_token(token)
        for key, _ in parse_qsl(parts.query):
            self.add_token(key)

    def words(self) -> list[str]:
        return sorted(self._words)

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(self.words()) + "\n")
        return target
