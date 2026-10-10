"""Secret extraction.

Patterns come from patterns.toml. Each match is classified, de-duplicated, and
filtered by entropy when the pattern asks for it. This module finds candidates;
it never contacts a provider. Validation is a separate stage.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


PATTERNS_FILE = Path(__file__).with_name("patterns.toml")
CONTEXT_KEYWORDS = ("key", "token", "secret", "auth", "bearer", "password", "passwd",
                    "credential", "api", "apikey", "private")


@dataclass
class Pattern:
    id: str
    type: str
    regex: re.Pattern
    description: str = ""
    entropy: float = 0.0
    group: int = 0
    keywords: list[str] = field(default_factory=list)


@dataclass
class Secret:
    type: str
    value: str
    pattern_id: str
    source: str = ""
    context: str = ""
    confidence: float = 0.0


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def load_patterns(path: Path | None = None) -> list[Pattern]:
    target = path or PATTERNS_FILE
    with open(target, "rb") as handle:
        data = tomllib.load(handle)
    patterns: list[Pattern] = []
    for row in data.get("pattern", []):
        patterns.append(
            Pattern(
                id=row["id"],
                type=row["type"],
                regex=re.compile(row["regex"]),
                description=row.get("description", ""),
                entropy=float(row.get("entropy", 0.0)),
                group=int(row.get("group", 0)),
                keywords=list(row.get("keywords", [])),
            )
        )
    return patterns


class Extractor:
    def __init__(self, patterns: list[Pattern] | None = None, max_scan: int = 0):
        self.patterns = patterns if patterns is not None else load_patterns()
        self.max_scan = max_scan

    @staticmethod
    def _confidence(pattern: Pattern, value: str, context: str) -> float:
        score = 0.4
        if shannon_entropy(value) >= 3.5:
            score += 0.15
        if len(value) >= 24:
            score += 0.1
        low = context.lower()
        if any(word in low for word in CONTEXT_KEYWORDS):
            score += 0.15
        if not pattern.entropy:
            score += 0.15
        if value.isupper() and value.isalpha():
            score -= 0.2
        return max(0.0, min(1.0, round(score, 2)))

    def scan(self, text: str, source: str = "") -> list[Secret]:
        if not text:
            return []
        if self.max_scan and len(text) > self.max_scan:
            half = max(1, self.max_scan // 2)
            text = text[:half] + "\n\n" + text[-half:]
        found: dict[tuple[str, str], Secret] = {}
        lower = text.lower()
        for pattern in self.patterns:
            if pattern.keywords:
                # A keyword-prefixed rule is expensive over a long run of word
                # characters, so only the windows around each keyword are read.
                for start, end in self._windows(lower, pattern.keywords):
                    self._match(pattern, text, start, end, source, found)
            else:
                self._match(pattern, text, 0, len(text), source, found)
        return list(found.values())

    WINDOW_BEFORE = 300
    WINDOW_AFTER = 300

    @classmethod
    def _windows(cls, lower: str, keywords: list[str]) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        for keyword in keywords:
            needle = keyword.lower()
            if not needle:
                continue
            at = lower.find(needle)
            while at != -1:
                spans.append((max(0, at - cls.WINDOW_BEFORE),
                              at + len(needle) + cls.WINDOW_AFTER))
                at = lower.find(needle, at + len(needle))
        if not spans:
            return []
        spans.sort()
        merged: list[tuple[int, int]] = [spans[0]]
        for start, end in spans[1:]:
            last = merged[-1]
            if start <= last[1]:
                merged[-1] = (last[0], max(last[1], end))
            else:
                merged.append((start, end))
        return merged

    def _match(self, pattern: Pattern, text: str, start: int, end: int,
               source: str, found: dict[tuple[str, str], Secret]) -> None:
        for match in pattern.regex.finditer(text, start, end):
            try:
                value = match.group(pattern.group) or match.group(0)
            except IndexError:
                value = match.group(0)
            value = value.strip()
            if not value:
                continue
            if pattern.entropy and shannon_entropy(value) < pattern.entropy:
                continue
            key = (pattern.type, value)
            if key in found:
                continue
            ctx_start = max(match.start() - 48, 0)
            ctx_end = min(match.end() + 48, len(text))
            context = text[ctx_start:ctx_end].replace("\n", " ")
            found[key] = Secret(
                type=pattern.type,
                value=value,
                pattern_id=pattern.id,
                source=source,
                context=context,
                confidence=self._confidence(pattern, value, context),
            )
