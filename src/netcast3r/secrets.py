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
    try:
        with open(target, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        if path:
            raise ValueError(f"could not read the patterns file {target}: {exc}") from exc
        return []
    patterns: list[Pattern] = []
    for row in data.get("pattern", []):
        if not isinstance(row, dict) or "regex" not in row:
            continue
        try:
            regex = re.compile(row["regex"])
        except re.error:
            continue
        if "group" in row:
            group = int(row["group"])
        else:
            group = 1 if regex.groups else 0
        patterns.append(
            Pattern(
                id=row.get("id", ""),
                type=row.get("type", ""),
                regex=regex,
                description=row.get("description", ""),
                entropy=float(row.get("entropy", 0.0)),
                group=group,
                keywords=list(row.get("keywords", [])),
            )
        )
    return patterns


class Extractor:
    def __init__(self, patterns: list[Pattern] | None = None, max_scan: int = 0):
        self.patterns = patterns if patterns is not None else load_patterns()
        self.max_scan = max_scan
        self._vocab: re.Pattern | None = None
        self._vocab_members: dict[str, list[str]] = {}
        self._vocab_ready = False

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
            # scan head and tail as separate strings so a value cannot be
            # fabricated across the join
            segments = [text[:half], text[-half:]]
        else:
            segments = [text]
        found: dict[tuple[str, str], Secret] = {}
        for segment in segments:
            # Locate every catalog keyword in ONE case-insensitive pass, then
            # let each pattern read the spans it cares about. Re-running a
            # substring search per keyword made the catalog scan scale with
            # (patterns x keywords x bytes) and stall on a hostile blob.
            positions = self._keyword_positions(segment)
            for pattern in self.patterns:
                if pattern.keywords:
                    for start, end in self._windows(positions, pattern.keywords):
                        self._match(pattern, segment, start, end, source, found)
                else:
                    self._match(pattern, segment, 0, len(segment), source, found)
        return list(found.values())

    WINDOW_BEFORE = 400
    WINDOW_AFTER = 8000

    def _keyword_positions(self, text: str) -> dict[str, list[tuple[int, int]]]:
        """Every keyword hit in ``text`` keyed by the lowercased keyword.

        One compiled alternation walks the text once. A match can still cover
        a shorter keyword inside it ("sk" inside "sk_live"), so each hit is
        decomposed into every catalogue keyword it contains. That keeps the
        window set identical to the old per-keyword scan without paying its
        cost.
        """
        vocabulary = self._vocabulary()
        if vocabulary is None:
            return {}
        positions: dict[str, list[tuple[int, int]]] = {}
        for match in vocabulary.finditer(text):
            lowered = match.group(0).lower()
            for keyword in self._vocab_members.get(lowered, (lowered,)):
                at = lowered.find(keyword)
                while at >= 0:
                    positions.setdefault(keyword, []).append(
                        (match.start() + at, match.start() + at + len(keyword)))
                    at = lowered.find(keyword, at + 1)
        return positions

    def _vocabulary(self) -> re.Pattern | None:
        """Alternation of every keyword in this extractor, built lazily."""
        if not self._vocab_ready:
            words = {kw.lower() for pattern in self.patterns for kw in pattern.keywords if kw}
            if words:
                # Longest first so a keyword that contains a shorter one wins.
                ordered = sorted(words, key=len, reverse=True)
                self._vocab = re.compile("|".join(re.escape(word) for word in ordered),
                                         re.IGNORECASE)
                self._vocab_members = {
                    word: [other for other in words if other in word]
                    for word in words}
            self._vocab_ready = True
        return self._vocab

    @classmethod
    def _windows(cls, positions: dict[str, list[tuple[int, int]]],
                 keywords: list[str]) -> list[tuple[int, int]]:
        if not positions:
            return []
        spans: list[tuple[int, int]] = []
        for keyword in keywords:
            if not keyword:
                continue
            for start, end in positions.get(keyword.lower(), ()):
                spans.append((max(0, start - cls.WINDOW_BEFORE),
                              end + cls.WINDOW_AFTER))
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
