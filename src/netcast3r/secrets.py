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
    def __init__(self, patterns: list[Pattern] | None = None):
        self.patterns = patterns if patterns is not None else load_patterns()

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
        found: dict[tuple[str, str], Secret] = {}
        lower = text.lower()
        for pattern in self.patterns:
            if pattern.keywords and not any(word.lower() in lower for word in pattern.keywords):
                continue
            for match in pattern.regex.finditer(text):
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
                start = max(match.start() - 48, 0)
                end = min(match.end() + 48, len(text))
                context = text[start:end].replace("\n", " ")
                found[key] = Secret(
                    type=pattern.type,
                    value=value,
                    pattern_id=pattern.id,
                    source=source,
                    context=context,
                    confidence=self._confidence(pattern, value, context),
                )
        return list(found.values())
