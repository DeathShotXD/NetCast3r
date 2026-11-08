"""Run-scoped operator directives for the live mesh.

A directive is a short instruction sent while a run is in flight. The queue
holds it until the solver worker drains it, then the mesh turns it into a skip
filter or a highest-priority objective. The queue is thread-safe because the
HTTP thread writes while the solver thread reads.

The classifier is deliberately small and deterministic. It decides intent from
plain words, so a weak or unavailable model can never drop an operator
instruction on the floor.
"""

from __future__ import annotations

import re
import secrets
import threading
import time

MAX_TEXT = 2000
MAX_HISTORY = 250
MAX_TERMS = 12

# Words that carry intent but not subject matter. Removing them keeps a skip
# directive aimed at "the admin panel" instead of "skip the".
SKIP_VERBS = {
    "skip", "stop", "drop", "ignore", "discard", "park", "defer", "hold",
    "off", "later", "avoid", "unnecessary", "unneeded", "useless",
    "dont", "don't", "do", "not", "never", "now", "for", "the", "a", "an",
    "that", "this", "it", "its", "task", "objective", "move", "test",
    "testing", "check", "checking", "focus", "please", "agent", "brain",
    "currently", "right", "just", "about", "on", "of", "to", "and", "or",
    "with", "without", "from", "at", "in", "into", "any", "some", "more",
    "next", "already", "again", "until", "than", "then", "there", "here",
    "is", "are", "was", "were", "be", "been", "being", "these", "those",
}

FOCUS_VERBS = {
    "check", "test", "try", "focus", "look", "investigate", "verify", "probe",
    "enumerate", "scan", "review", "examine", "prioritise", "prioritize",
    "do", "run", "target", "attack", "analyse", "analyze", "find", "confirm",
    "validate", "explore", "pivot", "escalate", "please", "now", "the", "a",
    "an", "on", "at", "in", "into", "for", "of", "to", "and", "or", "this",
    "that", "it", "its", "task", "agent", "brain", "currently", "first",
    "next", "right", "away", "also", "then", "there", "here",
}

GENERIC = {
    "host", "hosts", "target", "targets", "url", "urls", "site", "web",
    "path", "paths", "page", "pages", "request", "requests", "response",
    "endpoint", "endpoints", "service", "services", "document", "file",
    "files", "server", "app", "application", "api", "apis", "thing",
    "things", "something", "stuff", "work", "the", "a", "an", "it", "this",
    "that", "with", "from", "into", "over", "under", "again", "still",
    "new", "old", "same", "other", "another", "any", "all", "some",
}

SKIP_RE = re.compile(
    r"\b(skip|stop|drop|ignore|discard|park|defer|hold\s+off|"
    r"not\s+now|later|avoid|don'?t|do\s+not|unnecessary|unneeded)\b", re.I)
FOCUS_RE = re.compile(
    r"\b(check|test|try|focus|look\s+at|investigate|verify|probe|enumerate|"
    r"scan|review|examine|prioriti[sz]e|do|run|find|confirm|validate|"
    r"explore|pivot|escalate)\b", re.I)
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/?#=&%-]{1,64}")


def classify(text: str, kind: str = "auto") -> str:
    """Return ``skip`` or ``focus``. An explicit kind always wins."""
    kind = str(kind or "auto").strip().lower()
    if kind in ("skip", "focus"):
        return kind
    value = str(text or "")
    if SKIP_RE.search(value) and not FOCUS_RE.search(value):
        return "skip"
    if SKIP_RE.search(value) and FOCUS_RE.search(value):
        # "skip the scan and check the login page" is a focus directive with
        # a skip side note; the subject after the focus verb is the real ask.
        skip_at = SKIP_RE.search(value).start()
        focus_at = FOCUS_RE.search(value).start()
        return "skip" if skip_at <= focus_at else "focus"
    return "focus"


def _singular(token: str) -> str:
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if (len(token) > 3 and token.endswith("s")
            and not token.endswith(("ss", "is", "us"))):
        return token[:-1]
    return token


def terms_for(text: str, kind: str = "auto") -> list[str]:
    """Significant subject words in a directive, lowercase and singularised."""
    intent = classify(text, kind)
    drop = SKIP_VERBS if intent == "skip" else FOCUS_VERBS
    found: list[str] = []
    seen: set[str] = set()
    for raw in TOKEN_RE.findall(str(text or "")):
        # Split compound tokens so "host-header" and "IDOR/BOLA" contribute
        # the same words the task matcher extracts.
        for piece in re.split(r"[^A-Za-z0-9]+", raw):
            token = _singular(piece.lower())
            if not token or token in seen:
                continue
            if token in drop or token in GENERIC:
                continue
            if len(token) < 3 and not token.isdigit():
                continue
            seen.add(token)
            found.append(token)
            if len(found) >= MAX_TERMS:
                return found
    return found


def _tokens(text: str) -> set[str]:
    """Singular lowercase words, with compound tokens split on punctuation.

    ``IDOR/BOLA`` must yield ``idor`` and ``bola`` so a directive that names
    one half still matches the task.
    """
    return {_singular(token) for token
            in re.findall(r"[a-z0-9]+", str(text or "").lower())}


def _term_hit(needle: str, tokens: set[str], blob: str) -> bool:
    if needle in tokens:
        return True
    # Prefix awareness for a long term: "admin" still hits "administrator".
    # Short terms stay exact so "port" never hits "support".
    return len(needle) >= 5 and needle in blob


def matches(text: str, terms: list[str]) -> int:
    """How many directive terms the text carries.

    A term matches a whole word or a meaningful prefix, so "port" still hits
    "ports" and "admin" hits "administrator" without matching "ad".
    """
    if not terms:
        return 0
    blob = str(text or "").lower()
    tokens = _tokens(blob)
    hits = 0
    for term in terms:
        needle = _singular(str(term).lower())
        if not needle:
            continue
        if _term_hit(needle, tokens, blob):
            hits += 1
    return hits


def matches_enough(text: str, terms: list[str]) -> bool:
    """True when a skip directive clearly targets this text.

    Half the subject words is the normal bar. The first word is the head noun
    of the instruction, so a precise head match ("skip the IDOR user data
    test") is enough even when the task phrases the modifiers differently.
    """
    if not terms:
        return False
    clean = [_singular(str(term).lower()) for term in terms if str(term).strip()]
    if not clean:
        return False
    hits = matches(text, clean)
    if hits == 0:
        return False
    needed = 1 if len(clean) <= 2 else 2
    if hits >= needed:
        return True
    head = clean[0]
    return len(head) >= 4 and _term_hit(head, _tokens(text), str(text or "").lower())


class DirectiveQueue:
    """Thread-safe FIFO of operator directives for one run."""

    def __init__(self, run_id: str = ""):
        self.run_id = run_id
        self._lock = threading.Lock()
        self._queued: list[dict] = []
        self._history: list[dict] = []
        self._counter = 0

    def push(self, text: str, kind: str = "auto", target: str = "",
             source: str = "operator") -> dict:
        value = " ".join(str(text or "").split())[:MAX_TEXT]
        if not value:
            raise ValueError("directive text required")
        intent = classify(value, kind)
        terms = terms_for(value, intent)
        with self._lock:
            self._counter += 1
            directive = {
                "id": "dir_" + secrets.token_hex(6),
                "run_id": self.run_id,
                "text": value,
                "kind": intent,
                "requested": str(kind or "auto"),
                "terms": terms,
                "target": str(target or "")[:200],
                "source": str(source or "operator")[:40],
                "status": "queued",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "order": self._counter,
            }
            self._queued.append(directive)
            self._history.append(dict(directive))
            if len(self._history) > MAX_HISTORY:
                self._history = self._history[-MAX_HISTORY:]
            return dict(directive)

    def drain(self) -> list[dict]:
        """Hand every queued directive to the mesh exactly once."""
        with self._lock:
            if not self._queued:
                return []
            batch = self._queued
            self._queued = []
            for item in batch:
                item["status"] = "delivered"
                for row in self._history:
                    if row.get("id") == item.get("id"):
                        row["status"] = "delivered"
            return [dict(item) for item in batch]

    def mark(self, directive_id: str, status: str, detail: str = "") -> None:
        with self._lock:
            for row in self._history:
                if row.get("id") == directive_id:
                    row["status"] = str(status or row.get("status") or "")[:40]
                    if detail:
                        row["detail"] = str(detail)[:400]
                    break

    def history(self, limit: int = 60) -> list[dict]:
        try:
            count = max(1, min(int(limit or 60), MAX_HISTORY))
        except (TypeError, ValueError):
            count = 60
        with self._lock:
            return [dict(row) for row in self._history[-count:]]

    def pending(self) -> int:
        with self._lock:
            return len(self._queued)
