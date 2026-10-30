"""A curated technique library built from public offensive-security research.

The library is not a scanner and not a finding generator. Each entry describes
a technique, the signals that make it worth testing, the smallest proof, and
the public source it came from. `plan` ranks entries against a target's
fingerprint so an agent can choose a precise experiment instead of running a
generic checklist.

Research is ingested deliberately: `ingest` stores a written digest as a skill
with its source URL. The library ships with a 2025-2026 corpus covering CSPT,
cache deception, ORM leaks, error-based SSTI, OAuth/SCIM/MCP identity bugs,
parser differentials, Next.js cache chains, and less-saturated API classes.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

TECHNIQUES_PATH = Path(__file__).with_name("data") / "techniques.json"
IMPACT_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
RARITY_WEIGHT = {"rare": 3, "uncommon": 2, "common": 1}

HOST_HINTS = {
    "nextjs": ["nextjs", "next.js", "__next_data__", "x-now-route-matches"],
    "react": ["react", "spa", "client-side"],
    "django": ["django", "drf", "python"],
    "prisma": ["prisma", "node", "typescript"],
    "beego": ["beego", "golang", "go"],
    "odata": ["odata", "entity-framework", "dotnet", "asp.net"],
    "graphql": ["graphql", "relay", "introspection"],
    "oauth": ["oauth", "oidc", "openid", "sso"],
    "saml": ["saml", "shibboleth", "adfs"],
    "scim": ["scim", "provisioning", "okta"],
    "jwt": ["jwt", "bearer", "token"],
    "cdn": ["cloudflare", "akamai", "fastly", "cloudfront", "cdn", "cache"],
    "android": ["android", "apk", "mobile", "ios"],
    "cloud": ["aws", "gcp", "azure", "cloud", "s3", "gcs"],
    "mcp": ["mcp", "model-context-protocol", "agent"],
    "llm": ["llm", "ai", "chatbot", "rag", "prompt"],
    "ci": ["github", "gitlab", "actions", "ci", "workflow"],
}


@lru_cache(maxsize=1)
def techniques() -> tuple[dict, ...]:
    try:
        raw = json.loads(TECHNIQUES_PATH.read_text())
    except (OSError, ValueError):
        return ()
    items = []
    for item in raw.get("techniques", []):
        if not isinstance(item, dict) or not item.get("id") or not item.get("title"):
            continue
        entry = dict(item)
        entry["signals"] = [str(value) for value in entry.get("signals") or []]
        entry["tags"] = [str(value) for value in entry.get("tags") or []]
        entry["prereqs"] = [str(value) for value in entry.get("prereqs") or []]
        entry["steps"] = [str(value) for value in entry.get("steps") or []]
        entry["tools"] = [str(value) for value in entry.get("tools") or []]
        entry["sources"] = [str(value) for value in entry.get("sources") or []]
        items.append(entry)
    return tuple(items)


def find_technique(technique_id: str) -> dict | None:
    for item in techniques():
        if item["id"] == technique_id:
            return item
    return None


def _matches(value: str, context: str, tokens: set[str]) -> bool:
    text = str(value).lower().strip()
    if not text:
        return False
    if text in tokens or text in context:
        return True
    parts = [part for part in re.split(r"[^a-z0-9.+#-]+", text) if part]
    return bool(parts) and all(part in context for part in parts)


def search(query: str = "", tag: str = "", rarity: str = "", impact: str = "",
           limit: int = 20) -> dict:
    q = (query or "").strip().lower()
    tag = (tag or "").strip().lower()
    rarity = (rarity or "").strip().lower()
    impact = (impact or "").strip().lower()
    items = list(techniques())
    if q:
        items = [item for item in items
                 if q in item["title"].lower() or q in item["class"].lower()
                 or q in " ".join(item["signals"]).lower()
                 or q in " ".join(item["tags"]).lower()
                 or q in " ".join(item["steps"]).lower()]
    if tag:
        items = [item for item in items if tag in item["tags"]]
    if rarity:
        items = [item for item in items if item["rarity"] == rarity]
    if impact:
        items = [item for item in items if item["impact"] == impact]
    items.sort(key=lambda item: (IMPACT_WEIGHT.get(item["impact"], 0),
                                 RARITY_WEIGHT.get(item["rarity"], 0),
                                 item["title"].lower()), reverse=True)
    return {"items": items[:max(1, min(int(limit or 20), 100))],
            "total": len(items),
            "note": ("A technique is a hypothesis. Confirm the target is in scope "
                     "and prove the effect before recording anything.")}


def plan(index=None, target: str = "", tech: str = "", signals: list | None = None,
         tags: list | None = None, limit: int = 6) -> dict:
    """Rank techniques against a target fingerprint, deterministically."""
    parts = [target or "", tech or ""]
    parts.extend(str(value) for value in (signals or []))
    parts.extend(str(value) for value in (tags or []))
    context = " ".join(parts).strip().lower()
    tokens = {token for token in re.split(r"[^a-z0-9.+#-]+", context) if token}
    hints: set[str] = set()
    for name, words in HOST_HINTS.items():
        if name in context or any(word in context for word in words):
            hints.add(name)
    expertise = {}
    if index is not None:
        try:
            for row in index.list_expertise(limit=100):
                expertise[str(row.get("tech") or "").lower()] = int(
                    row.get("exposures") or 0)
        except Exception:  # noqa: BLE001 - ranking must not depend on this table
            expertise = {}
    ranked = []
    for item in techniques():
        signal_hits = [value for value in item["signals"]
                       if _matches(value, context, tokens)]
        tag_hits = [value for value in item["tags"] if _matches(value, context, tokens)]
        prereq_hits = [value for value in item["prereqs"]
                       if _matches(value, context, tokens)]
        hint_hits = [hint for hint in hints
                     if hint in item["tags"] or hint in item["signals"]
                     or hint == item["class"]]
        exposure = sum(expertise.get(tag, 0) for tag in item["tags"])
        if context and not (signal_hits or tag_hits or hint_hits or prereq_hits):
            # A fingerprint match must be real; do not pad the plan with
            # unrelated high-impact entries just because they are critical.
            continue
        score = (3 * len(signal_hits) + 2 * len(tag_hits)
                 + len(prereq_hits) + 2 * len(hint_hits)
                 + min(3, exposure))
        if not context:
            score = (IMPACT_WEIGHT.get(item["impact"], 0) * 2
                     + RARITY_WEIGHT.get(item["rarity"], 0))
        ranked.append({
            "id": item["id"],
            "title": item["title"],
            "class": item["class"],
            "rarity": item["rarity"],
            "impact": item["impact"],
            "score": score,
            "why": sorted(set(signal_hits + tag_hits + hint_hits))[:8],
            "signals": item["signals"],
            "steps": item["steps"],
            "proof": item["proof"],
            "tools": item["tools"],
            "sources": item["sources"],
            "tags": item["tags"],
        })
    ranked.sort(key=lambda row: (-row["score"], -IMPACT_WEIGHT.get(row["impact"], 0),
                                 row["title"].lower()))
    return {
        "target": target,
        "tech": tech,
        "signals": list(signals or []),
        "items": ranked[:max(1, min(int(limit or 6), 30))],
        "catalogue": len(techniques()),
        "note": ("Ranked from a public-research library. A high score is a reason "
                 "to test, not evidence of a vulnerability."),
    }


def sources() -> dict:
    by_class: dict[str, int] = {}
    by_rarity: dict[str, int] = {}
    for item in techniques():
        by_class[item["class"]] = by_class.get(item["class"], 0) + 1
        by_rarity[item["rarity"]] = by_rarity.get(item["rarity"], 0) + 1
    return {"total": len(techniques()),
            "by_class": dict(sorted(by_class.items())),
            "by_rarity": dict(sorted(by_rarity.items())),
            "note": "Techniques are curated from public research, not target data."}


def _slug(title: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", (title or "").lower()).strip("-")
    return value[:80] or "research-note"


def ingest(index, url: str, title: str, notes: str, tags: list | None = None) -> dict:
    """Store a written research digest as a skill with its source URL."""
    url = (url or "").strip()
    title = (title or "").strip()
    notes = (notes or "").strip()
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("url must be an http(s) URL")
    if len(title) < 8:
        raise ValueError("title must be at least 8 characters")
    if len(notes) < 80:
        raise ValueError("notes must be at least 80 characters of usable technique detail")
    clean_tags = [str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()]
    name = f"research-{_slug(title)}"
    body = (f"# {title}\n\nSource: {url}\n\n"
            f"Curated: {', '.join(clean_tags) if clean_tags else 'general'}\n\n"
            f"{notes}\n")
    skill = index.upsert_skill(
        name=name, body=body, title=title,
        description=notes.splitlines()[0][:200],
        tags=[*clean_tags, "research"], source=url)
    return {"skill": skill, "name": name, "source": url,
            "note": ("The digest is now an active skill for every agent. It is a "
                     "summary, not a replacement for the original source.")}
