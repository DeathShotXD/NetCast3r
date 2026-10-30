"""Exploit-chain library.

The chain is the unit many programs actually reward: one low-impact signal is
combined with a second bug to produce access or data loss. Each entry lists the
steps, the signals that make it plausible, and the minimum proof. It is not a
scanner and a chain is not a finding until every link is reproduced.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

CHAINS_PATH = Path(__file__).with_name("data") / "chains.json"
IMPACT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@lru_cache(maxsize=1)
def chains() -> tuple[dict, ...]:
    try:
        raw = json.loads(CHAINS_PATH.read_text())
    except (OSError, ValueError):
        return ()
    items = []
    for item in raw.get("chains", []):
        if not isinstance(item, dict) or not item.get("id") or not item.get("title"):
            continue
        entry = dict(item)
        for key in ("steps", "signals", "tags", "sources"):
            entry[key] = [str(value) for value in entry.get(key) or []]
        items.append(entry)
    return tuple(items)


def search(query: str = "", tag: str = "", impact: str = "",
           limit: int = 20) -> dict:
    q = (query or "").strip().lower()
    tag = (tag or "").strip().lower()
    impact = (impact or "").strip().lower()
    items = list(chains())
    if q:
        items = [item for item in items
                 if q in item["title"].lower() or q in " ".join(item["steps"]).lower()
                 or q in " ".join(item["signals"]).lower()
                 or q in " ".join(item["tags"]).lower()]
    if tag:
        items = [item for item in items if tag in item["tags"]]
    if impact:
        items = [item for item in items if item["impact"] == impact]
    items.sort(key=lambda item: (IMPACT.get(item["impact"], 0),
                                 item["title"].lower()), reverse=True)
    return {"items": items[:max(1, min(int(limit or 20), 100))],
            "total": len(items),
            "note": ("A chain is a hypothesis. Reproduce every link before "
                     "recording a finding.")}


def plan(index, target: str = "", signals: list | None = None,
         tags: list | None = None, limit: int = 4) -> dict:
    parts = [target or ""]
    parts.extend(str(value) for value in (signals or []))
    parts.extend(str(value) for value in (tags or []))
    context = " ".join(parts).strip().lower()
    tokens = {token for token in re.split(r"[^a-z0-9.+#-]+", context) if token}
    ranked = []
    for item in chains():
        signal_hits = [value for value in item["signals"]
                       if value in context or value in tokens]
        tag_hits = [value for value in item["tags"] if value in context or value in tokens]
        step_hits = [value for value in item["steps"] if value in context]
        if context and not (signal_hits or tag_hits or step_hits):
            continue
        score = 3 * len(signal_hits) + 2 * len(tag_hits) + len(step_hits)
        if not context:
            score = IMPACT.get(item["impact"], 0) * 2
        ranked.append({
            "id": item["id"], "title": item["title"], "steps": item["steps"],
            "impact": item["impact"], "proof": item["proof"],
            "tags": item["tags"], "sources": item["sources"],
            "score": score,
            "why": sorted(set(signal_hits + tag_hits + step_hits))[:8],
        })
    if context and not ranked:
        for item in chains():
            ranked.append({
                "id": item["id"], "title": item["title"], "steps": item["steps"],
                "impact": item["impact"], "proof": item["proof"],
                "tags": item["tags"], "sources": item["sources"],
                "score": IMPACT.get(item["impact"], 0) * 2,
                "why": ["general high-impact chain"],
            })
    ranked.sort(key=lambda row: (-row["score"], -IMPACT.get(row["impact"], 0),
                                 row["title"].lower()))
    return {"target": target, "items": ranked[:max(1, min(int(limit or 4), 20))],
            "catalogue": len(chains()),
            "note": ("A chain is a hypothesis; each link needs its own proof.")}


def sources() -> dict:
    by_impact: dict[str, int] = {}
    tags: dict[str, int] = {}
    for item in chains():
        by_impact[item["impact"]] = by_impact.get(item["impact"], 0) + 1
        for tag in item["tags"]:
            tags[tag] = tags.get(tag, 0) + 1
    return {"total": len(chains()), "by_impact": by_impact,
            "tags": dict(sorted(tags.items())),
            "note": "Curated public chains, not target data."}
