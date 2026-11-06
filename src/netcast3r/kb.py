"""The shared knowledge base.

A model's context window is not memory. This is the durable, provider-agnostic
memory the whole control plane shares: technologies seen, endpoint shapes that
mattered, techniques that worked or dead-ended, and chains that were verified.
Every brain reads a digest into its brief, and every finished engagement writes
back what it actually observed, so the reasoning does not live in one model's
context and a different provider inherits the same knowledge instantly.

Two scopes:

- ``global`` entries carry across every mission and provider: a technology, an
  endpoint shape, a technique outcome, a verified chain.
- a mission id keeps target-specific facts next to the mission.

Nothing here is invented. ``learn_from_mission`` only restates what stored
evidence shows - a graph node, a hypothesis outcome, a verified path - and
marks a claim that is not yet observed as ``hypothesis``.

``seed_technique_corpus`` loads the curated critical/high web technique
catalogue into the global scope so every agent and the brain share the same
modern exploit knowledge regardless of which model provider is answering.
"""

from __future__ import annotations

import re

KINDS = {"technology", "service", "endpoint", "parameter", "technique", "chain",
         "credential-path", "dead-end", "signature", "payload", "pattern",
         "lesson", "capability"}
CONFIDENCE = {"observed", "inferred", "hypothesis"}
IMPACT_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_NUMBER = re.compile(r"\d+")


def record(index, scope: str, kind: str, key: str, title: str = "",
           body: str = "", confidence: str = "observed",
           source: dict | None = None, data: dict | None = None) -> dict:
    kind = str(kind or "").strip().lower()
    if kind and kind not in KINDS:
        # Unknown kinds are still stored; the set is a guide, not a gate.
        pass
    if confidence not in CONFIDENCE:
        confidence = "observed"
    return index.upsert_kb_entry(str(scope or "global"), kind, key,
                                 title=title, body=body, confidence=confidence,
                                 source=source, data=data)


def search(index, query: str = "", scope: str = "", kind: str = "",
           limit: int = 50, bump: bool = False) -> list[dict]:
    rows = index.list_kb_entries(scope=scope, kind=kind, q=query, limit=limit)
    if bump:
        for row in rows:
            index.bump_kb_hit(row["id"])
    return rows


def seed_technique_corpus(index, impacts: tuple[str, ...] = ("critical", "high"),
                          force: bool = False) -> dict:
    """Upsert the curated technique catalogue into the global shared KB.

    Critical and high-impact web techniques are seeded on control-plane boot so
    every brain, swarm role, and MCP agent inherits the same corpus. Entries are
    idempotent by key; re-running refreshes titles/bodies when the catalogue
    grows.
    """
    from . import research as research_module

    wanted = {str(i).lower() for i in impacts}
    seeded = skipped = 0
    for item in research_module.techniques():
        impact = str(item.get("impact") or "medium").lower()
        if wanted and impact not in wanted:
            skipped += 1
            continue
        tech_id = str(item.get("id") or "").strip()
        if not tech_id:
            continue
        title = str(item.get("title") or tech_id)
        steps = item.get("steps") or []
        proof = str(item.get("proof") or "")
        signals = ", ".join(str(s) for s in (item.get("signals") or [])[:8])
        tags = ", ".join(str(t) for t in (item.get("tags") or [])[:8])
        body = (
            f"[{impact.upper()}] {item.get('class') or 'web'} | "
            f"signals: {signals}. "
            f"Proof: {proof[:280]} "
            f"Steps: " + " -> ".join(str(s)[:80] for s in steps[:4])
            + (f" Tags: {tags}." if tags else "")
        )
        record(
            index, "global", "technique", f"corpus:{tech_id}",
            title=f"{impact}: {title}",
            body=body[:1800],
            confidence="hypothesis",
            source={"catalogue": "techniques.json", "technique_id": tech_id,
                    "impact": impact},
            data={"technique_id": tech_id, "impact": impact,
                  "class": item.get("class"), "rarity": item.get("rarity"),
                  "tags": list(item.get("tags") or [])[:12],
                  "sources": list(item.get("sources") or [])[:4]})
        seeded += 1
    return {
        "seeded": seeded,
        "skipped": skipped,
        "catalogue": len(research_module.techniques()),
        "impacts": sorted(wanted),
        "force": bool(force),
        "note": ("Technique corpus entries are shared hypotheses until a mission "
                 "observes them; they never become findings by themselves."),
    }


def corpus_digest(limit: int = 24, impact: str = "critical") -> list[dict]:
    """Compact catalogue view for prompts (does not require SQLite)."""
    from . import research as research_module

    rank = IMPACT_RANK
    want = str(impact or "critical").lower()
    allow = {
        "critical": {"critical", "high"},
        "high": {"critical", "high"},
        "all": None,
    }.get(want, {"critical", "high"})
    items = []
    for item in research_module.techniques():
        imp = str(item.get("impact") or "medium").lower()
        if allow is not None and imp not in allow:
            continue
        items.append({
            "id": item.get("id"),
            "title": item.get("title"),
            "impact": imp,
            "class": item.get("class"),
            "proof": str(item.get("proof") or "")[:160],
            "tags": list(item.get("tags") or [])[:6],
        })
    items.sort(key=lambda row: (rank.get(row["impact"], 9),
                                str(row.get("title") or "").lower()))
    return items[:max(1, min(int(limit or 24), 80))]


def digest(index, mission_id: str, limit: int = 12) -> list[dict]:
    """The memory a brain reads before it plans: corpus + global + mission."""
    limit = max(1, min(int(limit or 12), 80))
    # Ensure the shared technique corpus is present for every provider.
    try:
        existing = index.list_kb_entries(scope="global", kind="technique",
                                         limit=8)
        if len(existing) < 8:
            seed_technique_corpus(index)
    except Exception:  # noqa: BLE001 - digest must never raise
        pass

    def _pack(row: dict) -> dict:
        return {
            "kind": row.get("kind", ""),
            "title": row.get("title", ""),
            "body": str(row.get("body") or "")[:280],
            "confidence": row.get("confidence", "observed"),
            "scope": row.get("scope", "global"),
        }

    def _impact_rank(row: dict) -> tuple:
        title = str(row.get("title") or "").lower()
        impact = 3
        if title.startswith("critical:"):
            impact = 0
        elif title.startswith("high:"):
            impact = 1
        return (impact, -int(row.get("hits") or 0),
                str(row.get("updated_at") or ""))

    corpus_rows: list[dict] = []
    other_rows: list[dict] = []
    seen: set[str] = set()
    try:
        for row in index.list_kb_entries(scope="global", kind="technique",
                                         limit=max(limit * 3, 60)):
            key = str(row.get("key") or "")
            title = str(row.get("title") or "").lower()
            if key.startswith("corpus:") or title.startswith(("critical:", "high:")):
                if row["id"] not in seen:
                    corpus_rows.append(row)
                    seen.add(row["id"])
    except Exception:  # noqa: BLE001
        pass
    observation_kinds = (
        "technology", "service", "endpoint", "parameter", "pattern",
        "lesson", "signature", "payload", "dead-end", "chain", "capability",
        "credential-path")
    for scope in ("global", mission_id):
        if not scope:
            continue
        try:
            # Query observation kinds directly so corpus techniques cannot
            # exhaust the SQLite LIMIT window before nginx/endpoints appear.
            for kind in observation_kinds:
                for row in index.list_kb_entries(
                        scope=scope, kind=kind, limit=max(8, limit)):
                    if row["id"] in seen:
                        continue
                    seen.add(row["id"])
                    other_rows.append(row)
            if scope == mission_id:
                for row in index.list_kb_entries(scope=scope, limit=limit * 2):
                    if row["id"] in seen:
                        continue
                    seen.add(row["id"])
                    other_rows.append(row)
        except Exception:  # noqa: BLE001
            pass
    corpus_rows.sort(key=_impact_rank)
    # hits desc, then newest. The old tuple used -hits AND reverse=True, which
    # inverted the proven-first ordering and pushed old knowledge out.
    other_rows.sort(key=lambda row: (int(row.get("hits") or 0),
                                     str(row.get("updated_at") or "")),
                    reverse=True)
    # Split the brief: half critical/high corpus, half lived observations so
    # agents keep both modern exploit knowledge and mission-specific memory.
    half = max(0, limit // 2)
    corpus_slots = min(len(corpus_rows), half)
    other_slots = limit - corpus_slots
    if len(other_rows) < other_slots:
        corpus_slots = min(len(corpus_rows),
                           corpus_slots + (other_slots - len(other_rows)))
        other_slots = limit - corpus_slots
    selected = [*corpus_rows[:corpus_slots], *other_rows[:other_slots]]
    out = [_pack(row) for row in selected]
    for row in selected:
        try:
            index.bump_kb_hit(row["id"])
        except Exception:  # noqa: BLE001 - a hit count must never raise
            pass
    return out


def _endpoint_pattern(url: str) -> str:
    """A host-agnostic shape: numeric segments become {n}."""
    text = str(url or "")
    path = text
    if "://" in text:
        from urllib.parse import urlsplit
        try:
            path = urlsplit(text).path or "/"
        except ValueError:
            path = text
    return _NUMBER.sub("{n}", path)[:200]


def learn_from_mission(index, mission_id: str) -> dict:
    """Write back what this mission's stored evidence shows. Idempotent."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    host = ""
    target = str(mission.get("target") or "")
    if target:
        from urllib.parse import urlsplit
        try:
            host = (urlsplit(target if "://" in target else f"https://{target}")
                    .hostname or "")
        except ValueError:
            host = ""
    counts = {"technology": 0, "endpoint": 0, "technique": 0, "dead-end": 0,
              "chain": 0}

    for node in index.list_graph_nodes(mission_id):
        kind = str(node.get("kind") or "")
        label = str(node.get("label") or node.get("key") or "").strip()
        if not label:
            continue
        if kind in {"technology", "service"}:
            record(index, "global", kind, label.lower(), title=label,
                   body=f"Observed on {host}: {label}",
                   confidence=node.get("confidence") or "observed",
                   source={"mission_id": mission_id, "node_id": node.get("id")})
            counts["technology"] += 1
        elif kind == "endpoint":
            pattern = _endpoint_pattern(node.get("key") or label)
            if len(pattern) > 1:
                record(index, "global", "endpoint", pattern,
                       title=pattern,
                       body=f"Endpoint shape seen on {host}",
                       source={"mission_id": mission_id, "node_id": node.get("id")})
                counts["endpoint"] += 1

    for hyp in index.list_hypotheses(mission_id=mission_id, limit=200)[0]:
        status = str(hyp.get("status") or "open")
        if status in {"open", "archived", "inconclusive"}:
            continue
        technique = str(hyp.get("technique") or "").strip() or "general"
        title = str(hyp.get("title") or technique)
        hyp_id = str(hyp.get("id") or "")
        key = (f"{technique}:{status}:{host}:{title}:{hyp_id[-6:]}"
               .lower()[:200])
        if status == "refuted":
            kind, body = "dead-end", (
                f"Refuted on {host}: {title}. Expected: "
                f"{hyp.get('expected') or 'n/a'}. Do not re-run the same test.")
            counts["dead-end"] += 1
        else:
            kind, body = "technique", (
                f"{status.capitalize()} on {host}: {title} ({technique}).")
            counts["technique"] += 1
        record(index, "global", kind, key, title=title, body=body,
               confidence="observed",
               source={"mission_id": mission_id, "hypothesis_id": hyp.get("id")})

    for path in index.list_graph_paths(mission_id):
        if str(path.get("state")) != "verified":
            continue
        steps = path.get("steps") or []
        key = f"chain:{host}:{path.get('title')}".lower()[:200]
        record(index, "global", "chain", key,
               title=str(path.get("title") or "verified chain"),
               body=("Verified chain on " + (host or "target") + ": " +
                     " -> ".join(str(s.get("goal") or s.get("kind") or "step")
                                 for s in steps)[:600]),
               source={"mission_id": mission_id, "path_id": path.get("id")})
        counts["chain"] += 1

    return counts


def stats(index) -> dict:
    rows = index.list_kb_entries(limit=1000)
    by_kind: dict = {}
    by_scope: dict = {}
    for row in rows:
        by_kind[row.get("kind", "")] = by_kind.get(row.get("kind", ""), 0) + 1
        by_scope[row.get("scope", "global")] = by_scope.get(row.get("scope", "global"), 0) + 1
    return {"total": len(rows), "by_kind": by_kind, "by_scope": by_scope}
