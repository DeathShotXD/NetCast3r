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
"""

from __future__ import annotations

import re

KINDS = {"technology", "service", "endpoint", "parameter", "technique", "chain",
         "credential-path", "dead-end", "signature", "payload", "pattern",
         "lesson", "capability"}
CONFIDENCE = {"observed", "inferred", "hypothesis"}

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


def digest(index, mission_id: str, limit: int = 12) -> list[dict]:
    """The memory a brain reads before it plans: global plus this mission."""
    merged: dict[str, dict] = {}
    for scope in ("global", mission_id):
        if not scope:
            continue
        for row in index.list_kb_entries(scope=scope, limit=limit * 2):
            merged.setdefault(row["id"], row)
    ordered = sorted(merged.values(),
                     key=lambda row: (int(row.get("hits") or 0),
                                      row.get("updated_at") or ""),
                     reverse=True)
    out = []
    for row in ordered[:limit]:
        out.append({
            "kind": row.get("kind", ""),
            "title": row.get("title", ""),
            "body": str(row.get("body") or "")[:240],
            "confidence": row.get("confidence", "observed"),
            "scope": row.get("scope", "global"),
        })
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
        if status == "open":
            continue
        technique = str(hyp.get("technique") or "").strip() or "general"
        title = str(hyp.get("title") or technique)
        key = f"{technique}:{status}:{host}:{title}".lower()[:200]
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
