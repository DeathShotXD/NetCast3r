"""Self-evolution: the outcome ledger, maturity, and gap-driven proposals.

The self-model scores capability from training, skills, and findings. This adds
the missing half: what actually happened when the harness tried things. Every
hypothesis outcome, staged candidate, exploit run, and recorded dead end feeds a
technique ledger. From it the harness can see what it is good at, what keeps
failing, and propose a concrete improvement.

It proposes; it never applies. A proposal is a human-gated backlog entry, the
same as the self-model's gap proposals.
"""

from __future__ import annotations

import time

OUTCOMES = ("supported", "refuted", "inconclusive", "open")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ledger(index, limit: int = 500) -> dict:
    """Per-technique outcomes from stored evidence only."""
    rows: dict[str, dict] = {}

    def entry(technique) -> dict:
        key = str(technique or "").strip().lower() or "general"
        return rows.setdefault(key, {
            "technique": key, "supported": 0, "refuted": 0, "inconclusive": 0,
            "open": 0, "candidates": 0, "runs": 0, "verified": 0, "dead_ends": 0,
            "last": ""})

    for hypothesis in index.list_hypotheses(limit=limit)[0]:
        row = entry(hypothesis.get("technique"))
        status = str(hypothesis.get("status") or "open")
        if status in OUTCOMES:
            row[status] += 1
        row["last"] = max(row["last"], str(hypothesis.get("updated_at")
                                           or hypothesis.get("created_at") or ""))
    for candidate in index.list_candidates(limit=limit):
        entry(candidate.get("module_id"))["candidates"] += 1
    for run in index.list_runs(limit=limit)[0]:
        counts = run.get("counts") or {}
        if counts.get("mode") != "exploit":
            continue
        row = entry(counts.get("module_id"))
        row["runs"] += 1
        if counts.get("state") == "verified":
            row["verified"] += 1
    for knowledge in index.list_kb_entries(scope="global", kind="dead-end",
                                           limit=limit):
        technique = str(knowledge.get("key") or "").split(":")[0]
        if technique:
            entry(technique)["dead_ends"] += 1
    for row in rows.values():
        decided = row["supported"] + row["refuted"]
        row["win_rate"] = round(row["supported"] / decided, 2) if decided else None
        row["score"] = (row["supported"] * 3 + row["verified"] * 2
                        + row["candidates"] * 2 - row["refuted"] - row["dead_ends"])
    ordered = sorted(rows.values(), key=lambda item: (-item["score"], item["technique"]))
    return {"techniques": ordered[:60], "total": len(rows),
            "generated_at": _now()}


def maturity(index) -> dict:
    """Capability scores next to real outcomes."""
    from . import selfmodel

    state = selfmodel.snapshot(index)
    table = ledger(index)
    hot = [item for item in table["techniques"]
           if item["supported"] or item["verified"]][:8]
    cold = [item for item in table["techniques"]
            if (item["refuted"] + item["dead_ends"]) >= 2 and not item["supported"]][:8]
    return {"overall": state["overall"], "level": state["level"],
            "dimensions": [{"dimension": dim["dimension"], "score": dim["score"],
                            "level": dim["level"]} for dim in state["dimensions"]],
            "techniques_known": table["total"],
            "hot": [{"technique": item["technique"], "supported": item["supported"],
                     "win_rate": item["win_rate"]} for item in hot],
            "cold": [{"technique": item["technique"], "refuted": item["refuted"],
                      "dead_ends": item["dead_ends"]} for item in cold],
            "note": ("Maturity is the self-model's capability score plus what the "
                     "ledger shows actually worked and what kept failing.")}


def mature_outcomes(index, mission_id: str) -> dict:
    """Bump expertise from a finished mission's real outcome. Idempotent-ish."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    tags = set()
    profile = index.get_target_profile(mission_id) or {}
    for name in profile.get("tech") or []:
        tags.add(str(name).strip().lower())
    for node in index.list_graph_nodes(mission_id, kind="technology"):
        tags.add(str(node.get("key") or node.get("label") or "").strip().lower())
    supports = refutes = 0
    for hypothesis in index.list_hypotheses(mission_id=mission_id, limit=200)[0]:
        status = str(hypothesis.get("status") or "")
        if status == "supported":
            supports += 1
        elif status == "refuted":
            refutes += 1
    outcome = "success" if supports else ("failure" if refutes else "partial")
    if tags and (supports or refutes):
        index.bump_expertise(sorted(tags), outcome)
    return {"tags": sorted(tags), "outcome": outcome, "supports": supports,
            "refutes": refutes}


def scan(index, limit: int = 3) -> dict:
    """Turn gaps and cold techniques into deduplicated, human-gated proposals."""
    from . import selfmodel

    report = selfmodel.propose_gaps(index, limit=limit)
    created = list(report.get("created") or [])
    existing = {(item.get("area"), item.get("title"))
                for item in index.list_upgrade_proposals(limit=500)}
    for item in ledger(index)["techniques"]:
        if item["supported"] or (item["refuted"] + item["dead_ends"]) < 3:
            continue
        title = f"Add a working pattern for {item['technique']}"
        if ("general", title) in existing:
            continue
        try:
            proposal = selfmodel.propose(
                index, title=title,
                rationale=(f"{item['technique']} was refuted or dead-ended "
                           f"{item['refuted'] + item['dead_ends']} times with no "
                           "support. Record a concrete request or payload pattern, "
                           "or stop spending on the class."),
                evidence=(f"outcome ledger: technique={item['technique']}, "
                          f"refuted={item['refuted']}, dead_ends={item['dead_ends']}, "
                          f"candidates={item['candidates']}"),
                area="general", priority="medium")
        except ValueError:
            continue
        created.append(proposal)
        existing.add(("general", title))
    return {"created": created, "gaps": report.get("gaps") or [],
            "note": ("Proposals only, human-gated. Nothing is applied "
                     "automatically.")}
