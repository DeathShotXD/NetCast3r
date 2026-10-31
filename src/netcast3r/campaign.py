"""The campaign stage machine.

A user should be able to hand NetCast3r a bare domain and let it progress the
engagement itself. This is the state that makes that visible and deterministic:
which stage the mission is in, why, and which brain should run next.

Stages: recon -> fingerprint -> surface -> hypotheses -> verify -> chain ->
report. The stage is computed from stored evidence only - the target profile,
graph endpoints, open hypotheses, verified paths, findings - so it never claims
progress the mission did not make. Each finished run re-derives the stage, so a
mission matures as the evidence grows.
"""

from __future__ import annotations

import time

STAGES = ("recon", "fingerprint", "surface", "hypotheses", "verify", "chain",
          "report")

# Which brain runs a stage. The director starts that mode; enrichment and
# verification are deterministic steps it runs itself.
STAGE_MODE = {
    "recon": "hunt",
    "fingerprint": "hunt",
    "surface": "autopilot",
    "hypotheses": "swarm",
    "verify": "swarm",
    "chain": "swarm",
    "report": "autopilot",
}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def stage_of(index, mission_id: str) -> dict:
    """Compute the current stage from evidence. Reads only."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    profile = index.get_target_profile(mission_id)
    endpoints = len(index.list_graph_nodes(mission_id, kind="endpoint"))
    _, open_leads = index.list_hypotheses(mission_id=mission_id, status="open",
                                          limit=1)
    _, all_leads = index.list_hypotheses(mission_id=mission_id, limit=1)
    paths = index.list_graph_paths(mission_id)
    verified = [p for p in paths if str(p.get("state")) == "verified"]
    findings = int(mission.get("finding_count") or 0)
    runs = int(mission.get("run_count") or 0)

    if findings:
        stage, reason = "report", f"{findings} finding(s) recorded; report is ready"
    elif verified:
        stage, reason = "chain", (
            f"{len(verified)} verified path(s); chain toward the next impact")
    elif open_leads:
        stage, reason = "verify", f"{open_leads} open lead(s) to test"
    elif all_leads:
        stage, reason = "hypotheses", (
            "every lead is resolved; derive new leads from the surface")
    elif endpoints:
        stage, reason = "hypotheses", (
            f"{endpoints} endpoint(s) in the graph; record falsifiable leads")
    elif profile:
        stage, reason = "surface", "profile built; map the surface"
    else:
        stage, reason = "recon", (
            "no profile yet; fingerprint and probe the target"
            if runs else "nothing observed yet; begin recon")

    return {"mission_id": mission_id, "stage": stage, "mode": STAGE_MODE[stage],
            "reason": reason, "runs": runs, "endpoints": endpoints,
            "open_leads": open_leads, "total_leads": all_leads,
            "verified_paths": len(verified), "findings": findings,
            "profile": bool(profile)}


def advance(index, mission_id: str) -> dict:
    """Recompute the stage and persist it, keeping a short history."""
    current = stage_of(index, mission_id)
    stored = index.ensure_campaign(mission_id)
    if stored.get("stage") != current["stage"]:
        history = list(stored.get("stages") or [])
        history.append({"stage": current["stage"], "at": _now(),
                        "reason": current["reason"]})
        index.patch_campaign(mission_id, stage=current["stage"],
                             note=current["reason"],
                             stages=history[-40:])
    else:
        index.patch_campaign(mission_id, note=current["reason"])
    merged = dict(current)
    merged["history"] = (index.get_campaign(mission_id) or {}).get("stages") or []
    return merged
