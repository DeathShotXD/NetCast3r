"""Solve an arbitrary lab, not just a scripted one.

Thirteen lab families ship as deterministic recipes. The catalogue has hundreds.
This module covers the rest with the machinery that already exists: the managed
browser provisions a lab instance and later reads the Academy solved banner; the
bounded solver drives the scoped HTTP tools against that instance; and the
training record only accepts a solve after the banner is observed.

Nothing here bypasses a control. The solver's calls go through the same tool
registry, scope checks, and audit as every other agent. A lab is not a bounty
target: the mission it creates is a training mission, excluded from Prime and
the director.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

from . import browser, training
from .mcp.tools import ToolContext, ToolRegistry
from .model_solver import Solver

MAX_STEPS = 8
MIN_LESSON = 20
SOLVED_HINT = "solved"


def _default_complete(server):
    from .config import load_config
    from .providers import ProviderBus
    from .server.runner import DashboardBridge

    config = load_config()
    try:
        DashboardBridge(server.index, server.keys).apply(config)
    except Exception:  # noqa: BLE001
        pass
    bus = ProviderBus(config, timeout=45.0)

    def call(messages):
        # Training lane: prefer th-learn-* TokenHarbor keys so lab solving
        # never burns the hunt pool under rate limits.
        completion = bus.complete("training", messages, timeout=45.0,
                                  max_candidates=8)
        return {"text": completion.text or "",
                "provider": completion.provider or "",
                "model": completion.model or "",
                "error": completion.error or ""}

    return call


def _provision(server, lab: dict) -> str:
    """Launch the lab through the managed browser and return the instance URL."""
    runner = server._labs()
    return str(runner._browser_instance(lab["url"]) or "").rstrip("/")


def _verify(server, lab: dict) -> str:
    """Return the Academy solved text, or an empty string when not solved."""
    state = browser.state("portswigger", base=server.base)
    if not state.get("running"):
        return ""
    try:
        browser.goto("portswigger", lab["url"], base=server.base)
        snap = browser.snapshot("portswigger", base=server.base)
    except Exception:  # noqa: BLE001 - a browser failure is not a solve
        return ""
    text = "\n".join(str(item.get("text") or item.get("name") or "")
                     for item in snap.get("items") or [])
    return text if training.verify_signal(text) else ""


def _mission(index, lab: dict, instance: str) -> dict:
    academy = (lab.get("source") or "portswigger") == "portswigger"
    title = f"Training lab: {lab['slug']}"
    host = urlsplit(instance).hostname or ""
    scope = [entry for entry in [host, *(lab.get("hosts") or [])] if entry]
    target = "https://portswigger.net/" if academy else instance
    missions, _ = index.list_missions(limit=500)
    existing = next((mission for mission in missions
                     if mission.get("title") == title), None)
    if existing:
        return index.patch_mission(existing["id"], status="active",
                                   target=target,
                                   scope=scope) or existing
    return index.create_mission(
        title, target,
        objective=str(lab.get("objective") or lab["title"]),
        status="active", autonomy="autonomous", scope=scope)


def _pick(index, slug: str = "") -> dict | None:
    if slug:
        return training.find_lab(slug)
    plan = training.plan(index, limit=30)
    items = [item for item in plan.get("items") or []
             if item.get("status") != "solved"]
    # The Academy publishes a machine-verifiable solved banner; prefer it.
    for item in items:
        if (item.get("source") or "portswigger") == "portswigger":
            return training.find_lab(item["slug"]) or item
    return training.find_lab(items[0]["slug"]) if items else None


def _log(index, slug: str, message: str, data: dict | None = None) -> None:
    try:
        index.add_director_log("lab-solve", f"{slug or 'auto'}: {message}",
                               data=data or {})
    except Exception:  # noqa: BLE001 - logging must never stop a solve
        pass


def solve_next(server, index, slug: str = "", complete=None, provision=None,
               verify=None, max_steps: int = MAX_STEPS,
               timeout: float = 300.0) -> dict:
    """Solve one lab end to end and record it only after verification."""
    lab = _pick(index, slug)
    if not lab:
        _log(index, slug, "no unsolved lab in the catalogue")
        return {"started": False, "reason": "no unsolved lab in the catalogue"}
    from .server.lab_runner import RECIPES

    if lab["slug"] in RECIPES and not (provision or verify):
        run = server._labs().start(lab["slug"])
        return {"started": True, "mode": "recipe", "lab": lab["slug"],
                "run_id": run.get("id"), "solved": None}
    if complete is None:
        complete = _default_complete(server)
    academy = (lab.get("source") or "portswigger") == "portswigger"
    if academy:
        instance = (provision or _provision)(server, lab)
        verifier = verify or _verify
    else:
        instance = str(lab.get("url") or "")
        verifier = verify or (lambda server, item: "")
    if not instance:
        _log(index, lab["slug"], "could not provision the lab instance")
        return {"started": False, "lab": lab["slug"],
                "reason": "could not provision the lab instance"}
    mission = _mission(index, lab, instance)
    from .server.exploit_runner import LocalPlane

    registry = ToolRegistry(ToolContext(
        plane=LocalPlane(server), policy="full", base=server.base,
        actor="agent:lab", mission_id=mission["id"], authorized=True))
    goal = " ".join(part for part in (
        str(lab.get("objective") or ""),
        f"Proof required: {lab.get('proof')}" if lab.get("proof") else "",
        "Solve the lab and stop at the proof.") if part)
    solver = Solver(registry, complete, mission["id"], instance, goal=goal,
                    max_steps=max(1, min(int(max_steps or MAX_STEPS), 10)),
                    max_seconds=min(float(timeout), 600.0))
    result = solver.run()
    banner = (verifier)(server, lab)
    solved = bool(banner)
    lesson = str(result.get("summary") or "").strip()
    if solved and len(lesson) < MIN_LESSON:
        lesson = ("Reached the lab proof through the bounded solver: "
                  + banner.strip()[:200])
    evidence = banner.strip()[:2000] or (
        f"solver stopped: {result.get('stop')}; "
        f"{len(result.get('steps') or [])} step(s)")
    try:
        record = training.record(
            index, lab["slug"], "solved" if solved else "in_progress",
            lesson=lesson if solved else "", evidence=evidence,
            notes=str(result.get("summary") or "")[:1000],
            verified=solved, mission_id=mission["id"],
            technique=str(lab.get("category") or ""))
    except Exception as exc:  # noqa: BLE001 - a record failure must not lose the run
        record = {"error": f"{type(exc).__name__}: {exc}"}
    outcome = {
        "started": True, "mode": "solver", "lab": lab["slug"],
        "title": lab.get("title", ""), "instance": instance,
        "mission_id": mission["id"], "solved": solved,
        "banner": banner.strip()[:400],
        "stop": result.get("stop"), "steps": len(result.get("steps") or []),
        "record": record.get("progress") if isinstance(record, dict) else {},
        "note": "A lab is recorded only when the Academy banner is observed.",
    }
    _log_result(index, outcome)
    return outcome


def _log_result(index, result: dict) -> None:
    if not result.get("started"):
        return
    state = "solved" if result.get("solved") else "not solved"
    _log(index, str(result.get("lab") or ""),
         f"{state} via {result.get('mode')} after "
         f"{result.get('steps') or 0} step(s)", result)
