"""Second-brain peer harness coordination.

When a heavier coding agent (OpenCode, Cursor, Hermes, Claude Code, ...) connects
over MCP, Helix becomes the local steward / second brain: it keeps multi-target
bounty hunting moving on free MoE lanes while the peer runs deeper reasoning,
code edits, and scenario-specific upgrades. Both sides compound into the same
lesson / skill memory.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import control, harness

HEAVY_CLIENTS = {
    "opencode", "cursor", "hermes", "claude", "claude-code", "claude code",
    "windsurf", "codex", "aider", "continue", "copilot", "zed", "vscode",
    "chatgpt", "openai", "gemini-cli", "amp",
}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _client_name(state: dict | None) -> str:
    if not isinstance(state, dict):
        return ""
    client = state.get("client") if isinstance(state.get("client"), dict) else {}
    return str(client.get("name") or state.get("actor") or "").strip()


def _is_heavy(name: str) -> bool:
    needle = str(name or "").strip().lower()
    if not needle:
        return False
    return any(token in needle for token in HEAVY_CLIENTS)


def peers(base: str | Path | None = None) -> dict:
    """Live MCP peer (if any) and whether it outranks Helix for heavy work.

    A peer stays attached while either its own pid is alive, or the NetCast3r
    control plane is alive and the peer registered as a heavy client bound to
    that plane (Cursor / OpenCode agents often share the UI process lifetime).
    """
    state = control.read_mcp_state(base)
    public = {key: value for key, value in (state or {}).items() if key != "token"}
    pid = int((state or {}).get("pid") or 0)
    alive = bool(public and control.pid_alive(pid))
    if not alive and public:
        plane = control.read_control_plane(base) or {}
        plane_pid = int(plane.get("pid") or 0)
        bound = int((state or {}).get("plane_pid") or 0)
        if plane_pid and control.pid_alive(plane_pid) and (
                bound in (0, plane_pid) or _is_heavy(_client_name(state))):
            alive = True
    name = _client_name(state) if alive else ""
    heavy = alive and _is_heavy(name)
    return {
        "connected": alive,
        "client": name,
        "version": str(((state or {}).get("client") or {}).get("version") or ""),
        "heavy": heavy,
        "calls": int((state or {}).get("calls") or 0),
        "last_call_at": str((state or {}).get("last_call_at") or ""),
        "policy": str((state or {}).get("policy") or ""),
        "transport": str((state or {}).get("transport") or ""),
    }


def status(index, base: str | Path | None = None) -> dict:
    """Role map for Helix vs connected peer harness."""
    peer = peers(base)
    role = "second" if peer.get("heavy") else "primary"
    return {
        "ok": True,
        "generated_at": _now(),
        "helix_role": role,
        "peer": peer,
        "can_self_upgrade": bool(peer.get("heavy")),
        "can_apply_code": False,
        "upgrade_policy": "human-review-quarantine",
        "co_hunt": True,
        "note": (
            "Helix is the second brain while a heavy MCP harness is connected: "
            "Helix stewards multi-target bounty hunts on free MoE lanes; the peer "
            "handles deep reasoning and may propose upgrades. Generated code is "
            "quarantined for human review and is never applied to the running "
            "framework automatically."
            if peer.get("heavy") else
            "No heavy peer harness connected. Helix is the primary steward and "
            "runs the free MoE catalogue across TokenHarbor keys."
        ),
    }


def sync_learning(index, mission_id: str = "", peer_note: str = "",
                  peer_name: str = "") -> dict:
    """Mutual learning tick: reflect failures and optionally ingest a peer note."""
    learned = harness.learn_tick(index, mission_id=mission_id)
    ingested = None
    note = str(peer_note or "").strip()
    if note:
        title = f"Peer harness insight ({peer_name or 'mcp'})"
        try:
            lesson = index.add_lesson(
                title[:200], note[:4000],
                technique="peer-sync", outcome="observation",
                context="second_brain.sync",
                next_step="Apply on the next falsifiable lead in scope",
                tags=["second-brain", "peer", "shared"],
                mission_id=str(mission_id or ""),
                source=f"peer:{peer_name or 'mcp'}", confidence=0.55)
            ingested = {"id": lesson.get("id"), "title": lesson.get("title")}
        except Exception as exc:  # noqa: BLE001
            ingested = {"error": f"{type(exc).__name__}: {exc}"}
    return {
        "helix_role": status(index, None).get("helix_role"),
        "learned": learned,
        "peer_lesson": ingested,
        "generated_at": _now(),
    }


def self_upgrade(index, base: str | Path | None, *, title: str, rationale: str,
                 body: str = "", area: str = "exploit", apply_code: bool = False,
                 filename: str = "", peer_heavy: bool = False) -> dict:
    """Record an upgrade and quarantine generated code for human review.

    Peer identity is not an authorization to write executable code. Any body
    that is applied is written under ``upgrades/quarantine`` and the proposal
    stays ``proposed``; nothing is imported, executed, or written into the
    running package. A human moves a reviewed file out of quarantine.
    """
    title = str(title or "").strip()
    rationale = str(rationale or "").strip()
    body = str(body or "").strip()
    if not title or not rationale:
        raise ValueError("self_upgrade needs title and rationale")
    evidence = body[:4000] if body else "peer harness requested a scenario upgrade"
    proposal = index.add_upgrade_proposal(
        title[:200], rationale[:4000], evidence,
        area=str(area or "exploit")[:80],
        priority="high" if peer_heavy else "medium")
    written = None
    skill = None
    if apply_code and body:
        # Quarantine, not the active upgrades directory. Generated code is
        # data until a human reviews it; the running framework never changes
        # because a peer is connected.
        root = control.base_dir(base) / "upgrades" / "quarantine"
        root.mkdir(parents=True, exist_ok=True)
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "-"
                       for ch in (filename or title.lower().replace(" ", "-")))
        safe = (safe or "scenario").strip(".-")[:80]
        if not safe.endswith((".py", ".md", ".txt")):
            safe += ".py"
        path = root / safe
        path.write_text(body, encoding="utf-8")
        written = {"path": str(path), "bytes": path.stat().st_size,
                   "quarantined": True}
        try:
            index.update_upgrade_proposal(
                proposal["id"],
                rationale=(f"{rationale}\n\nQuarantined at {path}; not active. "
                           "A human must review and move it."))
            proposal = index.get_upgrade_proposal(proposal["id"]) or proposal
        except Exception:  # noqa: BLE001
            pass
    if body and len(body) >= 120:
        name = f"upgrade-{safe if written else title.lower().replace(' ', '-')}"[:64]
        name = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name)
        try:
            skill = index.upsert_skill(
                name=name or "upgrade-scenario",
                body=body[:12000],
                title=title[:200],
                description=rationale[:400],
                tags=["second-brain", "upgrade", str(area or "exploit")],
                source="second_brain:self_upgrade")
            skill = index.set_skill_status(name, "draft") or skill
        except Exception as exc:  # noqa: BLE001
            skill = {"error": f"{type(exc).__name__}: {exc}"}
    return {
        "proposal": proposal,
        "written": written,
        "skill": skill,
        "can_self_upgrade": bool(peer_heavy),
        "generated_at": _now(),
        "note": ("Upgrade quarantined under upgrades/quarantine and drafted as a "
                 "skill. A human must review and move it; nothing was activated."
                 if written else
                 "Upgrade proposal recorded. Generated code is quarantined for "
                 "human review; a connected peer is not an authorization."),
    }
