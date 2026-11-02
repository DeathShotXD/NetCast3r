"""Scheduled missions: Once / Weekly verify-again plans.

Adds a schedule and a verify-again mode that reuses a stored auth profile and
queues a director direction when due.

Schedules never widen scope and never create findings. They queue a direction
and let the director run the mission under its existing autonomy gates.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


MODES = {"once", "weekly", "verify_again"}


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime | None = None) -> str:
    return (value or _utc()).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(stamp: str) -> datetime | None:
    text = str(stamp or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def create(index, mission_id: str, *, name: str = "", mode: str = "weekly",
           run_at: str = "", auth_profile: str = "", note: str = "") -> dict:
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    mode = str(mode or "weekly").strip().lower()
    if mode not in MODES:
        raise ValueError(f"unknown schedule mode: {mode}")
    when = _parse(run_at) or (_utc() + timedelta(days=7 if mode == "weekly" else 0))
    return index.create_schedule(
        mission_id=mission_id,
        name=str(name or f"{mode} for {mission.get('title') or mission_id}")[:160],
        mode=mode,
        run_at=_stamp(when),
        auth_profile=str(auth_profile or "")[:120],
        note=str(note or "")[:2000],
    )


def list_schedules(index, mission_id: str = "", status: str = "active",
                   limit: int = 50) -> list[dict]:
    return index.list_schedules(mission_id=mission_id, status=status, limit=limit)


def due(index, now: datetime | None = None) -> list[dict]:
    stamp = _stamp(now or _utc())
    return index.list_due_schedules(before=stamp, limit=50)


def fire(index, schedule: dict) -> dict:
    """Queue a verify-again direction and advance the schedule clock."""
    mission_id = str(schedule.get("mission_id") or "")
    if not mission_id or not index.get_mission(mission_id):
        raise ValueError("mission not found")
    mode = str(schedule.get("mode") or "weekly")
    profile = str(schedule.get("auth_profile") or "").strip()
    body = (
        f"Scheduled {mode}: re-verify the authorised surface"
        + (f" with auth profile `{profile}`" if profile else "")
        + ". Prefer candidate_poc_verify on open candidates, then a surface "
          "diff against the previous web2root map. Do not widen scope."
    )
    if schedule.get("note"):
        body += f" Operator note: {schedule['note']}"
    direction = index.create_direction(mission_id, body, created_by="schedule")
    next_at = None
    status = "active"
    if mode == "once":
        status = "done"
    elif mode in {"weekly", "verify_again"}:
        next_at = _stamp(_utc() + timedelta(days=7))
    updated = index.patch_schedule(
        schedule["id"], status=status, last_run_at=_stamp(),
        run_at=next_at or schedule.get("run_at"),
        last_direction_id=direction.get("id") or "")
    return {"schedule": updated, "direction": direction}
