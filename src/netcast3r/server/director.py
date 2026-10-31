"""The director.

NetCast3r already has brains: the deterministic hunt, the operator, the five
role mesh, the runtime. Each one runs to a budget and stops. The director is
the layer that keeps them moving without an external harness: it wakes on a
tick, asks Prime to rank the portfolio, picks one mission and one brain,
starts a run through the same runners the API uses, watches it to completion,
learns whether the mission actually moved, and ticks again.

It is durable. State lives in the index (``director_state``), so a restart
resumes instead of re-planning, and ``director_log`` is the audit feed.

It is bounded by exactly the same gates every other caller is bound by: the
mission scope, the tool risk tiers, single-use approvals, and the rate limiter.
The director never creates a finding, never decides an approval, and never
submits a report. Its kill switch cancels everything it started.
"""

from __future__ import annotations

import threading
import time

from .events import Event
from .. import prime as prime_module

MIN_TICK = 5.0
MAX_TICK = 300.0
MAX_CONCURRENT = 4
# How long a mission rests after a run before it can be picked again.
BASE_COOLDOWN = 45.0
# Backoff ceiling once a mission keeps producing nothing.
MAX_COOLDOWN = 900.0
# Two no-progress runs in a row (or three failures) parks a mission.
NO_PROGRESS_LIMIT = 2
MAX_MISSION_FAILS = 3
# Per-mode budgets. Deliberately small: the director prefers many short,
# observable runs over one long run that hides its work.
MODE_BUDGETS = {
    "autopilot": {"max_steps": 8, "max_seconds": 420, "max_model_calls": 8},
    "swarm": {"max_steps": 8, "max_seconds": 600, "max_model_calls": 12},
}

DIRECTOR_NOTE = (
    "The director drives one mission at a time through the scoped runners. "
    "It records plans and outcomes, never findings."
)


class Director:
    def __init__(self, server, tick_seconds: float = 15.0,
                 max_concurrent: int = 1):
        self.server = server
        self.prime = prime_module.Prime(server.index)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.tick_seconds = self._clamp_tick(tick_seconds)
        self.max_concurrent = max(1, min(int(max_concurrent), MAX_CONCURRENT))
        self._last_tick = 0.0

    # -- lifecycle ---------------------------------------------------------
    @staticmethod
    def _clamp_tick(value: float) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = 15.0
        return max(MIN_TICK, min(number, MAX_TICK))

    def start(self) -> dict:
        self.server.index.ensure_director_state()
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return self.status()
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop, name="netcast3r-director", daemon=True)
            self._thread.start()
        self.server.index.add_director_log(
            "boot", "director started; scheduling per the scope filter")
        return self.status()

    def shutdown(self, timeout: float = 10.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self._tick()
            except Exception as exc:  # noqa: BLE001 - the loop must survive
                try:
                    self.server.index.add_director_log(
                        "error", f"{type(exc).__name__}: {exc}")
                except Exception:  # noqa: BLE001
                    pass
            wait = max(0.0, self.tick_seconds - (time.monotonic() - started))
            self._stop.wait(wait)

    # -- controls ----------------------------------------------------------
    def engage(self) -> dict:
        state = self.server.index.patch_director_state(
            engaged=1, paused=0, stop_reason="")
        self.server.index.add_director_log("control", "engaged")
        if state.get("scope_filter") in (None, ""):
            self.server.index.patch_director_state(scope_filter="autonomous")
        self.start()
        return self.status()

    def disengage(self, reason: str = "operator") -> dict:
        self.server.index.patch_director_state(
            engaged=0, note=str(reason or "operator"))
        self.server.index.add_director_log("control", f"disengaged ({reason})")
        return self.status()

    def pause(self) -> dict:
        self.server.index.patch_director_state(paused=1)
        self.server.index.add_director_log("control", "paused")
        return self.status()

    def resume(self) -> dict:
        self.server.index.patch_director_state(paused=0)
        self.server.index.add_director_log("control", "resumed")
        self.start()
        return self.status()

    def tune(self, tick_seconds: float | None = None,
             max_concurrent: int | None = None,
             scope_filter: str | None = None) -> dict:
        fields: dict = {}
        if tick_seconds is not None:
            fields["tick_seconds"] = int(self._clamp_tick(tick_seconds))
        if max_concurrent is not None:
            fields["max_concurrent"] = max(1, min(int(max_concurrent),
                                                  MAX_CONCURRENT))
        if scope_filter is not None:
            fields["scope_filter"] = str(scope_filter)
        if fields:
            self.server.index.patch_director_state(**fields)
            self.server.index.add_director_log(
                "control", "tuned", data=fields)
        return self.status()

    def kill(self, all_runs: bool = False, reason: str = "kill switch") -> dict:
        """Stop the harness. Cancels director runs, and every run when asked."""
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        runs = dict(active.get("runs") or {})
        cancelled = []
        for run_id, entry in runs.items():
            runner = str(entry.get("runner") or "solver")
            try:
                if runner == "hunt":
                    self.server._hunts().cancel(run_id)
                else:
                    self.server._solvers().cancel(run_id)
                cancelled.append(run_id)
            except Exception:  # noqa: BLE001 - keep killing
                pass
        if all_runs:
            try:
                for run_id in self.server.index.running_run_ids():
                    if self.server.jobs.cancel(run_id):
                        cancelled.append(run_id)
            except Exception:  # noqa: BLE001
                pass
        active["runs"] = {}
        self.server.index.patch_director_state(
            engaged=0, paused=1, stop_reason=str(reason), active=active)
        self.server.index.add_director_log(
            "kill", f"{reason}: cancelled {len(cancelled)} run(s)",
            data={"cancelled": cancelled, "all": bool(all_runs)})
        return self.status()

    # -- status ------------------------------------------------------------
    def status(self, with_portfolio: bool = False) -> dict:
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        runs = active.get("runs") or {}
        missions = active.get("missions") or {}
        payload = {
            "engaged": bool(state.get("engaged")),
            "paused": bool(state.get("paused")),
            "scope_filter": state.get("scope_filter") or "autonomous",
            "tick_seconds": int(state.get("tick_seconds") or 15),
            "max_concurrent": int(state.get("max_concurrent") or 1),
            "cycles": int(state.get("cycles") or 0),
            "runs_started": int(state.get("runs_started") or 0),
            "stop_reason": state.get("stop_reason") or "",
            "note": state.get("note") or "",
            "last_tick": state.get("last_tick") or "",
            "in_flight": [
                {"run_id": run_id, "mission_id": entry.get("mission_id", ""),
                 "mode": entry.get("mode", ""), "runner": entry.get("runner", ""),
                 "started_at": entry.get("started_at", ""),
                 "age": round(time.time() - float(entry.get("started", 0.0)), 1)}
                for run_id, entry in runs.items()
            ],
            "missions": [
                {"mission_id": mission_id,
                 "last_mode": entry.get("last_mode", ""),
                 "no_progress": int(entry.get("no_progress", 0)),
                 "fails": int(entry.get("fails", 0)),
                 "parked": bool(entry.get("parked")),
                 "last_run": entry.get("last_run", "")}
                for mission_id, entry in missions.items()
            ],
            "eligible": len(self._eligible(state)),
            "running": self._thread is not None and self._thread.is_alive(),
        }
        if with_portfolio:
            payload["portfolio"] = self.prime.decide(limit=5)
        return payload

    def eligibility(self) -> list[dict]:
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        missions_state = active.get("missions") or {}
        rows = []
        for mission in self._all_candidates():
            reason = self._ineligible_reason(mission, state)
            entry = missions_state.get(mission["id"], {})
            rows.append({
                "mission_id": mission["id"],
                "title": mission.get("title", ""),
                "status": mission.get("status", ""),
                "autonomy": mission.get("autonomy", ""),
                "eligible": reason == "",
                "reason": reason or "eligible",
                "parked": bool(entry.get("parked")),
                "no_progress": int(entry.get("no_progress", 0)),
            })
        return rows

    # -- the tick ----------------------------------------------------------
    def _tick(self, force: bool = False) -> dict:
        state = self.server.index.ensure_director_state()
        if not state.get("engaged") and not force:
            return {"action": "idle", "reason": "disengaged"}
        if state.get("paused") and not force:
            return {"action": "idle", "reason": "paused"}
        self._reap()
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        runs = active.get("runs") or {}
        if len(runs) >= int(state.get("max_concurrent") or 1):
            self._touch(active, state)
            return {"action": "wait", "reason": f"{len(runs)} run(s) in flight"}
        if not self._eligible(state):
            self._touch(active, state)
            return {"action": "idle", "reason": "no eligible mission"}
        decision = self.prime.decide(limit=prime_module.MAX_OBJECTIVES)
        chosen = None
        for row in decision["ranked"]:
            if self._busy(row["mission_id"], active):
                continue
            if self._cooldown_left(row["mission_id"], row, active) > 0:
                continue
            if (active.get("missions", {}).get(row["mission_id"], {})
                    .get("parked")):
                continue
            chosen = row
            break
        if chosen is None:
            self._touch(active, state)
            return {"action": "idle",
                    "reason": "every candidate is in flight, cooling down, or parked"}
        return self._start(chosen, active, state)

    # -- eligibility -------------------------------------------------------
    def _all_candidates(self) -> list[dict]:
        missions, _ = self.server.index.list_missions(limit=200)
        return [m for m in missions if not m.get("training")]

    def _eligible(self, state: dict) -> list[dict]:
        return [m for m in self._all_candidates()
                if self._ineligible_reason(m, state) == ""]

    @staticmethod
    def _ineligible_reason(mission: dict, state: dict) -> str:
        if mission.get("training"):
            return "training mission"  # labs are explicit, never auto-driven
        status = str(mission.get("status") or "")
        if status != "active":
            return f"status is {status or 'unknown'}"
        autonomy = str(mission.get("autonomy") or "supervised")
        if autonomy == "manual":
            return "manual: a human drives it"
        filt = str(state.get("scope_filter") or "autonomous")
        if filt == "autonomous" and autonomy != "autonomous":
            return f"scope filter is autonomous, mission is {autonomy}"
        if filt == "supervised" and autonomy not in {"supervised", "autonomous"}:
            return f"scope filter is supervised, mission is {autonomy}"
        if not str(mission.get("target") or "").strip():
            return "no target"
        return ""

    # -- bookkeeping -------------------------------------------------------
    def _busy(self, mission_id: str, active: dict) -> bool:
        for entry in (active.get("runs") or {}).values():
            if entry.get("mission_id") == mission_id:
                return True
        return False

    def _cooldown_left(self, mission_id: str, row: dict, active: dict) -> float:
        entry = (active.get("missions") or {}).get(mission_id) or {}
        last = float(entry.get("last_started") or 0.0)
        if not last:
            return 0.0
        no_progress = int(entry.get("no_progress") or 0)
        cooldown = min(BASE_COOLDOWN * (2 ** no_progress), MAX_COOLDOWN)
        return max(0.0, cooldown - (time.time() - last))

    def _progress(self, mission_id: str) -> dict:
        mission = self.server.index.get_mission(mission_id) or {}
        steps = 0
        for run in mission.get("runs") or []:
            counts = run.get("counts") or {}
            steps += int(counts.get("actions") or counts.get("steps") or 0)
        try:
            # The director's own plan notes are bookkeeping, not mission
            # progress; counting them would make every run look productive.
            notes = [note for note in
                     self.server.index.list_agent_notes(mission_id, limit=500)
                     if not str(note.get("kind") or "").startswith("director.")]
            notes = len(notes)
        except Exception:  # noqa: BLE001
            notes = 0
        try:
            leads = self.server.index.list_hypotheses(
                mission_id=mission_id, status="open", limit=1)[1]
        except Exception:  # noqa: BLE001
            leads = 0
        return {"steps": steps, "notes": notes, "leads": int(leads or 0),
                "findings": int(mission.get("finding_count") or 0)}

    def _reap(self) -> list[dict]:
        """Retire finished runs and update each mission's progress counters."""
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        runs = dict(active.get("runs") or {})
        missions = dict(active.get("missions") or {})
        finished = []
        for run_id, entry in list(runs.items()):
            run = self.server.index.get_run(run_id)
            if run and run.get("status") in {"queued", "running"}:
                continue
            mission_id = str(entry.get("mission_id") or "")
            mstate = dict(missions.get(mission_id) or {})
            before = mstate.get("progress") or {}
            after = self._progress(mission_id)
            if run and run.get("status") == "failed":
                mstate["fails"] = int(mstate.get("fails") or 0) + 1
            if before and all(before.get(key) == after.get(key) for key in after):
                mstate["no_progress"] = int(mstate.get("no_progress") or 0) + 1
            else:
                mstate["no_progress"] = 0
            mstate["progress"] = after
            if (mstate.get("no_progress", 0) >= NO_PROGRESS_LIMIT
                    or mstate.get("fails", 0) >= MAX_MISSION_FAILS):
                mstate["parked"] = True
            missions[mission_id] = mstate
            runs.pop(run_id, None)
            status = (run or {}).get("status", "missing")
            counts = (run or {}).get("counts") or {}
            self.server.index.add_director_log(
                "finish",
                f"{entry.get('mode', '')} {status} for {mission_id}",
                mission_id=mission_id, run_id=run_id,
                data={"status": status, "actions": counts.get("actions", 0),
                      "stop": counts.get("stop", ""),
                      "no_progress": mstate.get("no_progress", 0),
                      "parked": bool(mstate.get("parked"))})
            # Every finished run matures the mission: rebuild the graph, the
            # target profile, the campaign stage, and the shared memory.
            self._mature(mission_id)
            if mstate.get("parked"):
                self.server.index.add_director_log(
                    "parked",
                    "mission parked after no progress or repeated failures",
                    mission_id=mission_id, run_id=run_id)
            finished.append({"run_id": run_id, "mission_id": mission_id,
                             "status": status})
        if finished:
            active["runs"] = runs
            active["missions"] = self._trim_missions(missions)
            self.server.index.patch_director_state(active=active)
        return finished

    @staticmethod
    def _trim_missions(missions: dict) -> dict:
        if len(missions) <= 60:
            return missions
        ordered = sorted(missions.items(),
                         key=lambda item: float(item[1].get("last_started") or 0.0),
                         reverse=True)
        return dict(ordered[:60])

    def _mature(self, mission_id: str) -> dict:
        """Turn a finished run into durable, shared knowledge.

        Rebuild the evidence graph, the target profile, the campaign stage, and
        the knowledge base from the new evidence. This is what makes each
        engagement leave the whole platform more capable, regardless of which
        provider ran it. Every step is derived from stored observations only.
        """
        out: dict = {}
        try:
            from .. import campaign as campaign_module
            from .. import graph as graph_module
            from .. import kb as kb_module
            from .. import target as target_module

            graph_module.rebuild(self.server.index, mission_id)
            try:
                target_module.build_profile(self.server.index, mission_id)
            except ValueError:
                pass  # a mission without a usable target has no profile
            out["learned"] = kb_module.learn_from_mission(self.server.index,
                                                          mission_id)
            stage = campaign_module.advance(self.server.index, mission_id)
            out["stage"] = stage["stage"]
            # In the hypotheses stage there are no open leads: turn the exploit
            # catalog's ready modules into falsifiable leads automatically.
            if stage["stage"] == "hypotheses":
                from .. import exploits as exploits_module

                built = exploits_module.build_hypotheses(self.server.index,
                                                         mission_id, limit=3)
                out["leads_created"] = built["count"]
            self.server.index.add_director_log(
                "mature", f"stage {stage['stage']}: {stage['reason']}",
                mission_id=mission_id,
                data={"stage": stage["stage"], "learned": out["learned"],
                      "verified_paths": stage["verified_paths"],
                      "open_leads": stage["open_leads"]})
        except Exception as exc:  # noqa: BLE001 - maturing must not stop the loop
            try:
                self.server.index.add_director_log(
                    "mature-error", f"{type(exc).__name__}: {exc}",
                    mission_id=mission_id)
            except Exception:  # noqa: BLE001
                pass
        return out

    def _touch(self, active: dict, state: dict) -> None:
        cycles = int(state.get("cycles") or 0) + 1
        self.server.index.patch_director_state(
            cycles=cycles, last_tick=self._stamp(), active=active)

    def _start(self, row: dict, active: dict, state: dict) -> dict:
        mission_id = row["mission_id"]
        mission = self.server.index.get_mission(mission_id)
        if not mission:
            return {"action": "idle", "reason": "mission vanished"}
        mode = row["mode"]
        policy = "full" if mission.get("autonomy") == "autonomous" else "supervised"
        objective = row.get("objective") or {}
        goal = str(objective.get("goal") or mission.get("objective") or "")
        # An operator direction outranks the derived goal for this run.
        queued = self.server.index.list_directions(mission_id, status="queued",
                                                   limit=3)
        if queued:
            goal = f"Operator direction: {queued[0].get('body', '')} | {goal}"
        runs = dict(active.get("runs") or {})
        if mode == "hunt":
            run = self.server._hunts().start(mission_id)
            runner = "hunt"
        else:
            options = {"mode": mode, "policy": policy, "goal": goal}
            options.update(MODE_BUDGETS.get(mode, {}))
            run = self.server._solvers().start(mission_id, options)
            runner = "solver"
        if queued:
            # Mark the directions consumed so a later run does not repeat them.
            self.server.index.consume_directions(mission_id, limit=3,
                                                 run_id=run["id"])
        now = time.time()
        runs[run["id"]] = {
            "mission_id": mission_id, "mode": mode, "runner": runner,
            "started": now, "started_at": self._stamp(),
        }
        missions = dict(active.get("missions") or {})
        mstate = dict(missions.get(mission_id) or {})
        mstate.update({"last_started": now, "last_run": run["id"],
                       "last_mode": mode, "parked": False,
                       "progress": self._progress(mission_id)})
        missions[mission_id] = mstate
        active["runs"] = runs
        active["missions"] = self._trim_missions(missions)
        self.server.index.patch_director_state(
            cycles=int(state.get("cycles") or 0) + 1,
            runs_started=int(state.get("runs_started") or 0) + 1,
            last_tick=self._stamp(), active=active)
        note = (f"Director chose {mode} for '{mission.get('title', '')}' "
                f"(score {row.get('score', 0)}, {row.get('autonomy', '')}). "
                f"Objective: {goal[:200]}")
        try:
            self.server.index.add_agent_note(
                mission_id, "director.plan", f"Director: {mode}", note,
                run_id=run["id"])
        except Exception:  # noqa: BLE001 - a note is best effort
            pass
        self.server.index.add_director_log(
            "start", f"{mode} on {mission.get('title', mission_id)}",
            mission_id=mission_id, run_id=run["id"],
            data={"mode": mode, "policy": policy, "score": row.get("score"),
                  "objective": goal[:300], "autonomy": mission.get("autonomy")})
        try:
            self.server.bus.publish(Event(
                type="director", run_id=run["id"], agent="director",
                stage="reason",
                payload={"text": note, "mode": mode, "mission_id": mission_id}))
        except Exception:  # noqa: BLE001
            pass
        return {"action": "start", "mission_id": mission_id, "mode": mode,
                "run_id": run["id"], "policy": policy, "objective": goal,
                "score": row.get("score")}

    @staticmethod
    def _stamp() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # -- on-demand model advice -------------------------------------------
    def advise(self) -> dict:
        """Rank with the configured model as a second opinion, on request."""
        state = self.server.index.ensure_director_state()
        decision = self.prime.decide(limit=5, use_model=True)
        self.server.index.add_director_log(
            "advice", f"prime advised via {decision.get('source')}",
            data={"source": decision.get("source"),
                  "thought": decision.get("thought", "")})
        return {"scope_filter": state.get("scope_filter"), **decision}
