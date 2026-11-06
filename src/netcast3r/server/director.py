"""The director.

NetCast3r already has brains: the deterministic hunt, the operator, the five
role mesh, the runtime. Each run is short and observable. The director is the
layer that keeps them moving without an external harness: it wakes on a tick,
asks Prime to rank the portfolio, picks one mission and one brain, starts a
run through the same runners the API uses, matures the mission, learns, and
ticks again. An active mission never parks itself - only the operator pause
(or kill switch) stops the continuous hunt.

It is durable. State lives in the index (``director_state``), so a restart
resumes instead of re-planning, and ``director_log`` is the audit feed.

It is bounded by exactly the same gates every other caller is bound by: the
mission scope, the tool risk tiers, single-use approvals, and the rate limiter.
The director never creates a finding, never decides an approval, and never
submits a report. Its kill switch cancels everything it started.
"""

from __future__ import annotations

import calendar
import json
import threading
import time
from urllib.parse import urlsplit

from .events import Event
from .. import prime as prime_module


def _angle_fragment(target: str) -> str:
    """A path fragment that can be compared with a hint label.

    A root URL has no distinguishing path, so it never filters a hint.
    """
    try:
        parts = urlsplit(target if "://" in target else "https://" + target)
    except ValueError:
        return ""
    path = (parts.path or "").strip().lower()
    if path in ("", "/"):
        return ""
    return path

MIN_TICK = 5.0
MAX_TICK = 300.0
# Parallel mission slots - sized for multi-key TokenHarbor hunt lanes.
# Match the TokenHarbor hunt-lane pool (21+ free keys) so MoE can fan out.
MAX_CONCURRENT = 24
# How long a mission rests after a run before it can be picked again.
BASE_COOLDOWN = 45.0
# Backoff ceiling once a mission keeps producing nothing. Never a stop -
# only a longer breath before the next deeper pass.
MAX_COOLDOWN = 300.0
# After this many flat runs, queue a deepen direction and reset the stall
# counter. Missions never park; only the operator pause stops the hunt.
STALL_DEEPEN_AFTER = 3
# How often the director pulls public research feeds into the knowledge base.
KNOWLEDGE_REFRESH_EVERY = 6 * 3600.0
# A model-only brain is not worth starting when the brain loop has logged many
# *hard* failures and no answer inside this window. Transient free-tier 429s
# across a MoE catalogue are not a gate - sibling keys/models still answer.
MODEL_GATE_WINDOW = 900.0
MODEL_GATE_FAILURES = 8
# Per-mode budgets. Deliberately small: the director prefers many short,
# observable runs over one long run that hides its work.
MODE_BUDGETS = {
    "autopilot": {"max_steps": 8, "max_seconds": 420, "max_model_calls": 8},
    "swarm": {"max_steps": 8, "max_seconds": 600, "max_model_calls": 12},
}

DIRECTOR_NOTE = (
    "The director drives active missions continuously until the operator "
    "pauses. It records plans and outcomes, never findings."
)


class Director:
    def __init__(self, server, tick_seconds: float = 10.0,
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
        state = self.server.index.ensure_director_state()
        # The persisted state is the source of truth, so a tuned tick or
        # concurrency survives a restart and matches what status reports.
        self.tick_seconds = self._clamp_tick(state.get("tick_seconds")
                                             or self.tick_seconds)
        self.max_concurrent = max(1, min(
            int(state.get("max_concurrent") or self.max_concurrent),
            MAX_CONCURRENT))
        try:
            self.reconcile_inflight(reason="boot")
        except Exception:  # noqa: BLE001 - never block boot on reconcile
            pass
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

    def _live_run_ids(self) -> set[str]:
        """Run ids that still have an in-process handle right now."""
        live: set[str] = set()
        try:
            live.update(self.server.jobs.active() or [])
        except Exception:  # noqa: BLE001
            pass
        for attr in ("hunt_runner", "solver_runner", "lab_runner",
                     "path_runner", "exploit_runner"):
            runner = getattr(self.server, attr, None)
            if runner is None:
                continue
            handles = getattr(runner, "_handles", None)
            if isinstance(handles, dict):
                live.update(handles.keys())
        return live

    def _busy_run_count(self, runs: dict) -> int:
        """Concurrency slots: live workers + brief start grace, not ghosts."""
        live = self._live_run_ids()
        now = time.time()
        busy = 0
        for run_id, entry in (runs or {}).items():
            if run_id in live:
                busy += 1
                continue
            # Allow a short window for the runner to register its handle
            # (and for FakeHunts in tests that never register one).
            age = now - float((entry or {}).get("started") or 0.0)
            if 0 <= age < 45.0:
                busy += 1
        return busy

    def reconcile_inflight(self, reason: str = "reconcile") -> dict:
        """Drop director in-flight rows that died with the previous process.

        After a UI/API restart, ``JobManager.recover`` marks DB runs
        ``interrupted``, but the director's persisted ``active.runs`` can still
        claim they are flying. Helix and the operator must see the truth.
        Finished/failed runs stay for ``_reap`` so progress accounting still
        runs; only restart ghosts (interrupted / cancelled / missing) go here.
        """
        state = self.server.index.ensure_director_state()
        active = dict(state.get("active") or {})
        runs = dict(active.get("runs") or {})
        if not runs:
            return {"dropped": [], "kept": []}
        live = self._live_run_ids()
        ghost_status = {"interrupted", "cancelled"}
        dropped, kept = [], {}
        for run_id, entry in runs.items():
            if run_id in live:
                kept[run_id] = entry
                continue
            row = self.server.index.get_run(run_id) or {}
            status = str(row.get("status") or "")
            if not row or status in ghost_status:
                dropped.append({"run_id": run_id, "status": status or "missing"})
                continue
            # Still queued/running in the DB with no live handle after a
            # recover=False path or a crashed worker - treat as interrupted.
            age = time.time() - float((entry or {}).get("started") or 0.0)
            stale = status in {"queued", "running"} and (
                reason in {"boot", "recover"} or age > 90.0)
            if stale:
                try:
                    self.server.index.update_run(
                        run_id, status="interrupted", finished_at=self._stamp(),
                        error="director reconcile: no live worker")
                except Exception:  # noqa: BLE001
                    pass
                dropped.append({"run_id": run_id, "status": "interrupted"})
                continue
            kept[run_id] = entry
        if dropped:
            active["runs"] = kept
            self.server.index.patch_director_state(active=active)
            self.server.index.add_director_log(
                "reconcile",
                f"{reason}: dropped {len(dropped)} stale in-flight run(s)",
                data={"dropped": dropped})
        return {"dropped": dropped, "kept": list(kept.keys())}

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
            # Keep the running loop in step with the change.
            if "tick_seconds" in fields:
                self.tick_seconds = self._clamp_tick(fields["tick_seconds"])
            if "max_concurrent" in fields:
                self.max_concurrent = max(1, min(int(fields["max_concurrent"]),
                                                 MAX_CONCURRENT))
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
        # Always reconcile before reporting so Helix never sees ghost scans.
        try:
            self.reconcile_inflight(reason="status")
        except Exception:  # noqa: BLE001
            pass
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        runs = active.get("runs") or {}
        missions = active.get("missions") or {}
        live = set()
        try:
            live.update(self.server.jobs.active() or [])
        except Exception:  # noqa: BLE001
            pass
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
            "live_job_ids": sorted(live),
            "in_flight": [
                {"run_id": run_id, "mission_id": entry.get("mission_id", ""),
                 "mode": entry.get("mode", ""), "runner": entry.get("runner", ""),
                 "started_at": entry.get("started_at", ""),
                 "live": run_id in live,
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
            "model_health": self._model_health(),
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

    def _fire_schedules(self) -> None:
        """Queue due Once/Weekly verify-again directions without starting runs."""
        try:
            from .. import schedule as schedule_module

            for row in schedule_module.due(self.server.index)[:5]:
                try:
                    schedule_module.fire(self.server.index, row)
                    self.server.index.add_director_log(
                        "schedule", f"fired {row.get('id')} ({row.get('mode')})",
                        mission_id=str(row.get("mission_id") or ""))
                except Exception as exc:  # noqa: BLE001
                    self.server.index.add_director_log(
                        "schedule-error",
                        f"{row.get('id')}: {type(exc).__name__}: {exc}",
                        mission_id=str(row.get("mission_id") or ""))
        except Exception:  # noqa: BLE001 - schedules must not stop the director
            pass

    # -- the tick ----------------------------------------------------------
    def _tick(self, force: bool = False) -> dict:
        state = self.server.index.ensure_director_state()
        if not state.get("engaged") and not force:
            return {"action": "idle", "reason": "disengaged"}
        if state.get("paused") and not force:
            return {"action": "idle", "reason": "paused"}
        self._fire_schedules()
        self._refresh_knowledge_if_due(state)
        self._reap()
        try:
            self.reconcile_inflight(reason="tick")
        except Exception:  # noqa: BLE001
            pass
        state = self.server.index.ensure_director_state()
        active = state.get("active") or {}
        # Legacy parks never stick: an active mission keeps hunting until
        # the operator pauses the director.
        self._clear_parks(active)
        runs = active.get("runs") or {}
        busy = self._busy_run_count(runs)
        if busy >= int(state.get("max_concurrent") or 1):
            self._touch(active, state)
            return {"action": "wait", "reason": f"{busy} run(s) in flight"}
        eligible = {mission["id"] for mission in self._eligible(state)}
        # Operator priority hard-locks the director onto one mission until
        # cleared or that mission leaves active. Not eligible means wait:
        # never fill the slot with a different mission.
        priority_id = ""
        try:
            from .. import brain as brain_module
            priority_id = str((brain_module.operator_priority(self.server.index)
                               or {}).get("mission_id") or "")
        except Exception:  # noqa: BLE001
            priority_id = ""
        if priority_id:
            if priority_id not in eligible:
                self._touch(active, state)
                return {"action": "wait",
                        "reason": f"operator priority {priority_id} not eligible"}
            if self._busy(priority_id, active):
                self._touch(active, state)
                return {"action": "wait",
                        "reason": f"operator priority {priority_id} already in flight"}
            mission = self.server.index.get_mission(priority_id) or {}
            # Zero-progress lock escalates hunt -> swarm -> deepen. The next
            # mode is chosen in _reap; a soft 429 never closes this gate.
            chosen = {
                "mission_id": priority_id,
                "mode": self._priority_run_mode(priority_id, active),
                "score": 999,
                "autonomy": mission.get("autonomy") or "autonomous",
                "objective": {"goal": "operator priority hunt"},
            }
            return self._start(chosen, active, state)
        if not eligible:
            self._touch(active, state)
            return {"action": "idle", "reason": "no eligible mission"}
        decision = self.prime.decide(limit=50)
        chosen = None
        for row in decision["ranked"]:
            # The scope filter is authoritative: Prime ranks the whole
            # portfolio, but only an eligible mission may be started.
            if row["mission_id"] not in eligible:
                continue
            if self._busy(row["mission_id"], active):
                continue
            if self._cooldown_left(row["mission_id"], row, active) > 0:
                continue
            chosen = row
            break
        if chosen is None:
            self._touch(active, state)
            return {"action": "idle",
                    "reason": "every candidate is in flight or cooling down"}
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
        budget = mission.get("budget")
        if isinstance(budget, dict) and budget.get("max_runs") is not None:
            try:
                spent = int(mission.get("run_count") or 0)
                if spent >= int(budget["max_runs"]):
                    return f"campaign run budget spent ({spent}/{budget['max_runs']})"
            except (TypeError, ValueError):
                return "campaign budget is malformed"
        if not str(mission.get("target") or "").strip():
            return "no target"
        return ""

    # -- bookkeeping -------------------------------------------------------
    def _clear_parks(self, active: dict) -> None:
        """Drop any legacy parked flags so active missions stay in rotation."""
        missions = dict(active.get("missions") or {})
        changed = False
        for mission_id, entry in list(missions.items()):
            if not entry.get("parked"):
                continue
            entry = dict(entry)
            entry["parked"] = False
            entry.pop("parked_at", None)
            missions[mission_id] = entry
            changed = True
            try:
                self.server.index.add_director_log(
                    "unpark", "continuous hunt resumed; parks disabled",
                    mission_id=mission_id)
            except Exception:  # noqa: BLE001
                pass
        if changed:
            active["missions"] = missions
            self.server.index.patch_director_state(active=active)

    def _refresh_knowledge_if_due(self, state: dict) -> None:
        """Pull public research feeds on a cadence so the mesh keeps learning."""
        active = dict(state.get("active") or {})
        meta = dict(active.get("meta") or {})
        last = float(meta.get("knowledge_refreshed_at") or 0.0)
        if last and time.time() - last < KNOWLEDGE_REFRESH_EVERY:
            return
        try:
            from .. import feedwatch as feedwatch_module

            result = feedwatch_module.refresh(self.server.index, limit=20)
            meta["knowledge_refreshed_at"] = time.time()
            meta["knowledge_last"] = {
                "added": int(result.get("new") or 0),
                "sources": result.get("sources") or [],
                "errors": len(result.get("errors") or []),
            }
            active["meta"] = meta
            self.server.index.patch_director_state(active=active)
            self.server.index.add_director_log(
                "knowledge", "refreshed public research feeds",
                data=meta.get("knowledge_last") or {})
        except Exception as exc:  # noqa: BLE001 - learning must not stop hunts
            try:
                self.server.index.add_director_log(
                    "knowledge-error", f"{type(exc).__name__}: {exc}")
            except Exception:  # noqa: BLE001
                pass

    def _operator_priority_id(self) -> str:
        try:
            from .. import brain as brain_module
            return str((brain_module.operator_priority(self.server.index)
                        or {}).get("mission_id") or "")
        except Exception:  # noqa: BLE001
            return ""

    def _priority_run_mode(self, mission_id: str, active: dict) -> str:
        """Next brain for a locked mission. Never idle, never parked."""
        entry = (active.get("missions") or {}).get(mission_id) or {}
        mode = str(entry.get("next_priority_mode") or "hunt")
        if mode == "deepen":
            return "swarm"
        if mode not in {"hunt", "swarm"}:
            return "hunt"
        return mode

    def _advance_priority_ladder(self, mission_id: str, mstate: dict,
                                 entry: dict, run: dict | None,
                                 before: dict, after: dict) -> None:
        """On zero progress, escalate hunt -> swarm -> deepen and keep going."""
        counts = (run or {}).get("counts") or {}
        try:
            actions = int(counts.get("actions") or counts.get("steps") or 0)
        except (TypeError, ValueError):
            actions = 0
        flat = bool(before) and all(before.get(key) == after.get(key) for key in after)
        failed = str((run or {}).get("status") or "") == "failed"
        zero = failed or actions == 0 or flat
        mode = str((entry or {}).get("mode") or mstate.get("last_mode") or "hunt")
        mstate["parked"] = False
        mstate.pop("parked_at", None)
        if not zero:
            mstate["next_priority_mode"] = "swarm"
            return
        if mode == "hunt":
            mstate["next_priority_mode"] = "swarm"
        else:
            # Swarm (or anything else) with nothing new: queue a deeper angle
            # and hand the next slot to the deterministic hunt so the lock
            # does not spin on an empty model.
            self._queue_deepen(mission_id, mstate)
            mstate["next_priority_mode"] = "hunt"
        try:
            self.server.index.add_director_log(
                "priority-escalate",
                f"{mode} made no progress; next {mstate.get('next_priority_mode')}",
                mission_id=mission_id,
                data={"from": mode, "next": mstate.get("next_priority_mode"),
                      "parked": False, "actions": actions})
        except Exception:  # noqa: BLE001
            pass

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

    def _model_health(self) -> dict:
        """Read the recent brain journal for a model-availability signal.

        This is not a provider probe: a probe costs money and can rate-limit
        the key the hunt needs. It is an observation of what the brain loop
        already experienced. Transient free-tier 429s never close the gate -
        MoE walks sibling models and other TokenHarbor keys. Only repeated
        hard failures with no later success downgrade a model-only brain.
        """
        try:
            rows = self.server.index.list_director_log(limit=250)
        except Exception:  # noqa: BLE001 - a broken log must not stop the hunt
            return {"available": True, "reason": "journal unavailable",
                    "soft_failures": 0, "hard_failures": 0}
        now = time.time()
        last_success = -1.0
        wait_at = -1.0
        wait_text = ""
        hard_failures = 0
        soft_failures = 0
        for row in rows:
            try:
                parsed = calendar.timegm(time.strptime(
                    str(row.get("ts") or ""), "%Y-%m-%dT%H:%M:%SZ"))
                age = now - parsed
            except (ValueError, OverflowError):
                continue
            if age < 0 or age > MODEL_GATE_WINDOW:
                continue
            kind = str(row.get("kind") or "")
            if kind == "brain" and str((row.get("data") or {}).get("model") or ""):
                last_success = max(last_success, age)
            elif kind == "brain-wait":
                message = str(row.get("message") or "")
                soft = any(token in message.lower()
                           for token in ("429", "rate limit", "rate_limited",
                                         "too many requests"))
                if soft:
                    soft_failures += 1
                else:
                    hard_failures += 1
                # ``age`` grows with time, so the *newest* failure has the
                # smallest age. Pick it explicitly instead of relying on the
                # row order: a success between two failure bursts used to keep
                # the gate open forever because the oldest failure won.
                if wait_at < 0 or age < wait_at:
                    wait_at = age
                    wait_text = message[:200]
        # Soft 429s are MoE rotation noise - never close the gate on them alone.
        if hard_failures >= MODEL_GATE_FAILURES and (last_success < 0
                                                     or wait_at < last_success):
            return {"available": False, "failures": hard_failures,
                    "hard_failures": hard_failures, "soft_failures": soft_failures,
                    "reason": wait_text or "no model answered recently",
                    "window_seconds": int(MODEL_GATE_WINDOW)}
        reason = "a model answered recently" if last_success >= 0 \
            else ("free-tier rate limits only; MoE still rotating"
                  if soft_failures else "no recent model failure")
        return {"available": True, "failures": hard_failures,
                "hard_failures": hard_failures, "soft_failures": soft_failures,
                "reason": reason}

    def _gate_mode(self, mode: str) -> tuple[str, str]:
        """Downgrade a model-only brain to the deterministic hunt."""
        if mode == "hunt":
            return mode, ""
        health = self._model_health()
        if health.get("available"):
            return mode, ""
        return "hunt", f"model gate: {health.get('reason', 'no model answered')}"

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
        graph_nodes = graph_edges = covered = 0
        try:
            graph_nodes = len(self.server.index.list_graph_nodes(mission_id))
            graph_edges = len(self.server.index.list_graph_edges(mission_id))
        except Exception:  # noqa: BLE001
            pass
        try:
            from .. import checklists as checklists_module

            counts = (checklists_module.summary(self.server.index, mission_id)
                      or {}).get("counts") or {}
            covered = (int(counts.get("covered") or 0)
                       + int(counts.get("vulnerable") or 0)
                       + int(counts.get("in_progress") or 0))
        except Exception:  # noqa: BLE001
            pass
        return {"steps": steps, "notes": notes, "leads": int(leads or 0),
                "findings": int(mission.get("finding_count") or 0),
                "graph_nodes": graph_nodes, "graph_edges": graph_edges,
                "covered": covered}

    def _spa_shell_signal(self, mission_id: str) -> tuple[bool, int]:
        """Read the latest hunt.map note for an SPA-shell signal.

        When set, path-guessing is settled and the deepen direction should
        steer to the JS bundle instead of more route guessing.
        """
        try:
            notes = self.server.index.list_agent_notes(mission_id, limit=50)
        except Exception:  # noqa: BLE001
            return False, 0
        # list_agent_notes returns oldest-first, so the last match is newest.
        latest = None
        for note in notes:
            if str(note.get("kind") or "") == "hunt.map":
                latest = note
        if not isinstance(latest, dict):
            return False, 0
        body = latest.get("body")
        if isinstance(body, str) and body.strip():
            try:
                body = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return False, 0
        if not isinstance(body, dict) or not body.get("spa_shell"):
            return False, 0
        try:
            return True, int(body.get("shell_bytes") or 0)
        except (TypeError, ValueError):
            return True, 0

    def _queue_deepen(self, mission_id: str, mstate: dict) -> None:
        """When a mission stalls, push a deeper angle instead of stopping."""
        hints: list[str] = []
        try:
            endpoints = self.server.index.list_graph_nodes(
                mission_id, kind="endpoint")[:8]
            for node in endpoints:
                label = str(node.get("label") or node.get("name") or "")[:80]
                if label:
                    hints.append(label)
        except Exception:  # noqa: BLE001
            pass
        if not hints:
            hints = ["auth surfaces", "API object IDs", "OAuth callbacks",
                     "cloud metadata SSRF only after URL sinks are mapped"]
        blocked = self._blocked_angles(mission_id)
        skipped: list[str] = []
        if blocked:
            kept = [hint for hint in hints
                    if not any(fragment in hint.lower() for fragment in blocked)]
            skipped = [hint for hint in hints if hint not in kept]
            if kept:
                hints = kept
            else:
                # Every mapped endpoint is a settled refusal. Point the next
                # run at angles that are not a path replay.
                hints = ["authentication and reset flows", "API object ownership",
                         "OAuth callback handling", "URL-fetching features"]
        spa_shell, shell_bytes = self._spa_shell_signal(mission_id)
        if spa_shell:
            # Path-guessing is settled: the stall is the SPA catch-all, so the
            # deeper angle is the real applicant API, not more shell routes.
            body = (
                "Deepen continuous hunt (stall pivot): path-guessing is "
                f"exhausted - every route returns the {shell_bytes}-byte SPA "
                "shell. Parse the JS bundle for the real applicant API base, "
                "then run BOLA/IDOR on a real /api object endpoint and capture "
                "the raw request AND response before claiming any support. Do "
                "not recreate existing open hypotheses. Never stop."
            )
        else:
            body = (
                "Deepen continuous hunt (stall pivot): probe distinct angles on "
                + "; ".join(hints[:5])
                + ". Capture the raw request AND response for every supported "
                "lead before promotion. Do not recreate existing open "
                "hypotheses. Prefer coverage gaps, auth/IDOR/OAuth, and "
                "PoC-gated promotion. Never stop."
            )
        if skipped:
            body += (" Do not retry an angle already edge-blocked or refused: "
                     + "; ".join(skipped[:5]) + ".")
        try:
            existing = self.server.index.list_directions(
                mission_id, status="queued", limit=20)
            if any("Deepen continuous hunt" in str(d.get("body") or "")
                   for d in existing):
                return
            self.server.index.create_direction(
                mission_id, body, created_by="agent:director")
            self.server.index.add_director_log(
                "deepen", "queued deepen direction after stall",
                mission_id=mission_id,
                data={"no_progress": mstate.get("no_progress"),
                      "hints": hints[:5], "skipped_blocked": skipped[:5]})
        except Exception:  # noqa: BLE001
            pass

    def _blocked_angles(self, mission_id: str) -> list[str]:
        """Return path fragments whose recorded probes were refused.

        A stall used to re-queue the same endpoint even after every probe had
        been stopped by an edge control, which burns the next run on a settled
        question. Read the verdict from the stored responses instead.
        """
        try:
            hypotheses, _ = self.server.index.list_hypotheses(
                mission_id=mission_id, limit=200)
            if not hypotheses:
                return []
            rows, _ = self.server.index.list_tool_calls(
                mission_id=mission_id, limit=4000)
        except Exception:  # noqa: BLE001 - a broken read must not stop a stall
            return []
        if not rows:
            return []
        from .. import verdicts as verdicts_module

        blocked: list[str] = []
        for hypothesis in hypotheses:
            technique = str(hypothesis.get("technique") or "").lower()
            if not any(key in technique for key in ("ssrf", "redirect")):
                continue
            if str(hypothesis.get("status") or "") in {
                    "refuted", "promoted", "archived"}:
                continue
            fragment = _angle_fragment(str(hypothesis.get("target") or ""))
            if not fragment:
                continue
            # Classify only the probes that hit this angle. The mission log
            # mixes hundreds of unrelated requests, and an unrelated 301 must
            # not turn this lead into a redirect.
            subset = [
                row for row in rows
                if fragment in str((row.get("args") or {}).get("target")
                                   or "").lower()]
            if not subset:
                continue
            try:
                verdict = verdicts_module.classify(hypothesis, subset) or {}
            except Exception:  # noqa: BLE001
                continue
            if verdict.get("verdict") not in {"edge-blocked", "blocked"}:
                continue
            blocked.append(fragment)
        return blocked

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
            else:
                mstate["fails"] = 0
            if before and all(before.get(key) == after.get(key) for key in after):
                mstate["no_progress"] = int(mstate.get("no_progress") or 0) + 1
            else:
                mstate["no_progress"] = 0
            mstate["progress"] = after
            # Never park. On a stall, deepen and keep hunting.
            mstate["parked"] = False
            mstate.pop("parked_at", None)
            if mission_id and mission_id == self._operator_priority_id():
                self._advance_priority_ladder(
                    mission_id, mstate, entry, run, before or {}, after)
            if int(mstate.get("no_progress") or 0) >= STALL_DEEPEN_AFTER:
                self._queue_deepen(mission_id, mstate)
                mstate["no_progress"] = 0
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
                      "parked": False})
            # Every finished run matures the mission: rebuild the graph, the
            # target profile, the campaign stage, and the shared memory.
            self._mature(mission_id)
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
            # If the mission still has almost no host nodes, seed a web2root
            # surface map so the next runs have assets to reason over.
            try:
                hosts = self.server.index.list_graph_nodes(mission_id, kind="host")
                if len(hosts) < 2:
                    from .. import web2root as web2root_module

                    mapped = web2root_module.map_surface(
                        self.server.index, mission_id, depth="standard",
                        probe_limit=25)
                    out["web2root"] = {
                        "hosts_live": mapped.get("hosts_live"),
                        "hosts_discovered": mapped.get("hosts_discovered"),
                    }
            except Exception:  # noqa: BLE001 - mapping must not stop maturing
                pass
            # After a foothold / exploit stage, queue a post-ex plan so the
            # next autonomous run continues lateral/cloud/identity work.
            try:
                stage = (campaign_module.stage_of(self.server.index, mission_id)
                         or {}).get("stage")
                if stage in {"exploit", "chain"}:
                    from .. import postex as postex_module

                    plan = postex_module.plan(self.server.index, mission_id,
                                              limit=5)
                    ready = [o for o in (plan.get("objectives") or [])
                             if o.get("ready")]
                    if ready:
                        body = (
                            "Post-exploitation continue: "
                            + "; ".join(
                                f"{o.get('name')} ({o.get('why')})"
                                for o in ready[:3])
                            + ". Prefer gated modules; do not widen scope."
                        )
                        existing = self.server.index.list_directions(
                            mission_id, status="queued", limit=20)
                        if not any("Post-exploitation continue" in str(
                                d.get("body") or "") for d in existing):
                            direction = self.server.index.create_direction(
                                mission_id, body, created_by="agent:postex")
                            out["postex_direction"] = direction.get("id")
                            out["postex_ready"] = len(ready)
            except Exception:  # noqa: BLE001
                pass
            try:
                collapsed = self.server.index.collapse_duplicate_hypotheses(
                    mission_id)
                if collapsed.get("archived"):
                    out["hypotheses_collapsed"] = collapsed
            except Exception:  # noqa: BLE001
                pass
            out["learned"] = kb_module.learn_from_mission(self.server.index,
                                                          mission_id)
            from .. import evolve as evolve_module

            out["expertise"] = evolve_module.mature_outcomes(self.server.index,
                                                             mission_id)
            from .. import harness as harness_module
            from .. import investigations as investigations_module

            synced = investigations_module.sync_from_notes(
                self.server.index, mission_id, limit=2)
            out["leads_synced"] = synced["counts"]["created"]
            # Compound operational memory from this run's real tool failures
            # and repeated successes. Draft skills stay human-gated.
            learned = harness_module.learn_tick(self.server.index,
                                                mission_id=mission_id)
            out["harness"] = {
                "lessons": len(learned.get("lessons_created") or []),
                "skills": len((learned.get("skills") or {}).get("created") or []),
            }
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
                      "open_leads": stage["open_leads"],
                      "leads_synced": out.get("leads_synced", 0),
                      "harness": out.get("harness") or {}})
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
        requested_mode = row["mode"]
        mode, gate_reason = self._gate_mode(requested_mode)
        policy = "full" if mission.get("autonomy") == "autonomous" else "supervised"
        objective = row.get("objective") or {}
        goal = str(objective.get("goal") or mission.get("objective") or "")
        try:
            critical_note = None
            for note in reversed(
                    self.server.index.list_agent_notes(mission_id, limit=120)):
                if str(note.get("kind") or "") == "hunt.critical":
                    critical_note = note
                    break
            if critical_note:
                try:
                    payload = json.loads(str(critical_note.get("body") or "{}"))
                except (TypeError, ValueError):
                    payload = {}
                tops = payload.get("top_leads") or []
                titles = [str(item.get("title") or "")[:120]
                          for item in tops if isinstance(item, dict)]
                titles = [t for t in titles if t]
                if titles:
                    hint = str(payload.get("director_hint") or "").strip()
                    lead_text = "; ".join(titles[:3])
                    prefix = f"Priority leads: {lead_text}"
                    if hint:
                        prefix = f"{prefix}. {hint}"
                    goal = f"{prefix} | {goal}" if goal else prefix
        except Exception:  # noqa: BLE001 - hunt notes are best effort
            pass
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
            budget = mission.get("budget") if isinstance(mission.get("budget"), dict) else {}
            for key in ("max_seconds", "max_model_calls"):
                if budget.get(key) is not None:
                    options[key] = budget[key]
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
        if gate_reason:
            note += f" [{gate_reason}]"
        try:
            self.server.index.add_agent_note(
                mission_id, "director.plan", f"Director: {mode}", note,
                run_id=run["id"])
        except Exception:  # noqa: BLE001 - a note is best effort
            pass
        self.server.index.add_director_log(
            "start", f"{mode} on {mission.get('title', mission_id)}",
            mission_id=mission_id, run_id=run["id"],
            data={"mode": mode, "requested_mode": requested_mode,
                  "policy": policy, "score": row.get("score"),
                  "objective": goal[:300], "autonomy": mission.get("autonomy"),
                  "model_gate": gate_reason})
        try:
            self.server.bus.publish(Event(
                type="director", run_id=run["id"], agent="director",
                stage="reason",
                payload={"text": note, "mode": mode, "mission_id": mission_id}))
        except Exception:  # noqa: BLE001
            pass
        return {"action": "start", "mission_id": mission_id, "mode": mode,
                "requested_mode": requested_mode, "run_id": run["id"],
                "policy": policy, "objective": goal,
                "score": row.get("score"), "model_gate": gate_reason}

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
