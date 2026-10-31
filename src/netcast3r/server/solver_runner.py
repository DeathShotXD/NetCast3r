"""Run the bounded model action loop as a live run.

The loop is model-driven, so it is a worker with a budget, not a request that
hangs the dashboard. Each step emits an event, so Live Runs shows the real
reason -> act -> observe -> decide cycle. The runner creates no finding.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .agent_runtime import LocalPlane
from .events import Event
from .. import autopilot, model_solver, swarm


class SolverRunner:
    def __init__(self, server, complete=None, workers: int = 1):
        self.server = server
        self._complete = complete
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers),
                                       thread_name_prefix="netcast3r-solver")
        self._handles: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def start(self, mission_id: str, options: dict | None = None) -> dict:
        mission = self.server.index.get_mission(mission_id)
        if not mission:
            raise ValueError("mission not found")
        if mission.get("training"):
            raise ValueError("training mission: solve labs with a lab recipe instead")
        target = str(mission.get("target") or "").strip()
        if not target:
            raise ValueError("mission has no target")
        options = dict(options or {})
        mode = str(options.get("mode") or "solve").strip().lower()
        if mode not in {"solve", "autopilot", "swarm"}:
            raise ValueError(f"unknown solver mode: {mode}")
        defaults = {"solve": model_solver.DEFAULT_STEPS,
                    "autopilot": autopilot.DEFAULT_STEPS,
                    "swarm": swarm.DEFAULT_STEPS}[mode]
        seconds = {"solve": model_solver.DEFAULT_SECONDS,
                   "autopilot": autopilot.DEFAULT_SECONDS,
                   "swarm": swarm.DEFAULT_SECONDS}[mode]
        run = self.server.index.create_run(target, {
            "mode": mode, "mission_id": mission_id,
            "max_steps": options.get("max_steps", defaults),
            "goal": str(options.get("goal") or mission.get("objective") or "")[:400],
            "policy": str(options.get("policy") or "supervised"),
        })
        self.server.index.add_mission_run(mission_id, run["id"])
        cancel = threading.Event()
        with self._lock:
            self._handles[run["id"]] = cancel
        self.pool.submit(self._run, run["id"], mission_id, mission, options, cancel,
                         mode, seconds)
        return run

    def cancel(self, run_id: str) -> bool:
        with self._lock:
            cancel = self._handles.get(run_id)
        if not cancel:
            return False
        cancel.set()
        return True

    def shutdown(self, wait: bool = False) -> None:
        with self._lock:
            for cancel in self._handles.values():
                cancel.set()
        self.pool.shutdown(wait=wait, cancel_futures=True)

    def _emit(self, run_id: str):
        def emit(event: Event) -> None:
            event.run_id = event.run_id or run_id
            self.server.bus.publish(event)
            try:
                self.server.index.add_event(run_id, event.to_dict())
            except Exception:  # noqa: BLE001 - event writes are best effort
                pass
        return emit

    def _completion(self, messages: list[dict]) -> dict:
        if self._complete is not None:
            return self._complete(messages)
        from ..config import load_config
        from ..providers import ProviderBus
        from .runner import DashboardBridge

        config = load_config()
        try:
            DashboardBridge(self.server.index, self.server.keys).apply(config)
        except Exception:  # noqa: BLE001 - a broken provider row must not stop the loop
            pass
        completion = ProviderBus(config, timeout=45.0).complete(
            "sentinel", messages, timeout=45.0)
        return {"text": completion.text or "", "provider": completion.provider,
                "model": completion.model, "error": completion.error or "",
                "usage": completion.usage or {}}

    def _completion_for(self, agent: str, messages: list[dict],
                        exclude: set[str] | None = None) -> dict:
        """One model call routed by agent identity.

        The mesh gives each role a different identity, so a deployment can bind
        the strategist to one model and the validator to another. An injected
        completion is shared by every role, which keeps tests deterministic.
        """
        if self._complete is not None:
            return self._complete(messages)
        from ..config import load_config
        from ..providers import ProviderBus
        from .runner import DashboardBridge

        config = load_config()
        try:
            DashboardBridge(self.server.index, self.server.keys).apply(config)
        except Exception:  # noqa: BLE001 - a broken provider row must not stop the loop
            pass
        completion = ProviderBus(config, timeout=45.0).complete(
            agent, messages, timeout=45.0, exclude_providers=exclude)
        return {"text": completion.text or "", "provider": completion.provider,
                "model": completion.model, "error": completion.error or "",
                "usage": completion.usage or {}}

    def _run(self, run_id: str, mission_id: str, mission: dict,
             options: dict, cancel: threading.Event, mode: str = "solve",
             default_seconds: float = model_solver.DEFAULT_SECONDS) -> None:
        emit = self._emit(run_id)
        self.server.index.update_run(run_id, status="running", started_at=_now())
        emit(Event(type="run.state", stage="reason", payload={"status": "running"}))
        try:
            from ..mcp.tools import POLICIES, ToolContext, ToolRegistry

            policy = str(options.get("policy") or "supervised").strip().lower()
            if policy not in POLICIES:
                policy = "supervised"
            authorized = (str(mission.get("autonomy") or "") == "autonomous"
                          and str(mission.get("status") or "") == "active")
            ctx = ToolContext(
                plane=LocalPlane(self.server), policy=policy,
                base=self.server.base,
                actor={"autopilot": "agent:autopilot", "swarm": "agent:swarm"}.get(
                    mode, "agent:solver"),
                mission_id=mission_id, authorized=authorized)
            registry = ToolRegistry(ctx)
            # The director hands the brain a Prime objective; the brain reads
            # its goal from the mission, so overlay it without mutating.
            goal = str(options.get("goal") or "").strip()
            brain_mission = {**mission, "objective": goal} if goal else mission

            def on_step(stage: str, payload: dict) -> None:
                emit(Event(type="log", stage=stage,
                           agent=str(payload.get("agent") or ""),
                           payload=payload))

            if mode == "autopilot":
                operator = autopilot.Autopilot(
                    registry, self._completion, brain_mission,
                    max_steps=options.get("max_steps", autopilot.DEFAULT_STEPS),
                    max_seconds=options.get("max_seconds", default_seconds),
                    max_model_calls=options.get("max_model_calls",
                                                autopilot.DEFAULT_MODEL_CALLS),
                    run_id=run_id, on_step=on_step, should_stop=cancel.is_set)
                result = operator.run()
            elif mode == "swarm":
                mesh = swarm.Swarm(
                    registry, self._completion_for, brain_mission,
                    max_steps=options.get("max_steps", swarm.DEFAULT_STEPS),
                    max_seconds=options.get("max_seconds", default_seconds),
                    max_model_calls=options.get("max_model_calls",
                                                swarm.DEFAULT_MODEL_CALLS),
                    run_id=run_id, on_step=on_step, should_stop=cancel.is_set)
                result = mesh.run()
            else:
                solver = model_solver.Solver(
                    registry, self._completion, mission_id,
                    str(mission.get("target") or ""),
                    goal=str(options.get("goal") or mission.get("objective") or ""),
                    max_steps=options.get("max_steps", model_solver.DEFAULT_STEPS),
                    max_seconds=options.get("max_seconds", model_solver.DEFAULT_SECONDS),
                    on_step=on_step, should_stop=cancel.is_set)
                result = solver.run()
            status = "stopped" if result["stop"] == "cancelled" else "done"
            summary = {
                "mode": result.get("mode", mode), "target": result["target"],
                "steps": result["actions"], "actions": result["actions"],
                "model_calls": result["model_calls"],
                "stop": result["stop"], "seconds": result["seconds"],
                "hypotheses": result.get("hypotheses", 0),
                "findings": 0,
            }
            if mode == "swarm":
                roles = result.get("roles") or {}
                calls = result.get("role_calls") or {}
                verdicts = result.get("verdicts") or {}
                summary.update({
                    "rounds": result.get("rounds", 0),
                    "agents": len([count for count in calls.values() if count]),
                    "corroborated": result.get("corroborated", 0),
                    "contested": result.get("contested", 0),
                    # Flat numeric counters keep the run record easy to read
                    # and the live view easy to render.
                    "scout_actions": roles.get("scout", 0),
                    "attacker_actions": roles.get("attacker", 0),
                    "strategist_calls": calls.get("strategist", 0),
                    "validator_calls": calls.get("validator", 0),
                    "scribe_calls": calls.get("scribe", 0),
                    "supports": verdicts.get("supports", 0),
                    "refuted": verdicts.get("refutes", 0),
                    "inconclusive": verdicts.get("inconclusive", 0),
                })
            self.server.index.update_run(run_id, status=status, finished_at=_now(),
                                         counts_json=summary)
            emit(Event(type="run.state", stage="decide",
                       payload={"status": status, "counts": summary}))
            if status == "done":
                emit(Event(type="log", stage="decide", payload={
                    "text": (f"{mode} finished: {result['stop']}; "
                             f"{result['actions']} action(s), 0 findings")}))
                emit(Event(type="run.finished", payload={"counts": summary}))
        except Exception as exc:  # noqa: BLE001 - record the failure
            error = f"{type(exc).__name__}: {exc}"
            self.server.index.update_run(run_id, status="failed", finished_at=_now(),
                                         error=error)
            emit(Event(type="error", level="error", payload={"error": error}))
            emit(Event(type="run.state", stage="decide", payload={"status": "failed"}))
        finally:
            with self._lock:
                self._handles.pop(run_id, None)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())