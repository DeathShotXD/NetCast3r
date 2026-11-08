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
from ..directives import DirectiveQueue


class SolverRunner:
    def __init__(self, server, complete=None, workers: int = 16):
        self.server = server
        self._complete = complete
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers),
                                       thread_name_prefix="netcast3r-solver")
        self._handles: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        # Run-scoped operator instructions. The HTTP thread pushes; the solver
        # worker drains at every round so a live instruction changes the plan
        # without restarting the run.
        self._directives: dict[str, DirectiveQueue] = {}
        # One bus per runner so a throttled or dead (provider, model) pair
        # stays retired across the many calls a swarm makes, instead of being
        # re-walked from scratch on every logical call.
        self._bus = None
        self._bus_timeout = 0.0

    def _provider_bus(self, config, timeout: float = 60.0):
        from ..providers import ProviderBus

        bus = self._bus
        if bus is None or self._bus_timeout != timeout:
            bus = ProviderBus(config, timeout=timeout)
            self._bus = bus
            self._bus_timeout = timeout
        else:
            bus.config = config
        return bus

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
        # A live hunt is endless by default: the mesh keeps seeding new
        # techniques until the operator stops it. Unit tests and scripts that
        # name an explicit step or time cap keep their bounded run.
        explicit_cap = ("max_steps" in options) or ("max_seconds" in options)
        endless = bool(options.get("endless",
                                   (not explicit_cap) and mode in ("swarm", "autopilot")))
        options["endless"] = endless
        run = self.server.index.create_run(target, {
            "mode": mode, "mission_id": mission_id,
            "max_steps": 0 if endless else options.get("max_steps", defaults),
            "endless": endless,
            "goal": str(options.get("goal") or mission.get("objective") or "")[:400],
            "policy": str(options.get("policy") or "supervised"),
        })
        self.server.index.add_mission_run(mission_id, run["id"])
        cancel = threading.Event()
        # Only the mesh modes have a planner that can consume an instruction.
        directives = (DirectiveQueue(run["id"]) if mode in ("swarm", "autopilot")
                      else None)
        with self._lock:
            self._handles[run["id"]] = cancel
            if directives is not None:
                self._directives[run["id"]] = directives
            self._trim_directives_locked()
        self.pool.submit(self._run, run["id"], mission_id, mission, options, cancel,
                         mode, seconds, directives)
        return run

    def _trim_directives_locked(self) -> None:
        """Keep the in-memory queue map bounded on a long-lived server."""
        if len(self._directives) <= 120:
            return
        for run_id in list(self._directives):
            if run_id not in self._handles and len(self._directives) > 100:
                self._directives.pop(run_id, None)

    def directive(self, run_id: str, text: str, kind: str = "auto",
                  target: str = "", source: str = "operator") -> dict:
        """Queue one operator instruction for a running solver.

        Returns the stored directive. A run that already finished is a
        conflict: the operator should steer a new run instead of writing into
        a closed transcript.
        """
        with self._lock:
            queue = self._directives.get(run_id)
            active = run_id in self._handles
        if queue is None:
            if not self.server.index.get_run(run_id):
                raise LookupError("run not found")
            raise ValueError("run does not accept operator directives")
        if not active:
            raise ValueError("run is not active")
        return queue.push(text, kind=kind, target=target, source=source)

    def directives(self, run_id: str, limit: int = 60) -> list[dict]:
        with self._lock:
            queue = self._directives.get(run_id)
        return queue.history(limit=limit) if queue is not None else []

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
        from ..agents import _first_json
        from ..config import load_config
        from .runner import DashboardBridge

        config = load_config()
        try:
            DashboardBridge(self.server.index, self.server.keys).apply(config)
        except Exception:  # noqa: BLE001 - a broken provider row must not stop the loop
            pass
        completion = self._provider_bus(config, 60.0).complete(
            "sentinel", messages, timeout=60.0,
            validate=lambda text: _first_json(text) is not None)
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
        from ..agents import _first_json
        from ..config import load_config
        from .runner import DashboardBridge

        config = load_config()
        try:
            DashboardBridge(self.server.index, self.server.keys).apply(config)
        except Exception:  # noqa: BLE001 - a broken provider row must not stop the loop
            pass
        completion = self._provider_bus(config, 60.0).complete(
            agent, messages, timeout=60.0, exclude_providers=exclude,
            validate=lambda text: _first_json(text) is not None)
        return {"text": completion.text or "", "provider": completion.provider,
                "model": completion.model, "error": completion.error or "",
                "usage": completion.usage or {}}

    def _run(self, run_id: str, mission_id: str, mission: dict,
             options: dict, cancel: threading.Event, mode: str = "solve",
             default_seconds: float = model_solver.DEFAULT_SECONDS,
             directives: DirectiveQueue | None = None) -> None:
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
                # Keep the run's directive history in step with the stream so a
                # reload shows accepted/applied instructions, not just queued.
                if directives is not None and stage == "directive":
                    directive_id = str(payload.get("directive_id") or "")
                    status = str(payload.get("status") or "")
                    if directive_id and status:
                        detail = str(payload.get("matched_task")
                                     or payload.get("plan") or "")
                        directives.mark(directive_id, status, detail)
                emit(Event(type="log", stage=stage,
                           agent=str(payload.get("agent") or ""),
                           payload=payload))

            if mode == "autopilot":
                endless = bool(options.get("endless", False))
                operator = autopilot.Autopilot(
                    registry, self._completion, brain_mission,
                    max_steps=options.get("max_steps", autopilot.DEFAULT_STEPS),
                    max_seconds=options.get("max_seconds", default_seconds),
                    max_model_calls=options.get("max_model_calls",
                                                autopilot.DEFAULT_MODEL_CALLS),
                    run_id=run_id, on_step=on_step, should_stop=cancel.is_set,
                    directive_source=directives.drain if directives else None,
                    endless=endless)
                result = operator.run()
            elif mode == "swarm":
                endless = bool(options.get("endless", False))
                mesh = swarm.Swarm(
                    registry, self._completion_for, brain_mission,
                    max_steps=options.get("max_steps", swarm.DEFAULT_STEPS),
                    max_seconds=options.get("max_seconds", default_seconds),
                    max_model_calls=options.get("max_model_calls",
                                                swarm.DEFAULT_MODEL_CALLS),
                    run_id=run_id, on_step=on_step, should_stop=cancel.is_set,
                    directive_source=directives.drain if directives else None,
                    endless=endless)
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