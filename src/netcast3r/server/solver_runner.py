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
from .. import model_solver


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
        run = self.server.index.create_run(target, {
            "mode": "solve", "mission_id": mission_id,
            "max_steps": options.get("max_steps", model_solver.DEFAULT_STEPS),
        })
        self.server.index.add_mission_run(mission_id, run["id"])
        cancel = threading.Event()
        with self._lock:
            self._handles[run["id"]] = cancel
        self.pool.submit(self._run, run["id"], mission_id, mission, options, cancel)
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

    def _run(self, run_id: str, mission_id: str, mission: dict,
             options: dict, cancel: threading.Event) -> None:
        emit = self._emit(run_id)
        self.server.index.update_run(run_id, status="running", started_at=_now())
        emit(Event(type="run.state", stage="reason", payload={"status": "running"}))
        try:
            from ..mcp.tools import ToolContext, ToolRegistry

            ctx = ToolContext(
                plane=LocalPlane(self.server), policy="supervised",
                base=self.server.base, actor="agent:solver", mission_id=mission_id)
            registry = ToolRegistry(ctx)

            def on_step(stage: str, payload: dict) -> None:
                emit(Event(type="log", stage=stage, payload=payload))

            solver = model_solver.Solver(
                registry, self._completion, mission_id,
                str(mission.get("target") or ""),
                goal=str(mission.get("objective") or ""),
                max_steps=options.get("max_steps", model_solver.DEFAULT_STEPS),
                max_seconds=options.get("max_seconds", model_solver.DEFAULT_SECONDS),
                on_step=on_step, should_stop=cancel.is_set)
            result = solver.run()
            status = "stopped" if result["stop"] == "cancelled" else "done"
            summary = {
                "mode": "solve", "target": result["target"],
                "steps": len(result["steps"]), "actions": result["actions"],
                "model_calls": result["model_calls"],
                "stop": result["stop"], "seconds": result["seconds"],
                "findings": 0,
            }
            self.server.index.update_run(run_id, status=status, finished_at=_now(),
                                         counts_json=summary)
            emit(Event(type="run.state", stage="decide",
                       payload={"status": status, "counts": summary}))
            if status == "done":
                emit(Event(type="log", stage="decide", payload={
                    "text": (f"solve finished: {result['stop']}; "
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