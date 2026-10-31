"""Verify an attack path as a live run.

A path is a candidate chain toward an impact. Verifying it runs each step
through the same scoped, risk-gated tools every other caller uses and records
what each observation supports. The runner creates no finding. It appears in
Live Runs as Reason, Act, Observe, Decide so the operator sees the real
evidence, not a summary.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .agent_runtime import LocalPlane
from .events import Event
from .. import graph


class PathRunner:
    def __init__(self, server, complete=None, workers: int = 1):
        self.server = server
        self._complete = complete
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers),
                                       thread_name_prefix="netcast3r-path")
        self._handles: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def start(self, path_id: str, options: dict | None = None) -> dict:
        path = self.server.index.get_graph_path(path_id)
        if not path:
            raise ValueError("path not found")
        mission = self.server.index.get_mission(path.get("mission_id", ""))
        if not mission:
            raise ValueError("mission not found")
        target = str(mission.get("target") or "").strip()
        if not target:
            raise ValueError("mission has no target")
        options = dict(options or {})
        run = self.server.index.create_run(target, {
            "mode": "path", "mission_id": mission["id"], "path_id": path_id,
            "policy": str(options.get("policy") or "supervised"),
        })
        self.server.index.add_mission_run(mission["id"], run["id"])
        cancel = threading.Event()
        with self._lock:
            self._handles[run["id"]] = cancel
        self.pool.submit(self._run, run["id"], mission, path, options, cancel)
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

    def _completion(self, agent: str, messages: list[dict]) -> dict:
        if self._complete is not None:
            return self._complete(messages)
        from ..config import load_config
        from ..providers import ProviderBus
        from .runner import DashboardBridge

        config = load_config()
        try:
            DashboardBridge(self.server.index, self.server.keys).apply(config)
        except Exception:  # noqa: BLE001 - a broken provider row must not stop the run
            pass
        completion = ProviderBus(config, timeout=45.0).complete(
            "verifier", messages, timeout=45.0)
        return {"text": completion.text or "", "provider": completion.provider,
                "model": completion.model, "error": completion.error or "",
                "usage": completion.usage or {}}

    def _run(self, run_id: str, mission: dict, path: dict, options: dict,
             cancel: threading.Event) -> None:
        emit = self._emit(run_id)
        self.server.index.update_run(run_id, status="running", started_at=_now())
        emit(Event(type="run.state", stage="reason",
                   payload={"status": "running", "mode": "path"}))
        try:
            from ..mcp.tools import POLICIES, ToolContext, ToolRegistry

            policy = str(options.get("policy") or "supervised").strip().lower()
            if policy not in POLICIES:
                policy = "supervised"
            authorized = (str(mission.get("autonomy") or "") == "autonomous"
                          and str(mission.get("status") or "") == "active")
            ctx = ToolContext(plane=LocalPlane(self.server), policy=policy,
                              base=self.server.base, actor="agent:path",
                              mission_id=mission["id"], authorized=authorized)
            registry = ToolRegistry(ctx)

            def on_step(stage: str, payload: dict) -> None:
                emit(Event(type="log", stage=stage,
                           agent=str(payload.get("agent") or "path"),
                           payload=payload))

            result = graph.verify_path(
                self.server.index, mission, path, registry,
                complete=self._completion, on_step=on_step,
                should_stop=cancel.is_set)
            status = "stopped" if result["state"] == "candidate" and cancel.is_set() \
                else "done"
            summary = {"mode": "path", "target": mission.get("target", ""),
                       "path_id": path["id"], "state": result["state"],
                       "steps": len(result["steps"]),
                       "supports": result["supports"],
                       "refutes": result["refutes"],
                       "blocked": result["blocked"],
                       "stop": result["state"], "findings": 0}
            self.server.index.update_run(run_id, status=status, finished_at=_now(),
                                         counts_json=summary)
            emit(Event(type="run.state", stage="decide",
                       payload={"status": status, "counts": summary}))
            emit(Event(type="log", stage="decide", payload={
                "text": (f"path {result['state']}: {result['supports']} supported, "
                         f"{result['refutes']} refuted, {result['blocked']} blocked; "
                         "0 findings")}))
            emit(Event(type="run.finished", payload={"counts": summary}))
        except Exception as exc:  # noqa: BLE001 - record the failure
            error = f"{type(exc).__name__}: {exc}"
            self.server.index.update_run(run_id, status="failed",
                                         finished_at=_now(), error=error)
            emit(Event(type="error", level="error", payload={"error": error}))
            emit(Event(type="run.state", stage="decide", payload={"status": "failed"}))
        finally:
            with self._lock:
                self._handles.pop(run_id, None)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
