"""Background scan jobs.

A run executes on a worker thread, publishes events as it goes, and can be
asked to stop cooperatively. The in-memory registry is only a cache; the
database is the record, so a restart recovers cleanly.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .events import Event, EventBus


class JobManager:
    def __init__(self, index, bus: EventBus, runner: Callable, workers: int = 2):
        self.index = index
        self.bus = bus
        self.runner = runner
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="netcast3r-run")
        self._handles: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _emit(self, run_id: str) -> Callable[[Event], None]:
        def emit(event: Event) -> None:
            event.run_id = event.run_id or run_id
            self.bus.publish(event)
            try:
                self.index.add_event(run_id, event.to_dict())
            except Exception:
                pass
        return emit

    def submit(self, run_id: str, target: str, options: dict | None = None) -> dict:
        cancel = threading.Event()
        with self._lock:
            self._handles[run_id] = {"cancel": cancel, "state": "queued"}
        self.pool.submit(self._execute, run_id, target, options or {}, cancel)
        return {"id": run_id, "status": "queued"}

    def _execute(self, run_id: str, target: str, options: dict, cancel: threading.Event) -> None:
        emit = self._emit(run_id)
        with self._lock:
            self._handles.setdefault(run_id, {})["state"] = "running"
        self.index.update_run(run_id, status="running", started_at=_utc())
        emit(Event(type="run.state", run_id=run_id, payload={"status": "running"}))
        status, summary, error = "done", {}, ""
        try:
            summary = self.runner(run_id, target, options, emit, cancel.is_set) or {}
            findings = summary.pop("findings_list", []) if isinstance(summary, dict) else []
            if findings:
                self.index.add_findings(run_id, findings)
            if cancel.is_set():
                status = "stopped"
        except Exception as exc:  # noqa: BLE001 - a failed run must not kill the server
            status, error = "failed", f"{type(exc).__name__}: {exc}"
            emit(Event(type="error", run_id=run_id, level="error", payload={"error": error}))
        self.index.update_run(run_id, status=status, finished_at=_utc(),
                              counts_json=summary if isinstance(summary, dict) else {},
                              error=error)
        with self._lock:
            if run_id in self._handles:
                self._handles[run_id]["state"] = status
        emit(Event(type="run.state", run_id=run_id,
                   payload={"status": status, "counts": summary if isinstance(summary, dict) else {}}))
        if status == "done":
            emit(Event(type="run.finished", run_id=run_id, payload={"counts": summary}))

    def cancel(self, run_id: str) -> bool:
        with self._lock:
            handle = self._handles.get(run_id)
        if not handle or handle.get("state") not in ("queued", "running"):
            return False
        handle["cancel"].set()
        return True

    def is_running(self, run_id: str) -> bool:
        with self._lock:
            handle = self._handles.get(run_id)
        return bool(handle and handle.get("state") in ("queued", "running"))

    def active(self) -> list[str]:
        with self._lock:
            return [rid for rid, handle in self._handles.items()
                    if handle.get("state") in ("queued", "running")]

    def recover(self) -> int:
        """Any run left mid-flight by a previous process becomes interrupted."""
        recovered = 0
        with self._lock:
            rows = self.index.conn.execute(
                "SELECT id FROM runs WHERE status IN ('running', 'queued')").fetchall()
        for row in rows:
            self.index.update_run(row["id"], status="interrupted", finished_at=_utc(),
                                  error="server restarted")
            recovered += 1
        return recovered

    def shutdown(self, wait: bool = False) -> None:
        for run_id in self.active():
            self.cancel(run_id)
        self.pool.shutdown(wait=wait, cancel_futures=True)


def _utc() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
