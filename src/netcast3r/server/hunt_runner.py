"""Standalone dashboard hunt.

A hunt is a deterministic, read-only pass over one mission target: scope,
fingerprint, a few safe surface paths, a research technique plan, a chain plan,
and explicit hypotheses. It does not need OpenCode, Hermes, or any external
agent; the dashboard can start it and watch it in Live Runs.

It creates hypotheses, never findings. A hypothesis is a precise question with
an expected observation; it still has to be tested.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from .agent_runtime import LocalPlane
from .events import Event


class HuntRunner:
    def __init__(self, server, workers: int = 2):
        self.server = server
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers),
                                       thread_name_prefix="netcast3r-hunt")
        self._handles: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def start(self, mission_id: str) -> dict:
        mission = self.server.index.get_mission(mission_id)
        if not mission:
            raise ValueError("mission not found")
        if mission.get("training"):
            raise ValueError("training mission: use the training agent or a lab recipe")
        target = str(mission.get("target") or "").strip()
        if not target:
            raise ValueError("mission has no target")
        run = self.server.index.create_run(
            target, {"mode": "hunt", "mission_id": mission_id})
        self.server.index.add_mission_run(mission_id, run["id"])
        cancel = threading.Event()
        with self._lock:
            self._handles[run["id"]] = cancel
        self.pool.submit(self._run, run["id"], mission_id, target, cancel)
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

    def _run(self, run_id: str, mission_id: str, target: str,
             cancel: threading.Event) -> None:
        emit = self._emit(run_id)
        self.server.index.update_run(run_id, status="running", started_at=_now())
        try:
            summary = self._execute(run_id, mission_id, target, emit, cancel)
            status, error = "done", ""
        except Exception as exc:  # noqa: BLE001 - record the failure
            summary = {"mode": "hunt", "findings": 0,
                       "error": f"{type(exc).__name__}: {exc}"}
            status, error = "failed", summary["error"]
            emit(Event(type="error", agent="hunt", level="error",
                       payload={"error": summary["error"]}))
        self.server.index.update_run(run_id, status=status, finished_at=_now(),
                                     counts_json=summary, error=error)
        with self._lock:
            self._handles.pop(run_id, None)
        emit(Event(type="run.state", stage="done", payload={"status": status}))
        if status == "done":
            emit(Event(type="run.finished", payload={"counts": summary}))

    def _call(self, registry, name: str, args: dict) -> dict:
        payload, is_error = registry.call(name, args, actor="agent:hunt")
        if is_error:
            error = payload.get("error") or {}
            raise RuntimeError(f"{name}: {error.get('message') or 'refused'}")
        return payload

    def _execute(self, run_id: str, mission_id: str, target: str, emit,
                 cancel) -> dict:
        from ..mcp.tools import ToolContext, ToolRegistry

        ctx = ToolContext(
            plane=LocalPlane(self.server), policy="supervised",
            base=self.server.base, actor="agent:hunt", mission_id=mission_id)
        registry = ToolRegistry(ctx)
        host = urlsplit(target if "://" in target else "https://" + target).hostname or target
        if cancel.is_set():
            raise RuntimeError("cancelled")

        emit(Event(type="log", agent="hunt", stage="scope",
                   payload={"text": f"checking scope for {host}"}))
        scope = self._call(registry, "scope_check",
                           {"target": target, "mission_id": mission_id})
        if not scope.get("in_scope"):
            raise RuntimeError("target is outside the mission scope")

        emit(Event(type="log", agent="hunt", stage="fingerprint",
                   payload={"text": f"fingerprinting {target}"}))
        probe = self._call(registry, "http_probe", {
            "target": target, "mission_id": mission_id,
            "method": "GET", "max_bytes": 65536, "timeout": 15})
        body = str(probe.get("body") or "")
        headers = probe.get("headers") or {}
        title = ""
        if "<title" in body.lower():
            start = body.lower().find("<title")
            end = body.lower().find("</title>", start)
            title = body[start:end].split(">", 1)[-1].strip()[:200] if end > start else ""
        emit(Event(type="fetch", agent="hunt", stage="fingerprint", payload={
            "url": probe.get("url") or target, "status": probe.get("status"),
            "kind": "progress"}))
        signals = [str(value).lower() for value in
                   (headers.get("server"), headers.get("x-powered-by"),
                    headers.get("via"), title) if value]
        signals = [value for value in signals if value]

        safe_paths = ["/robots.txt", "/.well-known/security.txt", "/sitemap.xml"]
        surface = []
        for path in safe_paths:
            if cancel.is_set():
                raise RuntimeError("cancelled")
            try:
                response = self._call(registry, "http_request", {
                    "target": target.rstrip("/") + path,
                    "mission_id": mission_id, "method": "GET",
                    "max_bytes": 32768, "timeout": 10,
                    "follow_redirects": False})
            except RuntimeError:
                continue
            surface.append({"path": path, "status": response.get("status"),
                            "bytes": response.get("bytes")})
            emit(Event(type="fetch", agent="hunt", stage="surface", payload={
                "url": target.rstrip("/") + path,
                "status": response.get("status")}))

        emit(Event(type="log", agent="hunt", stage="surface",
                   payload={"text": "comparing path encodings" }))
        try:
            diff = self._call(registry, "http_path_diff", {
                "target": target, "mission_id": mission_id,
                "method": "GET", "max_variants": 8, "max_bytes": 32768})
            variants = diff.get("variants") or []
        except RuntimeError:
            variants = []

        emit(Event(type="log", agent="hunt", stage="research",
                   payload={"text": "ranking research techniques and chains"}))
        techniques = self._call(registry, "technique_plan", {
            "target": target, "signals": signals, "limit": 4})
        chains = self._call(registry, "chain_plan", {
            "target": target, "signals": signals, "limit": 3})

        hypotheses = []
        for item in (techniques.get("items") or [])[:2]:
            if cancel.is_set():
                break
            try:
                hypothesis = self._call(registry, "hypothesis_create", {
                    "title": f"Test {item['title']} on {host}",
                    "target": target, "mission_id": mission_id,
                    "technique": item["id"],
                    "rationale": ", ".join(item.get("why") or []) or item.get("class", ""),
                    "expected": item.get("proof") or "a reproducible effect",
                })
            except RuntimeError:
                continue
            hypotheses.append(hypothesis)
            emit(Event(type="log", agent="hunt", stage="hypotheses", payload={
                "text": f"hypothesis: {hypothesis.get('title')}"}))

        summary = {
            "mode": "hunt", "target": target, "title": title,
            "pages": 1 + len(surface), "signals": len(signals),
            "endpoints": len(variants), "leads": len(hypotheses),
            "techniques": len(techniques.get("items") or []),
            "chains": len(chains.get("items") or []),
            "findings": 0,
        }
        emit(Event(type="log", agent="hunt", stage="hypotheses", payload={
            "text": (f"hunt complete: {len(hypotheses)} hypotheses, "
                     f"{len(techniques.get('items') or [])} techniques, "
                     f"0 findings")}))
        return summary


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
