"""Continuous lab training loop.

Runs beside the hunt director. Uses the learn-lane model pool (th-learn-*) to
grind PortSwigger / Acunetix / Juice Shop and other catalogue labs without
stopping, so the framework compounds technique memory before publish.
"""

from __future__ import annotations

import threading
import time


# Prefer modern lab packs the operator named for pre-publish training speed.
# PortSwigger dominates the catalogue, so we rotate source preference each tick.
PRIORITY_SOURCES = (
    "local-juice-shop",
    "acunetix-testphp",
    "portswigger",
    "local-dvwa",
    "local-webgoat",
)


class TrainingDirector:
    def __init__(self, server, tick_seconds: float = 25.0, max_inflight: int = 3):
        self.server = server
        self.tick_seconds = max(8.0, float(tick_seconds))
        self.max_inflight = max(1, min(int(max_inflight), 6))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._inflight = 0
        self._cycles = 0
        self._source_cursor = 0
        self._last_slug = ""
        self._last_source = ""
        self._last_error = ""
        self._engaged = True

    def start(self) -> dict:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return self.status()
            self._stop.clear()
            self._engaged = True
            self._thread = threading.Thread(
                target=self._loop, name="netcast3r-training-director", daemon=True)
            self._thread.start()
        try:
            self.server.index.add_director_log(
                "training", "continuous lab trainer started (learn-lane keys)")
        except Exception:  # noqa: BLE001
            pass
        return self.status()

    def shutdown(self, timeout: float = 8.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None

    def pause(self) -> dict:
        self._engaged = False
        return self.status()

    def resume(self) -> dict:
        self._engaged = True
        if self._thread is None or not self._thread.is_alive():
            return self.start()
        return self.status()

    def status(self) -> dict:
        return {
            "engaged": self._engaged,
            "running": bool(self._thread and self._thread.is_alive()),
            "cycles": self._cycles,
            "inflight": self._inflight,
            "max_inflight": self.max_inflight,
            "tick_seconds": self.tick_seconds,
            "last_slug": self._last_slug,
            "last_source": self._last_source,
            "last_error": self._last_error,
            "lane": "learn",
            "priority_sources": list(PRIORITY_SOURCES),
            "note": ("Continuous PortSwigger / Acunetix / Juice Shop / local-lab "
                     "solver using th-learn-* TokenHarbor keys."),
        }

    def _loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                if self._engaged:
                    self._tick()
            except Exception as exc:  # noqa: BLE001 - never kill the trainer
                self._last_error = f"{type(exc).__name__}: {exc}"
                try:
                    self.server.index.add_director_log(
                        "training.error", self._last_error)
                except Exception:  # noqa: BLE001
                    pass
            wait = max(0.0, self.tick_seconds - (time.monotonic() - started))
            self._stop.wait(wait)

    def _tick(self) -> None:
        # Yield lab capacity while operator priority owns the plane.
        # Skip when training_paused_for_priority is true, or when
        # operator_priority.mission_id is set.
        if self._paused_for_operator_priority():
            self._last_error = "paused: operator priority hunt owns capacity"
            return
        with self._lock:
            if self._inflight >= self.max_inflight:
                return
            self._inflight += 1
            self._cycles += 1
        worker = threading.Thread(
            target=self._solve_one, name="netcast3r-lab-solve-tick", daemon=True)
        worker.start()

    def _paused_for_operator_priority(self) -> bool:
        index = getattr(self.server, "index", None)
        if index is None:
            return False
        try:
            flag = index.get_setting("training_paused_for_priority")
        except Exception:  # noqa: BLE001
            flag = None
        if flag is True or (isinstance(flag, dict) and flag.get("paused")):
            return True
        try:
            from .. import brain as brain_module
            locked = brain_module.operator_priority(index) or {}
        except Exception:  # noqa: BLE001
            return False
        return bool(locked.get("mission_id"))

    def _next_source(self) -> str:
        with self._lock:
            source = PRIORITY_SOURCES[self._source_cursor % len(PRIORITY_SOURCES)]
            self._source_cursor += 1
            return source

    def _pick_lab(self) -> tuple[str, str]:
        from .. import training as training_module

        preferred = self._next_source()
        plan = training_module.plan(
            self.server.index, limit=1, source=preferred)
        items = plan.get("items") if isinstance(plan, dict) else None
        if items:
            lab = items[0]
            return str(lab.get("slug") or ""), preferred
        # Fall back across the full catalogue when a pack is exhausted / offline.
        plan = training_module.plan(self.server.index, limit=1)
        items = plan.get("items") if isinstance(plan, dict) else None
        if items:
            lab = items[0]
            return (str(lab.get("slug") or ""),
                    str(lab.get("source") or "auto"))
        return "", preferred

    def _solve_one(self) -> None:
        try:
            from .. import lab_solver as lab_solver_module

            slug, source = self._pick_lab()
            self._last_slug = slug or "auto"
            self._last_source = source
            lab_solver_module.solve_next(
                self.server, self.server.index, slug=slug)
            self._last_error = ""
            try:
                self.server.index.add_director_log(
                    "training.solve",
                    f"lab trainer finished pass on {self._last_slug or 'auto'} "
                    f"[{self._last_source or 'auto'}]")
            except Exception:  # noqa: BLE001
                pass
        except Exception as exc:  # noqa: BLE001
            self._last_error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self._inflight = max(0, self._inflight - 1)
