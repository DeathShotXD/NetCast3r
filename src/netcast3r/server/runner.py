"""Default run executor.

Wraps the existing orchestrator so a scan started from the API behaves exactly
like one started from the console: the same stages, the same report files, the
same validation ladder. Events are forwarded to the bus as they happen.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ..theme import strip as strip_ansi
from .events import Event
from .keys import mask


class EventConsole:
    """Console adapter that turns orchestrator calls into live events."""

    is_dashboard = False
    show_reasoning = False
    _rich = None
    color = False

    def __init__(self, emit: Callable[[Event], None], run_id: str = ""):
        self.emit = emit
        self.run_id = run_id
        self.events: list[dict] = []

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def header(self, target: str) -> None:
        self.events.append({"kind": "header", "agent": "run", "text": target or "-"})
        self.emit(Event(type="stage.started", run_id=self.run_id, stage="crawl",
                        payload={"target": target}))

    def line(self, agent: str, text: str) -> None:
        self.events.append({"kind": "line", "agent": agent, "text": text})
        self.emit(Event(type="log", run_id=self.run_id, agent=agent, payload={"text": text}))

    def _emit(self, text: str) -> None:
        """Raw console output (progress bars, box rules). Always a plain log line."""
        text = strip_ansi(text or "").strip()
        if text:
            self.line("run", text)

    def reasoning(self, agent: str, text: str) -> None:
        for piece in (text or "").splitlines():
            piece = piece.strip()
            if piece:
                self.events.append({"kind": "reason", "agent": agent, "text": piece})

    def finding(self, status: str, secret_type: str, value: str, detail: str) -> None:
        masked = mask(value)
        self.events.append({"kind": "finding", "status": status, "type": secret_type,
                            "value": masked, "detail": detail})
        self.emit(Event(type="finding.created", run_id=self.run_id, level="warning",
                        payload={"status": status, "secret_type": secret_type,
                                 "value": masked, "detail": detail}))

    def counts(self, **values) -> None:
        self.emit(Event(type="stage.progress", run_id=self.run_id, progress=dict(values)))

    def summary(self, data: dict) -> None:
        self.events.append({"kind": "summary", "agent": "run", "text": "run complete",
                            "data": dict(data)})
        self.emit(Event(type="run.state", run_id=self.run_id, payload={"summary": data}))


def run_scan(run_id: str, target: str, options: dict, emit: Callable[[Event], None],
             should_stop: Callable[[], bool]) -> dict:
    from ..config import load_config
    from ..orchestrator import Orchestrator
    from ..scope import ScopeManager
    from ..store import Store

    if should_stop():
        return {}

    config = load_config()
    run_config = config.run
    if options.get("tier"):
        run_config.action_tier = str(options["tier"])
    if options.get("depth"):
        run_config.depth = int(options["depth"])
    if options.get("timeout"):
        run_config.timeout = float(options["timeout"])

    results_root = Path(options.get("results_dir") or "results")
    out = results_root / run_id
    out.mkdir(parents=True, exist_ok=True)
    store = Store(out / "netcast3r.db")
    scope = ScopeManager.from_files("", "", extra_in=[target])
    console = EventConsole(emit, run_id)
    orchestrator = Orchestrator(config, scope, store, console=console)
    try:
        summary = orchestrator.run([target])
    finally:
        store.close()

    return {
        "target": summary.target,
        "pages": summary.pages,
        "js_files": summary.js_files,
        "endpoints": summary.endpoints,
        "candidates": summary.candidates,
        "verified": summary.verified,
        "findings": summary.findings,
        "report": summary.report,
        "results_dir": str(out),
        "findings_list": list(orchestrator.last_findings),
    }
