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

    def fetch(self, kind: str, url: str, status: int) -> None:
        """One fetched URL, live: the crawler panel eats these as they come."""
        self.events.append({"kind": "fetch", "agent": "recon", "text": url})
        self.emit(Event(type="fetch", run_id=self.run_id, agent="recon",
                        payload={"kind": kind, "url": url, "status": status}))
        if kind == "progress":
            self.emit(Event(type="stage.progress", run_id=self.run_id,
                            progress={"crawled": status}))

    def _emit(self, text: str) -> None:
        """Raw console output (progress bars, box rules). Always a plain log line."""
        text = strip_ansi(text or "").strip()
        if text:
            self.line("run", text)

    def reasoning(self, agent: str, text: str) -> None:
        # Forward the chunk as-is; the coalescer concatenates raw deltas so
        # words split across chunks reassemble (embedded newlines survive).
        text = text or ""
        if not text.strip():
            return
        self.events.append({"kind": "reason", "agent": agent, "text": text})
        self.emit(Event(type="reasoning", run_id=self.run_id, agent=agent,
                        payload={"text": text}))

    def model_call(self, payload: dict) -> None:
        """Forward a provider attempt (call/done) to the live stream."""
        data = dict(payload or {})
        agent = str(data.get("agent") or "run")
        provider = str(data.get("provider") or "?")
        model = str(data.get("model") or "?")
        kind = str(data.get("kind") or "call")
        detail = f"{provider}/{model}"
        if kind == "done":
            detail += f" {'ok' if data.get('ok') else 'failed'} {int(data.get('ms') or 0)}ms"
            if data.get("error"):
                detail += f" - {data['error']}"
        self.events.append({"kind": "model", "agent": agent, "text": detail})
        self.emit(Event(type="model", run_id=self.run_id, agent=agent, payload=data))

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


class DashboardBridge:
    """Feeds dashboard-configured providers and stored keys into a run.

    The config file stays the base layer. Anything configured on the
    Providers screen is merged on top: same name wins field by field, new
    names join the pool, and the priority order decides who is tried first.
    """

    def __init__(self, index, keys):
        self.index = index
        self.keys = keys

    def apply(self, config) -> int:
        from ..config import ProviderConfig

        applied = 0
        for row in self.index.list_providers():
            if not int(row.get("enabled", 1) or 0):
                continue
            name = (row.get("name") or "").strip()
            base_url = (row.get("base_url") or "").strip()
            if not name or not base_url:
                continue
            models = [str(item) for item in (row.get("models") or []) if str(item).strip()]
            if not models and row.get("model"):
                models = [str(row["model"])]
            key = self.keys.get(row.get("key_name") or "") or self.keys.get(name)
            priority = int(row.get("priority") or 100)
            existing = config.provider(name)
            if existing:
                existing.base_url = base_url
                if key:
                    existing.api_key = key
                if models:
                    existing.models = models
                existing.priority = priority
                applied += 1
                continue
            config.providers.append(ProviderConfig(
                name=name,
                base_url=base_url,
                api_key=key,
                api_key_env=f"NETCAST3R_{name.upper()}_KEY",
                priority=priority,
                models=models,
            ))
            applied += 1
        return applied


_bridge: DashboardBridge | None = None


def set_dashboard_bridge(bridge: "DashboardBridge | None") -> None:
    """Installed by build_server so scans see what the dashboard is configured with."""
    global _bridge
    _bridge = bridge


def _safe_results_dir(value) -> Path:
    """Keep run output under a relative directory; reject absolute/.. paths."""
    candidate = Path(str(value or "results"))
    if candidate.is_absolute() or ".." in candidate.parts:
        return Path("results")
    return candidate


def run_scan(run_id: str, target: str, options: dict, emit: Callable[[Event], None],
             should_stop: Callable[[], bool]) -> dict:
    from ..config import load_config
    from ..orchestrator import Orchestrator
    from ..scope import ScopeManager
    from ..store import Store

    if should_stop():
        return {}

    config = load_config()
    if _bridge is not None:
        try:
            _bridge.apply(config)
        except Exception:  # noqa: BLE001 - a broken index must not kill the run
            pass
    run_config = config.run
    if options.get("tier"):
        run_config.action_tier = str(options["tier"])
    if options.get("depth"):
        run_config.depth = int(options["depth"])
    if options.get("timeout"):
        run_config.timeout = float(options["timeout"])
    if options.get("rate"):
        run_config.requests_per_second = float(options["rate"])
    if options.get("delay"):
        run_config.delay = float(options["delay"])
    if options.get("retries") is not None and options.get("retries") != "":
        run_config.retries = int(options["retries"])
    if options.get("random_agent") is not None:
        run_config.random_user_agent = bool(options["random_agent"])
    if options.get("wayback") is not None:
        run_config.wayback = bool(options["wayback"])
    if options.get("subdomains") is not None:
        run_config.subdomains = bool(options["subdomains"])
    if options.get("max_pages"):
        run_config.concurrency = max(1, int(options["max_pages"]) // 25)

    results_root = _safe_results_dir(options.get("results_dir"))
    resume = bool(options.get("resume"))
    resume_from = str(options.get("resume_from") or "") if resume else ""
    out = results_root / run_id
    if resume and resume_from:
        # continue in the parent's results directory so the store keeps the
        # pages, scripts, findings and stage markers the run already wrote
        parent_out = results_root / resume_from
        if (parent_out / "netcast3r.db").is_file():
            out = parent_out
    out.mkdir(parents=True, exist_ok=True)
    store = Store(out / "netcast3r.db")
    scope = ScopeManager.from_files("", "", extra_in=[target])
    console = EventConsole(emit, run_id)
    orchestrator = Orchestrator(config, scope, store, console=console,
                                observer=console.model_call, resume=resume)
    try:
        summary = orchestrator.run([target], should_stop=should_stop)
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
        "unverified": len(getattr(orchestrator, "_unverified", []) or []),
        "review_loopholes": len((getattr(orchestrator, "_review", {}) or {}).get("loopholes", [])),
        "review_endpoints": len((getattr(orchestrator, "_review", {}) or {}).get("endpoints", [])),
        "report": summary.report,
        "results_dir": str(out),
        "findings_list": list(orchestrator.last_findings),
    }
