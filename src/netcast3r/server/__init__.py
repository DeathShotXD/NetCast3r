"""The dashboard backend.

One local HTTP server exposes everything the future GUI needs: runs, findings,
triage, providers, keys, settings, and a live event stream. The whole surface
is available as a pure ``Server.route`` call, so it is tested without a socket.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import threading
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, urlparse

from .events import EventBus
from .index import Index, is_training_target
from .jobs import JobManager
from .keys import KeyStore, mask
from .. import (chains, control, feedwatch, integrations, learning, quality,
                research, reveng, selfaudit, selfmodel, stix, surface, training)

API_VERSION = "v1"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
TOKEN_COOKIE = "netcast3r_token"
APP_DIR = Path(__file__).resolve().parent.parent / "web"

CSP = ("default-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
       "style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")


def _script_hashes(html: str) -> list[str]:
    """Hashes for every inline script, so the bundle needs no 'unsafe-inline'."""
    hashes = []
    for body in re.findall(r"<script\b[^>]*>(.*?)</script>", html, flags=re.S | re.I):
        if not body.strip():
            continue
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        hashes.append("'sha256-" + base64.b64encode(digest).decode("ascii") + "'")
    return hashes


def _app_csp(html: str) -> str:
    hashes = _script_hashes(html)
    script_src = "script-src 'self' " + " ".join(hashes) if hashes else "script-src 'self'"
    return ("default-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
            f"style-src 'self' 'unsafe-inline'; {script_src}; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'; object-src 'none'")


def _set_cookie(token: str) -> str:
    return f"{TOKEN_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json"
    headers: dict = field(default_factory=dict)


@dataclass
class Stream:
    frames: Iterator[str]
    content_type: str = "text/event-stream"
    headers: dict = field(default_factory=lambda: {
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _json(payload, status: int = 200) -> Response:
    return Response(status=status, body=json.dumps(payload, default=str).encode("utf-8"))


def _problem(status: int, title: str, detail: str = "") -> Response:
    body = json.dumps({"type": "about:blank", "title": title, "status": status,
                       "detail": detail}, default=str).encode("utf-8")
    return Response(status=status, body=body, content_type="application/problem+json")


def _str_list(value) -> list[str]:
    if isinstance(value, str):
        value = [value]
    return [str(item).strip() for item in (value or []) if str(item).strip()]


def _int_or(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _inventory_items(store, kind: str, limit: int) -> list:
    """Read one slice of a run's evidence store for the dashboard inspector."""
    limit = max(1, min(int(limit or 2000), 5000))
    readers = {
        "subdomains": lambda: store.list_subdomains(),
        "pages": lambda: store.list_assets(kind="page", limit=limit),
        "assets": lambda: store.list_assets(limit=limit),
        "js": lambda: store.list_js(limit=limit),
        "endpoints": lambda: store.list_endpoints(limit=limit),
        "secrets": lambda: store.list_secrets(limit=limit),
        "candidates": lambda: store.list_secret_candidates(limit=limit),
        "validations": lambda: store.list_validations(limit=limit),
        "corroborations": lambda: store.list_corroborations(limit=limit),
        "reviews": lambda: store.list_reviews(limit=limit),
        "findings": lambda: store.list_findings(limit=limit),
        "stages": lambda: [{"name": name, **data}
                           for name, data in store.stages().items()],
    }
    reader = readers.get(kind)
    if reader is None:
        return []
    return reader()


PLACEHOLDER = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetCast3r</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#05030A;color:#F5E9DC;
font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.card{border:1px solid #170F3F;border-radius:12px;padding:32px 40px;max-width:640px}
h1{margin:0 0 4px;font-size:20px;letter-spacing:2px;color:#C8F81A}
p{color:#A89591;margin:8px 0}
code{color:#F5E9DC}
a{color:#9F23DD}
</style></head><body><div class="card">
<h1>NETCAST3R API</h1>
<p>The backend is running. The graphical dashboard is not built yet.</p>
<p>API root: <code>/api/v1</code> &middot; live events: <code>/api/v1/events/stream</code></p>
<p>Try <code>GET /api/v1/meta</code>, <code>/api/v1/runs</code>, <code>/api/v1/findings</code>.</p>
</div></body></html>"""


class Server:
    def __init__(self, index: Index, bus: EventBus, jobs: JobManager, keys: KeyStore,
                 config=None, token: str = "", auth_required: bool = True,
                 static_dir: Path | None = None, base: Path | None = None):
        self.index = index
        self.bus = bus
        self.jobs = jobs
        self.keys = keys
        self.config = config
        self.base = Path(base) if base else None
        if self.config is None:
            # A bare server still needs an output root for runs it starts.
            from types import SimpleNamespace
            self.config = SimpleNamespace(results_dir="results")
        self.token = token
        self.auth_required = auth_required
        self.static_dir = Path(static_dir) if static_dir else None
        self.started = threading.Event()
        self._app_stamp: tuple[int, int] | None = None
        self._app_cache: str | None = None
        self._csp = CSP
        self._agent_lock = threading.Lock()
        self._lab_lock = threading.Lock()
        self.agent_runtime = None
        self.lab_runner = None
        self._routes = self._build_routes()
        try:
            learning.seed_builtin_skills(self.index)
        except Exception:  # noqa: BLE001 - seeding must never stop the server
            pass

    # -- mission agent ----------------------------------------------------
    def _agent(self):
        runtime = self.agent_runtime
        if runtime is None:
            with self._agent_lock:
                runtime = self.agent_runtime
                if runtime is None:
                    from .agent_runtime import AgentRuntime
                    runtime = AgentRuntime(self)
                    self.agent_runtime = runtime
        return runtime

    def _labs(self):
        runtime = self.lab_runner
        if runtime is None:
            with self._lab_lock:
                runtime = self.lab_runner
                if runtime is None:
                    from .lab_runner import LabRunner
                    runtime = LabRunner(self)
                    self.lab_runner = runtime
        return runtime

    # -- run helpers ------------------------------------------------------
    def _start_run(self, target: str, options: dict, parent_run_id: str = "") -> dict:
        """Create a run, record where it writes, then hand it to the workers."""
        from .runner import results_dir_for

        options = dict(options or {})
        run = self.index.create_run(target, options, parent_run_id=parent_run_id)
        self.index.update_run(run["id"], results_dir=str(results_dir_for(run["id"], options)))
        self.jobs.submit(run["id"], target, options)
        return self.index.get_run(run["id"])

    def _remove_run_output(self, run: dict, run_id: str) -> bool:
        """Delete a finished run's evidence directory when it is safe to do so."""
        raw = ((run.get("counts") or {}).get("results_dir")
               or run.get("results_dir") or "")
        if not raw:
            return False
        if self.index.results_dir_in_use(str(raw), exclude_run_id=run_id):
            return False

        root = Path(str(getattr(self.config, "results_dir", "results") or "results"))
        target = Path(str(raw))
        if not root.is_absolute():
            root = Path.cwd() / root
        if not target.is_absolute():
            target = Path.cwd() / target
        if target.is_symlink():
            return False
        try:
            target = target.resolve()
            root = root.resolve()
            target.relative_to(root)
        except (OSError, ValueError):
            return False
        if target == root or not target.name.startswith("run_"):
            return False
        if not target.is_dir():
            return False
        try:
            shutil.rmtree(target)
        except OSError:
            return False
        return True

    # -- provider helpers -------------------------------------------------
    @staticmethod
    def _provider_key_names(provider: dict) -> list[str]:
        names = []
        for candidate in (provider.get("key_name"), provider.get("id"), provider.get("name")):
            name = str(candidate or "").strip()
            if name and name not in names:
                names.append(name)
        return names

    def _provider_key(self, provider: dict) -> str:
        for name in self._provider_key_names(provider):
            value = self.keys.get(name)
            if value:
                return value
        return ""

    @staticmethod
    def _canonical_provider_key(provider: dict) -> str:
        return str(provider.get("key_name") or "").strip() or str(provider.get("id") or "")

    # -- routing ----------------------------------------------------------
    def _build_routes(self):
        routes = []

        def add(method: str, pattern: str):
            regex = re.compile("^" + pattern + "$")
            def wrap(func):
                routes.append((method, regex, func))
                return func
            return wrap

        @add("GET", r"/api/v1/meta")
        def meta(ctx):
            return _json({"name": "netcast3r", "version": _version(), "api_version": API_VERSION,
                          "auth_required": self.auth_required,
                          "capabilities": ["runs", "findings", "events", "providers", "keys",
                                           "settings", "triage", "missions", "approvals",
                                           "tool_calls", "mcp", "agent"]})

        @add("GET", r"/api/v1/healthz")
        def healthz(ctx):
            return _json({"status": "ok"})

        @add("GET", r"/api/v1/readyz")
        def readyz(ctx):
            try:
                self.index.get_setting("__ready__", None)
                ready = True
            except Exception:
                ready = False
            return _json({"ready": ready}, 200 if ready else 503)

        @add("GET", r"/api/v1/summary")
        def summary(ctx):
            return _json(self.index.totals())

        @add("GET", r"/api/v1/metrics")
        def metrics(ctx):
            return _json({"uptime": None, "active_runs": len(self.jobs.active()),
                          "runs": self.index.list_runs(limit=0)[1],
                          "findings": self.index.list_findings(limit=0)[1]})

        @add("GET", r"/api/v1/runs")
        def list_runs(ctx):
            status = ctx.query.get("status", "")
            runs, total = self.index.list_runs(status=status, q=ctx.query.get("q", ""),
                                               limit=ctx.limit, offset=ctx.offset)
            return _json({"items": runs, "total": total, "page": ctx.page, "size": ctx.limit})

        @add("POST", r"/api/v1/runs")
        def create_run(ctx):
            target = (ctx.json().get("target") or "").strip()
            if not target:
                return _problem(400, "target required")
            options = ctx.json().get("options")
            options = dict(options) if isinstance(options, dict) else {}
            if is_training_target(target) and not options.get("allow_training_scan"):
                return _problem(
                    400, "training target: a cast is a live scan",
                    "use the training mission agent (role=training) or pass "
                    "allow_training_scan=true only for an explicit lab crawl")
            if self.config is not None:
                options.setdefault("results_dir", str(getattr(self.config, "results_dir", "results")))
            return _json(self._start_run(target, options), 201)

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)")
        def get_run(ctx):
            run = self.index.get_run(ctx.params["id"])
            return _json(run) if run else _problem(404, "run not found")

        @add("DELETE", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)")
        def delete_run(ctx):
            run_id = ctx.params["id"]
            run = self.index.get_run(run_id)
            if not run:
                return _json({"deleted": False, "files_removed": False})
            if self.jobs.is_running(run_id):
                self.jobs.cancel(run_id)
                return _problem(409, "run is still active",
                                "stop it before deleting")
            deleted = self.index.delete_run(run_id)
            removed = self._remove_run_output(run, run_id) if deleted else False
            return _json({"deleted": deleted, "files_removed": removed})

        @add("POST", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/stop")
        def stop_run(ctx):
            return _json({"stopped": self.jobs.cancel(ctx.params["id"])})

        @add("POST", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/rerun")
        def rerun(ctx):
            parent = self.index.get_run(ctx.params["id"])
            if not parent:
                return _problem(404, "run not found")
            options = dict(parent.get("options") or {})
            # A rerun is a fresh scan. Inheriting resume flags would make it
            # continue the old run and write into the parent's directory.
            options.pop("resume", None)
            options.pop("resume_from", None)
            if is_training_target(str(parent.get("target") or "")) \
                    and not options.get("allow_training_scan"):
                return _problem(
                    400, "training target: a rerun would crawl the lab",
                    "use the training mission agent instead")
            if self.config is not None:
                options["results_dir"] = str(getattr(self.config, "results_dir", "results"))
            return _json(self._start_run(parent["target"], options,
                                         parent_run_id=parent["id"]), 201)

        @add("POST", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/resume")
        def resume_run(ctx):
            parent = self.index.get_run(ctx.params["id"])
            if not parent:
                return _problem(404, "run not found")
            if parent.get("status") in ("running", "queued"):
                return _problem(409, "run is still active", "stop it before resuming")
            options = dict(parent.get("options") or {})
            options["resume"] = True
            options["resume_from"] = parent["id"]
            if self.config is not None:
                options.setdefault("results_dir", str(getattr(self.config, "results_dir", "results")))
            return _json(self._start_run(parent["target"], options,
                                         parent_run_id=parent["id"]), 201)

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/inventory")
        def run_inventory(ctx):
            run = self.index.get_run(ctx.params["id"])
            if not run:
                return _problem(404, "run not found")
            kind = (ctx.query.get("kind") or "").strip()
            limit = _int_or(ctx.query.get("limit"), 2000)
            results_dir = (run.get("counts") or {}).get("results_dir") or run.get("results_dir") or ""
            empty = _json({"kind": kind, "items": [], "total": 0})
            if not results_dir:
                return empty
            db = Path(str(results_dir)) / "netcast3r.db"
            if not db.is_file():
                return empty
            from ..store import Store
            store = Store(db)
            try:
                items = _inventory_items(store, kind, limit)
            finally:
                store.close()
            return _json({"kind": kind, "items": items, "total": len(items)})

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/summary")
        def run_summary(ctx):
            return _json(self.index.summary(ctx.params["id"]))

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/events")
        def run_events(ctx):
            since = _int_or(ctx.query.get("since"), 0)
            return _json({"items": self.index.list_events(ctx.params["id"], since=since)})

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/events/stream")
        def run_stream(ctx):
            run_id = ctx.params["id"]
            return Stream(self._event_frames(run_id, ctx.last_event_id))

        @add("GET", r"/api/v1/events/stream")
        def global_stream(ctx):
            return Stream(self._event_frames(None, ctx.last_event_id))

        @add("GET", r"/api/v1/findings")
        def list_findings(ctx):
            items, total = self.index.list_findings(
                run_id=ctx.query.get("run_id", ""), severity=ctx.query.get("severity", ""),
                status=ctx.query.get("status", ""), q=ctx.query.get("q", ""),
                sort=ctx.query.get("sort", "created_at"), limit=ctx.limit, offset=ctx.offset)
            return _json({"items": items, "total": total, "page": ctx.page, "size": ctx.limit})

        @add("GET", r"/api/v1/findings/(?P<id>[A-Za-z0-9_]+)")
        def get_finding(ctx):
            finding = self.index.get_finding(ctx.params["id"])
            return _json(finding) if finding else _problem(404, "finding not found")

        @add("POST", r"/api/v1/findings")
        def create_finding(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                finding = self.index.create_finding(
                    title=str(body.get("title", "")),
                    severity=str(body.get("severity", "")),
                    run_id=str(body.get("run_id", "")),
                    impact=str(body.get("impact", "")),
                    evidence=str(body.get("evidence", "")),
                    source=str(body.get("source", "")),
                    secret_type=str(body.get("secret_type", "manual")),
                    value=str(body.get("value", "")),
                    confidence=body.get("confidence", 0.0),
                    tags=body.get("tags") if isinstance(body.get("tags"), list) else [],
                    notes=str(body.get("notes", "")),
                    fingerprint=str(body.get("fingerprint", "")),
                )
            except (TypeError, ValueError) as exc:
                return _problem(400, str(exc))
            return _json(finding, 201)

        @add("PATCH", r"/api/v1/findings/(?P<id>[A-Za-z0-9_]+)")
        def patch_finding(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                finding = self.index.patch_finding(
                    ctx.params["id"], status=body.get("status", ""), notes=body.get("notes"),
                    tags=body.get("tags"), severity_override=body.get("severity_override", ""))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(finding) if finding else _problem(404, "finding not found")

        @add("GET", r"/api/v1/reveng/kinds")
        def reveng_kinds(ctx):
            return _json({
                "kinds": list(reveng.KINDS),
                "decompilers": {
                    "jadx": bool(shutil.which("jadx")),
                    "apktool": bool(shutil.which("apktool")),
                    "readelf": bool(shutil.which("readelf")),
                },
                "note": ("Analysis is local and read-only. Observations are leads; record a "
                         "finding only after confirming it against the live target."),
            })

        @add("POST", r"/api/v1/reveng/analyze")
        def reveng_run(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            path = str(body.get("path") or "").strip()
            if not path:
                return _problem(400, "path required")
            kind = str(body.get("kind") or "auto").strip().lower()
            try:
                result = reveng.analyze(
                    kind, path,
                    max_files=int(body.get("max_files") or 4000),
                    timeout=int(body.get("timeout") or 240),
                    keep=bool(body.get("keep") or False),
                )
            except (TypeError, ValueError) as exc:
                return _problem(400, str(exc))
            except OSError as exc:
                return _problem(400, f"could not read the artifact: {exc.strerror or exc}")
            if body.get("markdown"):
                result["report_markdown"] = reveng.render_markdown(result)
            return _json(result)

        @add("GET", r"/api/v1/findings/(?P<id>[A-Za-z0-9_]+)/artifacts")
        def list_finding_artifacts(ctx):
            if not self.index.get_finding(ctx.params["id"]):
                return _problem(404, "finding not found")
            items = self.index.list_finding_artifacts(ctx.params["id"])
            return _json({"items": items, "total": len(items)})

        @add("POST", r"/api/v1/findings/(?P<id>[A-Za-z0-9_]+)/artifacts")
        def add_finding_artifact(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            name = str(body.get("name") or "artifact.bin")
            encoding = str(body.get("encoding") or "text").lower()
            raw = body.get("content")
            if not isinstance(raw, str) or not raw:
                return _problem(400, "content required")
            try:
                content = base64.b64decode(raw, validate=True) if encoding == "base64" \
                    else raw.encode("utf-8")
            except (ValueError, TypeError):
                return _problem(400, "content is not valid base64")
            try:
                artifact = self.index.add_finding_artifact(
                    ctx.params["id"], name, content,
                    str(body.get("content_type") or "application/octet-stream"))
            except ValueError as exc:
                return _problem(400 if "not found" not in str(exc) else 404, str(exc))
            return _json(artifact, 201)

        @add("GET", r"/api/v1/findings/(?P<id>[A-Za-z0-9_]+)/artifacts/"
                    r"(?P<aid>[A-Za-z0-9_]+)")
        def get_finding_artifact(ctx):
            artifact = self.index.get_finding_artifact(ctx.params["id"], ctx.params["aid"])
            if not artifact:
                return _problem(404, "artifact not found")
            if str(ctx.query.get("download") or "").lower() in {"1", "true", "yes"}:
                try:
                    content = Path(artifact["path"]).read_bytes()
                except OSError:
                    return _problem(404, "artifact file is missing")
                return Response(status=200, body=content,
                                content_type=artifact["content_type"],
                                headers={"Content-Disposition":
                                         f'attachment; filename="{artifact["name"]}"'})
            if str(ctx.query.get("content") or "").lower() in {"1", "true", "yes"}:
                try:
                    content = Path(artifact["path"]).read_bytes()
                except OSError:
                    return _problem(404, "artifact file is missing")
                try:
                    text = content.decode("utf-8")
                    if any(ord(char) < 32 and char not in "\n\r\t" for char in text):
                        raise UnicodeDecodeError("utf-8", content, 0, 1, "binary")
                    artifact = {**artifact, "content": text, "encoding": "text"}
                except UnicodeDecodeError:
                    artifact = {**artifact, "content": base64.b64encode(content).decode("ascii"),
                                "encoding": "base64"}
            return _json(artifact)

        @add("DELETE", r"/api/v1/findings/(?P<id>[A-Za-z0-9_]+)/artifacts/"
                       r"(?P<aid>[A-Za-z0-9_]+)")
        def delete_finding_artifact(ctx):
            deleted = self.index.delete_finding_artifact(ctx.params["id"], ctx.params["aid"])
            return _json({"deleted": True}) if deleted else _problem(404, "artifact not found")

        @add("GET", r"/api/v1/findings/(?P<id>[A-Za-z0-9_]+)/quality")
        def finding_quality(ctx):
            try:
                return _json(quality.score_finding(self.index, ctx.params["id"]))
            except ValueError as exc:
                return _problem(404, str(exc))

        @add("GET", r"/api/v1/hypotheses")
        def list_hypotheses(ctx):
            try:
                items, total = self.index.list_hypotheses(
                    mission_id=ctx.query.get("mission_id", ""),
                    status=ctx.query.get("status", ""), q=ctx.query.get("q", ""),
                    limit=ctx.limit, offset=ctx.offset)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json({"items": items, "total": total, "page": ctx.page,
                          "size": ctx.limit})

        @add("POST", r"/api/v1/hypotheses")
        def create_hypothesis(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                hypothesis = self.index.create_hypothesis(
                    title=str(body.get("title", "")),
                    target=str(body.get("target", "")),
                    mission_id=str(body.get("mission_id", "")),
                    technique=str(body.get("technique", "")),
                    rationale=str(body.get("rationale", "")),
                    expected=str(body.get("expected", "")))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(hypothesis, 201)

        @add("GET", r"/api/v1/hypotheses/(?P<id>[A-Za-z0-9_]+)")
        def get_hypothesis(ctx):
            hypothesis = self.index.get_hypothesis(ctx.params["id"])
            return _json(hypothesis) if hypothesis else _problem(404, "hypothesis not found")

        @add("PATCH", r"/api/v1/hypotheses/(?P<id>[A-Za-z0-9_]+)")
        def patch_hypothesis(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                hypothesis = self.index.patch_hypothesis(
                    ctx.params["id"], title=body.get("title"),
                    technique=body.get("technique"), rationale=body.get("rationale"),
                    expected=body.get("expected"), status=body.get("status"),
                    test=body.get("test") if "test" in body else None,
                    result=body.get("result") if "result" in body else None)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(hypothesis) if hypothesis else _problem(404, "hypothesis not found")

        @add("POST", r"/api/v1/hypotheses/(?P<id>[A-Za-z0-9_]+)/promote")
        def promote_hypothesis(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                finding = self.index.promote_hypothesis(
                    ctx.params["id"], title=str(body.get("title", "")),
                    severity=str(body.get("severity", "")),
                    impact=str(body.get("impact", "")),
                    evidence=str(body.get("evidence", "")),
                    tags=body.get("tags") if isinstance(body.get("tags"), list) else [],
                    source=str(body.get("source", "")))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(finding, 201)

        @add("GET", r"/api/v1/training")
        def training_status(ctx):
            try:
                return _json(training.status(
                    self.index, source=ctx.query.get("source", "")))
            except ValueError as exc:
                return _problem(400, str(exc))

        @add("GET", r"/api/v1/training/sources")
        def training_sources(ctx):
            items = training.sources(self.index)
            return _json({"items": items, "total": len(items)})

        @add("GET", r"/api/v1/training/plan")
        def training_plan(ctx):
            try:
                return _json(training.plan(
                    self.index, category=ctx.query.get("category", ""),
                    difficulty=ctx.query.get("difficulty", ""),
                    limit=_int_or(ctx.query.get("limit"), 5),
                    source=ctx.query.get("source", "")))
            except ValueError as exc:
                return _problem(400, str(exc))

        @add("POST", r"/api/v1/training/record")
        def training_record(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                result = training.record(
                    self.index, slug=str(body.get("lab_slug", "")),
                    status=str(body.get("status", "")),
                    lesson=str(body.get("lesson", "")),
                    evidence=str(body.get("evidence", "")),
                    notes=str(body.get("notes", "")),
                    instance_url=str(body.get("instance_url", "")),
                    verified=bool(body.get("verified") or False),
                    technique=str(body.get("technique", "")),
                    mission_id=str(body.get("mission_id", "")))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(result, 201)

        @add("GET", r"/api/v1/skill-packs")
        def skill_packs(ctx):
            installed = {skill["name"] for skill in
                         self.index.list_skills(limit=200)[0]}
            items = []
            for pack in learning.bundled_skill_packs():
                item = dict(pack)
                item["installed"] = pack["name"] in installed
                items.append(item)
            return _json({"items": items, "total": len(items),
                          "note": ("Bundled playbooks are installed at startup for "
                                   "every agent. Read one with skills_get.")})

        @add("GET", r"/api/v1/labs/recipes")
        def lab_recipes(ctx):
            items = self._labs().available()
            return _json({"items": items, "total": len(items)})

        @add("POST", r"/api/v1/labs/run")
        def lab_run(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                run = self._labs().start(
                    str(body.get("slug") or "auto"),
                    mission_id=str(body.get("mission_id") or ""))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(run, 201)

        @add("POST", r"/api/v1/labs/runs/(?P<id>[A-Za-z0-9_]+)/stop")
        def lab_stop(ctx):
            return _json({"stopped": self._labs().cancel(ctx.params["id"])})

        @add("GET", r"/api/v1/toolbook")
        def toolbook(ctx):
            return _json(training.toolbook(query=ctx.query.get("q", ""),
                                           name=ctx.query.get("name", "")))

        @add("GET", r"/api/v1/techniques")
        def technique_search(ctx):
            return _json(research.search(
                query=ctx.query.get("q", ""), tag=ctx.query.get("tag", ""),
                rarity=ctx.query.get("rarity", ""),
                impact=ctx.query.get("impact", ""),
                limit=_int_or(ctx.query.get("limit"), 20)))

        @add("GET", r"/api/v1/techniques/plan")
        def technique_plan(ctx):
            signals = [item for item in
                       str(ctx.query.get("signals", "")).split(",") if item.strip()]
            tags = [item for item in
                    str(ctx.query.get("tags", "")).split(",") if item.strip()]
            return _json(research.plan(
                self.index, target=ctx.query.get("target", ""),
                tech=ctx.query.get("tech", ""), signals=signals, tags=tags,
                limit=_int_or(ctx.query.get("limit"), 6)))

        @add("GET", r"/api/v1/research/sources")
        def research_sources(ctx):
            return _json(research.sources())

        @add("GET", r"/api/v1/chains")
        def chain_search(ctx):
            return _json(chains.search(
                query=ctx.query.get("q", ""), tag=ctx.query.get("tag", ""),
                impact=ctx.query.get("impact", ""),
                limit=_int_or(ctx.query.get("limit"), 20)))

        @add("GET", r"/api/v1/chains/plan")
        def chain_plan(ctx):
            signals = [item for item in
                       str(ctx.query.get("signals", "")).split(",") if item.strip()]
            tags = [item for item in
                    str(ctx.query.get("tags", "")).split(",") if item.strip()]
            return _json(chains.plan(
                self.index, target=ctx.query.get("target", ""),
                signals=signals, tags=tags,
                limit=_int_or(ctx.query.get("limit"), 4)))

        @add("GET", r"/api/v1/chains/sources")
        def chain_sources(ctx):
            return _json(chains.sources())

        @add("GET", r"/api/v1/hunt-brief")
        def hunt_brief_route(ctx):
            try:
                return _json(research.hunt_brief(
                    self.index, mission_id=str(ctx.query.get("mission_id", "")),
                    limit=_int_or(ctx.query.get("limit"), 3)))
            except ValueError as exc:
                return _problem(400, str(exc))

        @add("GET", r"/api/v1/hunt-plan")
        def hunt_plan_route(ctx):
            signals = [item for item in
                       str(ctx.query.get("signals", "")).split(",") if item.strip()]
            try:
                return _json(research.hunt_plan(
                    self.index, mission_id=str(ctx.query.get("mission_id", "")),
                    tech=ctx.query.get("tech", ""), signals=signals,
                    limit=_int_or(ctx.query.get("limit"), 6)))
            except ValueError as exc:
                return _problem(400, str(exc))

        @add("POST", r"/api/v1/research/ingest")
        def research_ingest(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                result = research.ingest(
                    self.index, url=str(body.get("url", "")),
                    title=str(body.get("title", "")),
                    notes=str(body.get("notes", "")),
                    tags=body.get("tags") if isinstance(body.get("tags"), list) else [])
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(result, 201)

        @add("GET", r"/api/v1/knowledge/sources")
        def knowledge_sources(ctx):
            items = list(feedwatch.sources())
            return _json({"items": items, "total": len(items)})

        @add("POST", r"/api/v1/knowledge/refresh")
        def knowledge_refresh(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                return _json(feedwatch.refresh(
                    self.index, source_id=str(body.get("source") or ""),
                    limit=_int_or(body.get("limit"), 20)), 201)
            except ValueError as exc:
                return _problem(400, str(exc))

        @add("GET", r"/api/v1/knowledge")
        def knowledge_list(ctx):
            return _json(feedwatch.recent(
                self.index, source=ctx.query.get("source", ""),
                limit=_int_or(ctx.query.get("limit"), 50)))

        @add("POST", r"/api/v1/knowledge/(?P<id>[A-Za-z0-9_]+)/read")
        def knowledge_read(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                return _json(feedwatch.read(
                    self.index, ctx.params["id"],
                    max_chars=_int_or(body.get("max_chars"), 8000)))
            except ValueError as exc:
                return _problem(400, str(exc))

        @add("GET", r"/api/v1/selfmodel")
        def selfmodel_status(ctx):
            return _json(selfmodel.snapshot(self.index))

        @add("GET", r"/api/v1/selfmodel/gaps")
        def selfmodel_gaps(ctx):
            return _json(selfmodel.gaps(
                self.index, limit=_int_or(ctx.query.get("limit"), 6)))

        @add("POST", r"/api/v1/selfmodel/evolve")
        def selfmodel_evolve(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            return _json(selfmodel.propose_gaps(
                self.index, limit=_int_or(body.get("limit"), 3)), 201)

        @add("GET", r"/api/v1/upgrades")
        def list_upgrades(ctx):
            items = self.index.list_upgrade_proposals(
                status=ctx.query.get("status", ""),
                area=ctx.query.get("area", ""),
                limit=_int_or(ctx.query.get("limit"), 100))
            return _json({"items": items, "total": len(items)})

        @add("POST", r"/api/v1/upgrades")
        def propose_upgrade(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                result = selfmodel.propose(
                    self.index, title=str(body.get("title", "")),
                    rationale=str(body.get("rationale", "")),
                    evidence=str(body.get("evidence", "")),
                    area=str(body.get("area", "")),
                    priority=str(body.get("priority", "")))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(result, 201)

        @add("PATCH", r"/api/v1/upgrades/(?P<proposal_id>[A-Za-z0-9_-]+)")
        def update_upgrade(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                result = self.index.update_upgrade_proposal(
                    ctx.params["proposal_id"], status=str(body.get("status", "")),
                    rationale=str(body.get("rationale", "")))
            except ValueError as exc:
                return _problem(400, str(exc))
            if result is None:
                return _problem(404, "upgrade proposal not found")
            return _json(result)

        @add("GET", r"/api/v1/self-audit")
        def self_audit(ctx):
            from ..mcp.tools import TOOLS
            return _json(selfaudit.audit(self.index.path.parent,
                                         routes=len(self._routes), tools=len(TOOLS)))

        @add("GET", r"/api/v1/diagnostics")
        def diagnostics(ctx):
            from ..mcp.tools import TOOLS
            return _json(selfaudit.diagnostics(self.index, self.index.path.parent,
                                               routes=len(self._routes),
                                               tools=len(TOOLS)))

        @add("GET", r"/api/v1/expertise")
        def expertise_profile(ctx):
            items = self.index.list_expertise(limit=ctx.limit)
            return _json({"items": items, "total": len(items),
                          "note": ("Per-instance technology exposure from recorded "
                                   "lessons; this is not a global ranking.")})

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/diff")
        def run_diff(ctx):
            against = ctx.query.get("against", "")
            if not against:
                return _problem(400, "against is required")
            try:
                return _json(surface.diff(self.index, ctx.params["id"], against,
                                          limit=ctx.limit))
            except ValueError as exc:
                return _problem(400, str(exc))

        @add("GET", r"/api/v1/programs/rank")
        def program_rank(ctx):
            return _json(quality.program_stats(self.index))

        @add("GET", r"/api/v1/stix/export")
        def stix_export(ctx):
            try:
                return _json(stix.export_bundle(
                    self.index, mission_id=ctx.query.get("mission_id", ""),
                    severity=ctx.query.get("severity", ""), limit=ctx.limit))
            except ValueError as exc:
                return _problem(404, str(exc))

        @add("GET", r"/api/v1/taxii/collections")
        def taxii_collections(ctx):
            config = stix.load_taxii_config(self.index.path.parent)
            if not config["configured"]:
                return _problem(400, "TAXII is not configured")
            try:
                client = stix.TaxiiClient(config["url"], config["token"],
                                          config["user"], config["password"])
                api_root = ctx.query.get("api_root", "")
                if not api_root:
                    discovery = client.discovery()
                    api_root = (discovery.get("api_roots") or [discovery.get("default", "")])[0]
                return _json({"api_root": api_root,
                              "collections": client.collections(api_root)})
            except (ValueError, RuntimeError) as exc:
                return _problem(400, str(exc))

        @add("GET", r"/api/v1/taxii/objects")
        def taxii_objects(ctx):
            config = stix.load_taxii_config(self.index.path.parent)
            if not config["configured"]:
                return _problem(400, "TAXII is not configured")
            api_root = ctx.query.get("api_root", "")
            collection = ctx.query.get("collection_id", "")
            if not api_root or not collection:
                return _problem(400, "api_root and collection_id are required")
            try:
                client = stix.TaxiiClient(config["url"], config["token"],
                                          config["user"], config["password"])
                return _json(client.objects(
                    api_root, collection, added_after=ctx.query.get("added_after", ""),
                    limit=ctx.limit))
            except (ValueError, RuntimeError) as exc:
                return _problem(400, str(exc))

        @add("GET", r"/api/v1/lessons")
        def list_lessons(ctx):
            items, total = self.index.list_lessons(
                q=ctx.query.get("q", ""), tag=ctx.query.get("tag", ""),
                outcome=ctx.query.get("outcome", ""), limit=ctx.limit)
            return _json({"items": items, "total": total})

        @add("POST", r"/api/v1/lessons")
        def create_lesson(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                lesson = self.index.add_lesson(
                    title=str(body.get("title", "")),
                    lesson=str(body.get("lesson", "")),
                    technique=str(body.get("technique", "")),
                    context=str(body.get("context", "")),
                    outcome=str(body.get("outcome", "success")),
                    next_step=str(body.get("next_step", "")),
                    tags=body.get("tags") if isinstance(body.get("tags"), list) else [],
                    mission_id=str(body.get("mission_id", "")),
                    run_id=str(body.get("run_id", "")),
                    task_id=str(body.get("task_id", "")),
                    source=str(body.get("source", "")),
                    confidence=body.get("confidence", 0.5),
                )
            except (TypeError, ValueError) as exc:
                return _problem(400, str(exc))
            return _json(lesson, 201)

        @add("GET", r"/api/v1/lessons/(?P<id>[A-Za-z0-9_]+)")
        def get_lesson(ctx):
            lesson = self.index.get_lesson(ctx.params["id"])
            return _json(lesson) if lesson else _problem(404, "lesson not found")

        @add("DELETE", r"/api/v1/lessons/(?P<id>[A-Za-z0-9_]+)")
        def delete_lesson(ctx):
            return _json({"deleted": True}) if self.index.delete_lesson(
                ctx.params["id"]) else _problem(404, "lesson not found")

        @add("POST", r"/api/v1/lessons/reflect")
        def reflect(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            tool_call_id = str(body.get("tool_call_id", ""))
            run_id = str(body.get("run_id", ""))
            try:
                if tool_call_id:
                    call = self.index.get_tool_call(tool_call_id)
                    if not call:
                        return _problem(404, "tool call not found")
                    draft = learning.reflect_tool_call(call)
                elif run_id:
                    draft = learning.reflect_run(self.index, run_id)
                else:
                    return _problem(400, "tool_call_id or run_id is required")
                lesson = self.index.add_lesson(**draft)
            except (TypeError, ValueError) as exc:
                return _problem(400, str(exc))
            return _json(lesson, 201)

        @add("GET", r"/api/v1/skills")
        def list_skills(ctx):
            items, total = self.index.list_skills(
                q=ctx.query.get("q", ""), limit=ctx.limit,
                status=ctx.query.get("status", ""))
            return _json({"items": items, "total": total})

        @add("POST", r"/api/v1/skills")
        def upsert_skill(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                skill = self.index.upsert_skill(
                    name=str(body.get("name", "")), body=str(body.get("body", "")),
                    title=str(body.get("title", "")),
                    description=str(body.get("description", "")),
                    tags=body.get("tags") if isinstance(body.get("tags"), list) else [],
                    source=str(body.get("source", "")),
                )
            except (TypeError, ValueError) as exc:
                return _problem(400, str(exc))
            return _json(skill, 201)

        @add("GET", r"/api/v1/skills/(?P<name>[A-Za-z0-9_.-]+)")
        def get_skill(ctx):
            skill = self.index.get_skill(ctx.params["name"])
            return _json(skill) if skill else _problem(404, "skill not found")

        @add("POST", r"/api/v1/skills/(?P<name>[A-Za-z0-9_.-]+)/use")
        def use_skill(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            skill = self.index.use_skill(ctx.params["name"],
                                         success=bool(body.get("success", True)))
            return _json(skill) if skill else _problem(404, "skill not found")

        @add("PATCH", r"/api/v1/skills/(?P<name>[A-Za-z0-9_.-]+)")
        def patch_skill(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                skill = self.index.set_skill_status(
                    ctx.params["name"], str(body.get("status", "")))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(skill) if skill else _problem(404, "skill not found")

        @add("DELETE", r"/api/v1/skills/(?P<name>[A-Za-z0-9_.-]+)")
        def delete_skill(ctx):
            return _json({"deleted": True}) if self.index.delete_skill(
                ctx.params["name"]) else _problem(404, "skill not found")

        @add("GET", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)/next-actions")
        def mission_next_actions(ctx):
            try:
                return _json(learning.suggest_next(self.index, ctx.params["id"]))
            except ValueError as exc:
                return _problem(404, str(exc))

        @add("GET", r"/api/v1/missions")
        def list_missions(ctx):
            try:
                items, total = self.index.list_missions(
                    status=ctx.query.get("status", ""), limit=ctx.limit, offset=ctx.offset)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json({"items": items, "total": total, "page": ctx.page, "size": ctx.limit})

        @add("POST", r"/api/v1/missions")
        def create_mission(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                mission = self.index.create_mission(
                    title=str(body.get("title", "")), target=str(body.get("target", "")),
                    objective=str(body.get("objective", "")), status=str(body.get("status", "draft")),
                    autonomy=str(body.get("autonomy", "supervised")),
                    budget=body.get("budget") if isinstance(body.get("budget"), dict) else {},
                    scope=body.get("scope") if isinstance(body.get("scope"), list) else [],
                    plan=body.get("plan") if isinstance(body.get("plan"), list) else [])
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(mission, 201)

        @add("GET", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)")
        def get_mission(ctx):
            mission = self.index.get_mission(ctx.params["id"])
            return _json(mission) if mission else _problem(404, "mission not found")

        @add("PATCH", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)")
        def patch_mission(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            fields = {key: body.get(key) for key in
                      ("title", "target", "objective", "status", "autonomy",
                       "budget", "scope", "plan", "last_run_id") if key in body}
            try:
                mission = self.index.patch_mission(ctx.params["id"], **fields)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(mission) if mission else _problem(404, "mission not found")

        @add("DELETE", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)")
        def delete_mission(ctx):
            return _json({"deleted": self.index.delete_mission(ctx.params["id"])})

        @add("GET", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)/agent")
        def get_mission_agent(ctx):
            payload = self._agent().status(ctx.params["id"])
            return _json(payload) if payload else _problem(404, "mission not found")

        @add("POST", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)/agent/start")
        def start_mission_agent(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                payload = self._agent().start(ctx.params["id"], body)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(payload, 202)

        @add("POST", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)/agent/pause")
        def pause_mission_agent(ctx):
            try:
                payload = self._agent().pause(ctx.params["id"])
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(payload)

        @add("POST", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)/agent/resume")
        def resume_mission_agent(ctx):
            try:
                payload = self._agent().resume(ctx.params["id"])
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(payload)

        @add("POST", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)/agent/stop")
        def stop_mission_agent(ctx):
            try:
                payload = self._agent().stop(ctx.params["id"])
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(payload)

        @add("POST", r"/api/v1/missions/(?P<id>[A-Za-z0-9_]+)/runs")
        def start_mission_run(ctx):
            mission = self.index.get_mission(ctx.params["id"])
            if not mission:
                return _problem(404, "mission not found")
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            run_id = str(body.get("run_id", "")).strip()
            if run_id:
                updated = self.index.add_mission_run(mission["id"], run_id)
                if not updated:
                    return _problem(404, "run not found")
                return _json(updated, 201)
            target = str(body.get("target") or mission.get("target") or "").strip()
            options = body.get("options")
            options = dict(options) if isinstance(options, dict) else {}
            if not target:
                return _problem(400, "target required")
            if mission.get("training") or is_training_target(target):
                return _problem(
                    400, "training mission: a cast would crawl the lab",
                    "start the mission agent with role=training instead")
            run = self._start_run(target, options)
            self.index.add_mission_run(mission["id"], run["id"])
            if mission.get("status") in {"draft", "paused"}:
                mission = self.index.patch_mission(mission["id"], status="active") or mission
            return _json({"mission": mission, "run": run}, 201)

        @add("GET", r"/api/v1/approvals")
        def list_approvals(ctx):
            try:
                items, total = self.index.list_approvals(
                    status=ctx.query.get("status", ""),
                    mission_id=ctx.query.get("mission_id", ""),
                    limit=ctx.limit, offset=ctx.offset)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json({"items": items, "total": total, "page": ctx.page, "size": ctx.limit})

        @add("POST", r"/api/v1/approvals")
        def create_approval(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                approval = self.index.create_approval(
                    mission_id=str(body.get("mission_id", "")),
                    action=str(body.get("action", "")), risk=str(body.get("risk", "medium")),
                    requested_by=str(body.get("requested_by", "agent")),
                    reason=str(body.get("reason", "")),
                    payload=body.get("payload") if isinstance(body.get("payload"), dict) else {},
                    run_id=str(body.get("run_id", "")))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(approval, 201) if approval else _problem(404, "mission not found")

        @add("POST", r"/api/v1/approvals/(?P<id>[A-Za-z0-9_]+)/decision")
        def decide_approval(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                approval = self.index.decide_approval(
                    ctx.params["id"], str(body.get("decision", "")),
                    decided_by=str(body.get("decided_by", "operator")),
                    reason=str(body.get("reason", "")))
            except ValueError as exc:
                return _problem(409 if "already" in str(exc) else 400, str(exc))
            return _json(approval) if approval else _problem(404, "approval not found")

        @add("GET", r"/api/v1/approvals/(?P<id>[A-Za-z0-9_]+)")
        def get_approval(ctx):
            approval = self.index.get_approval(ctx.params["id"])
            return _json(approval) if approval else _problem(404, "approval not found")

        @add("POST", r"/api/v1/approvals/(?P<id>[A-Za-z0-9_]+)/consume")
        def consume_approval(ctx):
            try:
                approval = self.index.consume_approval(ctx.params["id"])
            except ValueError as exc:
                return _problem(409, str(exc))
            return _json(approval) if approval else _problem(404, "approval not found")

        @add("GET", r"/api/v1/submissions")
        def list_submissions(ctx):
            try:
                items, total = self.index.list_submissions(
                    status=ctx.query.get("status", ""),
                    mission_id=ctx.query.get("mission_id", ""),
                    finding_id=ctx.query.get("finding_id", ""),
                    platform=ctx.query.get("platform", ""),
                    limit=ctx.limit, offset=ctx.offset)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json({"items": items, "total": total, "page": ctx.page,
                          "size": ctx.limit})

        @add("POST", r"/api/v1/submissions")
        def create_submission(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                submission = self.index.create_submission(
                    title=str(body.get("title", "")),
                    platform=str(body.get("platform", "other")),
                    program=str(body.get("program", "")),
                    target=str(body.get("target", "")),
                    severity=str(body.get("severity", "medium")),
                    status=str(body.get("status", "draft")),
                    mission_id=str(body.get("mission_id", "")),
                    finding_id=str(body.get("finding_id", "")),
                    run_id=str(body.get("run_id", "")),
                    bounty_cents=body.get("bounty_cents", 0),
                    currency=str(body.get("currency", "USD")),
                    external_id=str(body.get("external_id", "")),
                    url=str(body.get("url", "")),
                    report_path=str(body.get("report_path", "")),
                    notes=str(body.get("notes", "")))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(submission, 201)

        @add("GET", r"/api/v1/submissions/summary")
        def submission_summary(ctx):
            return _json(self.index.submission_summary())

        @add("GET", r"/api/v1/submissions/(?P<id>[A-Za-z0-9_]+)")
        def get_submission(ctx):
            submission = self.index.get_submission(ctx.params["id"])
            return _json(submission) if submission else _problem(404, "submission not found")

        @add("PATCH", r"/api/v1/submissions/(?P<id>[A-Za-z0-9_]+)")
        def patch_submission(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            fields = {key: body.get(key) for key in
                      ("title", "platform", "program", "target", "severity", "status",
                       "bounty_cents", "currency", "external_id", "url", "report_path",
                       "notes", "mission_id", "finding_id", "run_id") if key in body}
            try:
                submission = self.index.patch_submission(ctx.params["id"], **fields)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(submission) if submission else _problem(404, "submission not found")

        @add("DELETE", r"/api/v1/submissions/(?P<id>[A-Za-z0-9_]+)")
        def delete_submission(ctx):
            return _json({"deleted": self.index.delete_submission(ctx.params["id"])})

        @add("GET", r"/api/v1/tool-calls")
        def list_tool_calls(ctx):
            try:
                items, total = self.index.list_tool_calls(
                    tool=ctx.query.get("tool", ""), status=ctx.query.get("status", ""),
                    mission_id=ctx.query.get("mission_id", ""),
                    run_id=ctx.query.get("run_id", ""),
                    limit=ctx.limit, offset=ctx.offset)
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json({"items": items, "total": total, "page": ctx.page, "size": ctx.limit})

        @add("POST", r"/api/v1/tool-calls")
        def create_tool_call(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            try:
                call = self.index.add_tool_call(
                    tool=str(body.get("tool", "")), risk=str(body.get("risk", "low")),
                    status=str(body.get("status", "ok")), actor=str(body.get("actor", "")),
                    mission_id=str(body.get("mission_id", "")),
                    run_id=str(body.get("run_id", "")),
                    approval_id=str(body.get("approval_id", "")),
                    args=body.get("args") if isinstance(body.get("args"), dict) else {},
                    result=body.get("result"), error=str(body.get("error", "")),
                    duration_ms=_int_or(body.get("duration_ms"), 0))
            except ValueError as exc:
                return _problem(400, str(exc))
            return _json(call, 201)

        @add("GET", r"/api/v1/tool-calls/(?P<id>[A-Za-z0-9_]+)")
        def get_tool_call(ctx):
            call = self.index.get_tool_call(ctx.params["id"])
            return _json(call) if call else _problem(404, "tool call not found")

        @add("GET", r"/api/v1/integrations")
        def integrations_status(ctx):
            tools = []
            for name, (mode, binary, risk, description) in integrations.TOOL_CATALOG.items():
                tools.append({"name": name, "mode": mode, "risk": risk,
                              "installed": bool(shutil.which(binary)),
                              "description": description})
            burp = integrations.load_burp_config(self.index.path.parent)
            return _json({
                "tools": tools,
                "burp": {"configured": burp["configured"], "url": burp["url"]},
                "note": ("Local tools run through recon_passive/recon_active; Burp "
                         "MCP is driven through burp_status/burp_call."),
            })

        @add("GET", r"/api/v1/mcp")
        def mcp_info(ctx):
            state = control.read_mcp_state(getattr(self, "base", None))
            public = {key: value for key, value in (state or {}).items() if key != "token"}
            if public:
                public["alive"] = control.pid_alive(int(state.get("pid") or 0))
            plane = control.public_control_plane(getattr(self, "base", None))
            try:
                from ..mcp.tools import catalog
                tools = catalog()
            except Exception as exc:  # noqa: BLE001 - informational endpoint
                tools = []
                registry_error = f"{type(exc).__name__}: {exc}"
            else:
                registry_error = ""
            return _json({
                "server": public or None,
                "connected": bool(public and public.get("alive")),
                "control_plane": plane,
                "state_file": str(control.mcp_state_path(getattr(self, "base", None))),
                "tools": tools,
                "registry_error": registry_error,
            })

        @add("GET", r"/api/v1/keys")
        def list_keys(ctx):
            return _json({"items": self.keys.listing()})

        @add("PUT", r"/api/v1/keys/(?P<name>[A-Za-z0-9_.\-]+)")
        def put_key(ctx):
            value = (ctx.json().get("value") or "").strip()
            if not value:
                return _problem(400, "value required")
            self.keys.set(ctx.params["name"], value)
            return _json({"name": ctx.params["name"], "masked": mask(value)})

        @add("DELETE", r"/api/v1/keys/(?P<name>[A-Za-z0-9_.\-]+)")
        def delete_key(ctx):
            return _json({"deleted": self.keys.delete(ctx.params["name"])})

        @add("GET", r"/api/v1/settings")
        def get_settings(ctx):
            return _json({"items": self.index.list_settings()})

        @add("PATCH", r"/api/v1/settings")
        def patch_settings(ctx):
            body = ctx.json()
            body = body if isinstance(body, dict) else {}
            for key, value in body.items():
                self.index.set_setting(str(key), value)
            return _json({"items": self.index.list_settings()})

        @add("GET", r"/api/v1/providers/health")
        def providers_health(ctx):
            items = []
            for provider in self.index.list_providers():
                items.append({
                    "id": provider["id"],
                    "name": provider.get("name", ""),
                    "base_url": provider.get("base_url", ""),
                    "models": provider.get("models", []),
                    "enabled": provider.get("enabled", 1),
                    "priority": provider.get("priority", 100),
                    "healthy": provider.get("healthy", 0),
                    "last_checked": provider.get("last_checked", ""),
                    "key_set": bool(self._provider_key(provider)),
                })
            return _json({"items": items})

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/report")
        def run_report(ctx):
            run = self.index.get_run(ctx.params["id"])
            if not run:
                return _problem(404, "run not found")
            results_dir = (run.get("counts") or {}).get("results_dir") or run.get("results_dir") or ""
            if not results_dir:
                return _problem(404, "no report", "this run has no results directory yet")
            candidate = Path(str(results_dir)) / "report.md"
            try:
                if not candidate.is_file():
                    return _problem(404, "no report", "the report has not been written yet")
                text = candidate.read_text("utf-8", "ignore")
            except OSError:
                return _problem(404, "no report", "the report could not be read")
            return Response(body=text.encode("utf-8"),
                            content_type="text/markdown; charset=utf-8")

        @add("GET", r"/api/v1/providers")
        def list_providers(ctx):
            items = self.index.list_providers()
            for item in items:
                item["masked"] = mask(self._provider_key(item))
            return _json({"items": items})

        @add("POST", r"/api/v1/providers")
        def add_provider(ctx):
            body = ctx.json()
            provider = self.index.add_provider(
                name=body.get("name", ""), kind=body.get("kind", "openai"),
                base_url=body.get("base_url", ""), model=body.get("model", ""),
                key_name=body.get("key_name", ""),
                models=_str_list(body.get("models")),
                priority=_int_or(body.get("priority"), 100),
                enabled=1 if body.get("enabled", True) in (True, 1, "1") else 0)
            api_key = str(body.get("api_key") or "").strip()
            if api_key:
                self.keys.set(self._canonical_provider_key(provider), api_key)
            provider["masked"] = mask(self._provider_key(provider))
            return _json(provider, 201)

        @add("PATCH", r"/api/v1/providers/(?P<id>[A-Za-z0-9_]+)")
        def patch_provider(ctx):
            body = ctx.json()
            existing = self.index.get_provider(ctx.params["id"])
            if not existing:
                return _problem(404, "provider not found")
            fields = {}
            for key in ("name", "kind", "base_url", "model", "key_name", "last_checked"):
                if key in body:
                    fields[key] = str(body[key])
            if "models" in body:
                fields["models"] = _str_list(body.get("models"))
            if "priority" in body:
                fields["priority"] = _int_or(body.get("priority"), 100)
            if "enabled" in body:
                fields["enabled"] = 1 if body.get("enabled") in (True, 1, "1") else 0
            provider = self.index.update_provider(ctx.params["id"], **fields)
            old_name = self._canonical_provider_key(existing)
            new_name = self._canonical_provider_key(provider)
            api_key = str(body.get("api_key") or "").strip()
            if api_key:
                self.keys.set(new_name, api_key)
                if old_name != new_name:
                    self.keys.delete(old_name)
            elif old_name != new_name:
                # Renaming a key reference moves the secret with the row
                # instead of orphaning it under the old name. If the new name
                # already has a key (the UI writes it before the rename), keep
                # that one and only drop the old alias.
                existing_key = self.keys.get(old_name)
                if existing_key:
                    if not self.keys.get(new_name):
                        self.keys.set(new_name, existing_key)
                    self.keys.delete(old_name)
            provider["masked"] = mask(self._provider_key(provider))
            return _json(provider)

        @add("DELETE", r"/api/v1/providers/(?P<id>[A-Za-z0-9_]+)")
        def delete_provider(ctx):
            provider = self.index.get_provider(ctx.params["id"])
            if not provider:
                return _json({"deleted": False, "key_removed": False})
            deleted = self.index.delete_provider(ctx.params["id"])
            removed = False
            if deleted:
                used_names = set()
                for row in self.index.list_providers():
                    used_names.update(self._provider_key_names(row))
                # Clean up the canonical key and any legacy aliases, but never
                # a name another provider still resolves.
                for name in self._provider_key_names(provider):
                    if name not in used_names:
                        removed = self.keys.delete(name) or removed
            return _json({"deleted": deleted, "key_removed": removed})

        @add("POST", r"/api/v1/providers/(?P<id>[A-Za-z0-9_]+)/test")
        def test_provider(ctx):
            provider = self.index.get_provider(ctx.params["id"])
            if not provider:
                return _problem(404, "provider not found")
            result = self._test_provider(provider)
            self.index.update_provider(provider["id"], healthy=1 if result["ok"] else 0,
                                       last_checked=_utc())
            return _json(result)

        @add("GET", r"/")
        def index_page(ctx):
            app = self._app()
            if app is None:
                return Response(body=PLACEHOLDER.encode("utf-8"),
                                content_type="text/html; charset=utf-8")
            headers = {"Content-Security-Policy": self._csp}
            token = str(ctx.query.get("token", ""))
            if self.auth_required and self._matches(token, self.token):
                headers["Set-Cookie"] = _set_cookie(self.token)
            return Response(body=app.encode("utf-8"), content_type="text/html; charset=utf-8",
                            headers=headers)

        @add("POST", r"/api/v1/session")
        def session(ctx):
            supplied = str(ctx.json().get("token") or "")
            if not self._matches(supplied, self.token):
                return _problem(401, "bad token", "that session token was not accepted")
            return Response(body=json.dumps({"ok": True}).encode(),
                            headers={"Set-Cookie": _set_cookie(self.token)})

        return routes

    # -- static app -------------------------------------------------------
    def _app(self) -> str | None:
        """The built dashboard, re-read whenever the file on disk changes.

        A rebuild should be visible on the next page load instead of needing a
        server restart; the stat check keeps the common path to one syscall.
        """
        path = None
        if self.static_dir and (self.static_dir / "index.html").exists():
            path = self.static_dir / "index.html"
        elif (APP_DIR / "index.html").exists():
            path = APP_DIR / "index.html"
        if path is None:
            return None
        try:
            stat = path.stat()
            stamp = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            return self._app_cache
        if stamp != self._app_stamp:
            text = path.read_text("utf-8")
            self._app_cache = text
            self._csp = _app_csp(text) if text else CSP
            self._app_stamp = stamp
        return self._app_cache

    @staticmethod
    def _matches(supplied: str, expected: str) -> bool:
        try:
            return bool(supplied) and secrets.compare_digest(supplied, expected)
        except (TypeError, ValueError):
            return False

    # -- helpers ----------------------------------------------------------
    def _event_frames(self, run_id: str | None, last_event_id: int | None):
        """Yield replay frames, then live frames, without gaps or interleaving.

        The subscription is opened *before* the database is read so events
        published during the read are captured live; anything already
        persisted up to the replay boundary is dropped from the live queue
        by ``EventBus.stream(since=...)``. The backlog is paged so a long run
        replays fully (bounded by the bus ring size), and replay frames are
        written straight to the wire - never through the subscriber queue,
        where a busy run could overflow it mid-replay.
        """
        sub = self.bus.subscribe()
        replay: list[dict] = []
        if run_id is not None:
            since = max(0, last_event_id or 0)
            while len(replay) < self.bus.capacity:
                page = self.index.list_events(run_id, since=since, limit=1000)
                if not page:
                    break
                replay.extend(page)
                since = int(page[-1].get("seq") or since)
                if len(page) < 1000:
                    break
        boundary = max((int(event.get("seq") or 0) for event in replay),
                       default=last_event_id or 0)
        return self._frames(run_id, replay, boundary, sub)

    def _frames(self, run_id: str | None, replay: list[dict], boundary: int, sub):
        try:
            for event in replay:
                yield (f"id: {event.get('seq', 0)}\nevent: message\ndata: "
                       + json.dumps(event, default=str) + "\n\n")
            yield from self.bus.stream(sub, run_id=run_id, since=boundary)
        finally:
            self.bus.unsubscribe(sub)

    @staticmethod
    def _reachable_host(host: str) -> bool:
        """Reject link-local, reserved, and metadata hosts by resolved address.

        Local and private endpoints stay allowed so an operator can still test
        a local model server; only the addresses that are never a real provider
        (link-local, reserved, unspecified, multicast) are refused.
        """
        import ipaddress
        import socket

        host = (host or "").strip().strip(".").lower()
        if not host or host.endswith(".internal"):
            return False
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError:
            return True
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            if ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                return False
        return True

    def _test_provider(self, provider: dict) -> dict:
        import time as _time

        import httpx

        value = self._provider_key(provider)
        base_url = (provider.get("base_url") or "").rstrip("/")
        if not value:
            return {"ok": False, "reason": "no key", "detail": "paste a key first"}
        if not base_url:
            return {"ok": False, "reason": "no base_url", "detail": "set a base url"}
        if not base_url.startswith(("http://", "https://")):
            return {"ok": False, "reason": "bad base_url",
                    "detail": "must start with http:// or https://"}
        host = (urlparse(base_url).hostname or "").lower()
        if not self._reachable_host(host):
            return {"ok": False, "reason": "blocked host",
                    "detail": "that endpoint is not reachable on the public or local network"}
        started = _time.time()
        try:
            with httpx.Client(timeout=10.0, follow_redirects=False) as client:
                response = client.get(f"{base_url}/models",
                                      headers={"Authorization": f"Bearer {value}"})
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "reason": "network", "detail": type(exc).__name__}
        latency = int((_time.time() - started) * 1000)
        if response.status_code in (200, 201):
            models = []
            try:
                payload = response.json()
                models = [row.get("id") for row in (payload.get("data") or [])][:200]
            except Exception:
                pass
            return {"ok": True, "reason": "ok", "latency_ms": latency, "models": models}
        if response.status_code in (401, 403):
            return {"ok": False, "reason": "auth", "detail": f"HTTP {response.status_code}"}
        if response.status_code == 429:
            return {"ok": False, "reason": "rate_limited", "detail": "HTTP 429"}
        return {"ok": False, "reason": "http", "detail": f"HTTP {response.status_code}"}

    # -- dispatch ---------------------------------------------------------
    def route(self, method: str, path: str, query: dict, headers: dict,
              body: bytes) -> Response | Stream:
        if not self._host_ok(headers.get("host", "")):
            return _problem(421, "bad host", "host not allowed")
        if not self._origin_ok(method, headers):
            return _problem(403, "bad origin", "cross-origin request refused")
        if self.auth_required and not self._token_ok(query, headers):
            # The shell and the unlock screen are served unauthenticated; they
            # carry no data. Every API route still demands a session token.
            if path not in ("/", "/api/v1/session"):
                return _problem(401, "unauthorized", "missing or bad session token")
        for route_method, regex, func in self._routes:
            match = regex.match(path)
            if not match:
                continue
            if route_method != method:
                continue
            ctx = _Context(method=method, path=path, query=query, headers=headers,
                           body=body, params=match.groupdict(), server=self)
            return func(ctx)
        return _problem(404, "not found", path)

    def _host_ok(self, host: str) -> bool:
        name = host.rsplit(":", 1)[0] if host and not host.startswith("[") else host
        if host.startswith("["):
            name = host.split("]")[0] + "]"
        return name in ALLOWED_HOSTS

    def _origin_ok(self, method: str, headers: dict) -> bool:
        if method in ("GET", "HEAD", "OPTIONS"):
            return True
        origin = headers.get("origin", "")
        if not origin:
            return True  # non-browser clients carry no Origin
        host = urlparse(origin).hostname or ""
        return host in ALLOWED_HOSTS

    def _token_ok(self, query: dict, headers: dict) -> bool:
        supplied = headers.get("x-netcast3r-token", "") or query.get("token", "")
        if not supplied:
            for part in headers.get("cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == TOKEN_COOKIE:
                    supplied = value
                    break
        return self._matches(supplied, self.token)


class _Context:
    def __init__(self, method, path, query, headers, body, params, server: Server):
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
        self.params = params
        self.server = server
        self.page = max(1, _int_or(query.get("page"), 1))
        self.limit = min(500, max(1, _int_or(query.get("size"), 50)))
        self.offset = (self.page - 1) * self.limit
        self.last_event_id = _int_or(query.get("last_event_id") or headers.get("last-event-id"), 0) or None

    def json(self) -> dict:
        if not self.body:
            return {}
        try:
            data = json.loads(self.body.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}


def _version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "0.0.0"


def _restore_session_token(server: Server) -> bool:
    """Keep a live MCP client connected across a clean UI restart.

    The token is already stored in a 0600 state file. Reusing it is safer than
    minting a new one and silently breaking every connected agent; a state
    file owned by a still-running process is never reused.
    """
    previous = control.read_control_plane(server.base)
    if not previous or not previous.get("token"):
        return False
    if control.pid_alive(int(previous.get("pid") or 0)):
        return False
    server.token = str(previous["token"])
    return True


def _utc() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NetCast3r"

    def log_message(self, *args):  # keep the console clean
        pass

    def _dispatch(self, method: str) -> None:
        server: Server = self.server.app  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {key.lower(): value for key, value in self.headers.items()}
        try:
            result = server.route(method, parsed.path, query, headers, body)
        except Exception as exc:  # noqa: BLE001
            result = _problem(500, "internal error", type(exc).__name__)

        if isinstance(result, Stream):
            self.send_response(200)
            self.send_header("Content-Type", result.content_type)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            for key, value in result.headers.items():
                self.send_header(key, value)
            self.end_headers()
            try:
                for frame in result.frames:
                    self.wfile.write(frame.encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        self.send_response(result.status)
        self.send_header("Content-Type", result.content_type)
        self.send_header("Content-Length", str(len(result.body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if "Content-Security-Policy" not in result.headers:
            self.send_header("Content-Security-Policy", CSP)
        for key, value in result.headers.items():
            self.send_header(key, value)
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(result.body)

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_DELETE(self):
        self._dispatch("DELETE")


def build_server(results_dir: str | Path = "results", base: Path | None = None,
                 runner=None, config=None, workers: int = 2,
                 recover: bool = True) -> Server:
    from types import SimpleNamespace

    from . import runner as runner_module
    from .runner import DashboardBridge, run_scan

    base = Path(base) if base else Path.home() / ".netcast3r"
    if config is None:
        config = SimpleNamespace(results_dir=str(results_dir))
    index = Index(base / "netcast3r.db")
    bus = EventBus()
    keys = KeyStore(base)
    runner_module.set_dashboard_bridge(DashboardBridge(index, keys))
    jobs = JobManager(index, bus, runner or run_scan, workers=workers)
    server = Server(index, bus, jobs, keys, config=config, token=secrets.token_urlsafe(24),
                    base=base)
    if recover:
        jobs.recover()
    return server


def serve(host: str = "127.0.0.1", port: int = 7857, *, open_browser: bool = True,
          results_dir: str | Path = "results", base: Path | None = None,
          runner=None, config=None, auth_required: bool = True) -> Server:
    server = build_server(results_dir=results_dir, base=base, runner=runner, config=config)
    _restore_session_token(server)
    server.auth_required = auth_required
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.app = server  # type: ignore[attr-defined]
    httpd.daemon_threads = True
    url = f"http://{host}:{httpd.server_address[1]}/?token={server.token}"
    print(f"NetCast3r API on {url}")
    control.write_control_plane(server.base, {
        "schema": 1,
        "pid": os.getpid(),
        "url": f"http://{host}:{httpd.server_address[1]}",
        "host": host,
        "port": httpd.server_address[1],
        "token": server.token,
        "base": str(server.base),
        "results_dir": str(getattr(server.config, "results_dir", results_dir)),
        "started_at": _utc(),
        "version": _version(),
    })
    server.started.set()
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server.agent_runtime is not None:
            server.agent_runtime.shutdown()
        if getattr(server, "lab_runner", None) is not None:
            server.lab_runner.shutdown(wait=True)
        server.jobs.shutdown(wait=True)
        server.index.close()
        httpd.server_close()
        control.remove_control_plane(server.base, pid=os.getpid())
    return server
