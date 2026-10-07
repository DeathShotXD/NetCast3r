"""The dashboard backend.

One local HTTP server exposes everything the future GUI needs: runs, findings,
triage, providers, keys, settings, and a live event stream. The whole surface
is available as a pure ``Server.route`` call, so it is tested without a socket.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, urlparse

from .events import EventBus
from .index import Index
from .jobs import JobManager
from .keys import KeyStore, mask

API_VERSION = "v1"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
TOKEN_COOKIE = "netcast3r_token"
APP_DIR = Path(__file__).resolve().parent.parent / "web"

CSP = ("default-src 'self'; img-src 'self' data:; connect-src 'self'; "
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
    return ("default-src 'self'; img-src 'self' data:; connect-src 'self'; "
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
                 static_dir: Path | None = None):
        self.index = index
        self.bus = bus
        self.jobs = jobs
        self.keys = keys
        self.config = config
        self.token = token
        self.auth_required = auth_required
        self.static_dir = Path(static_dir) if static_dir else None
        self.started = threading.Event()
        self._app_loaded = False
        self._app_cache: str | None = None
        self._csp = CSP
        self._routes = self._build_routes()

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
                                           "settings", "triage"]})

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
            options = ctx.json().get("options") or {}
            if self.config is not None:
                options.setdefault("results_dir", str(getattr(self.config, "results_dir", "results")))
            run = self.index.create_run(target, options)
            self.jobs.submit(run["id"], target, options)
            return _json(self.index.get_run(run["id"]), 201)

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)")
        def get_run(ctx):
            run = self.index.get_run(ctx.params["id"])
            return _json(run) if run else _problem(404, "run not found")

        @add("DELETE", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)")
        def delete_run(ctx):
            run_id = ctx.params["id"]
            self.jobs.cancel(run_id)
            return _json({"deleted": self.index.delete_run(run_id)})

        @add("POST", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/stop")
        def stop_run(ctx):
            return _json({"stopped": self.jobs.cancel(ctx.params["id"])})

        @add("POST", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/rerun")
        def rerun(ctx):
            parent = self.index.get_run(ctx.params["id"])
            if not parent:
                return _problem(404, "run not found")
            run = self.index.create_run(parent["target"], parent.get("options"),
                                        parent_run_id=parent["id"])
            self.jobs.submit(run["id"], parent["target"], parent.get("options") or {})
            return _json(self.index.get_run(run["id"]), 201)

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/summary")
        def run_summary(ctx):
            return _json(self.index.summary(ctx.params["id"]))

        @add("GET", r"/api/v1/runs/(?P<id>[A-Za-z0-9_]+)/events")
        def run_events(ctx):
            since = int(ctx.query.get("since", "0") or 0)
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

        @add("PATCH", r"/api/v1/findings/(?P<id>[A-Za-z0-9_]+)")
        def patch_finding(ctx):
            body = ctx.json()
            finding = self.index.patch_finding(
                ctx.params["id"], status=body.get("status", ""), notes=body.get("notes", ""),
                tags=body.get("tags"), severity_override=body.get("severity_override", ""))
            return _json(finding) if finding else _problem(404, "finding not found")

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
            for key, value in (ctx.json() or {}).items():
                self.index.set_setting(str(key), value)
            return _json({"items": self.index.list_settings()})

        @add("GET", r"/api/v1/providers")
        def list_providers(ctx):
            items = self.index.list_providers()
            for item in items:
                item["masked"] = mask(self.keys.get(item.get("key_name", "")))
            return _json({"items": items})

        @add("POST", r"/api/v1/providers")
        def add_provider(ctx):
            body = ctx.json()
            provider = self.index.add_provider(
                name=body.get("name", ""), kind=body.get("kind", "openai"),
                base_url=body.get("base_url", ""), model=body.get("model", ""),
                key_name=body.get("key_name", ""))
            if body.get("api_key"):
                self.keys.set(provider["key_name"] or provider["id"], body["api_key"])
            return _json(provider, 201)

        @add("DELETE", r"/api/v1/providers/(?P<id>[A-Za-z0-9_]+)")
        def delete_provider(ctx):
            return _json({"deleted": self.index.delete_provider(ctx.params["id"])})

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
        """The built dashboard, loaded once. None when it has not been built."""
        if not self._app_loaded:
            text = None
            if self.static_dir and (self.static_dir / "index.html").exists():
                text = (self.static_dir / "index.html").read_text("utf-8")
            elif (APP_DIR / "index.html").exists():
                text = (APP_DIR / "index.html").read_text("utf-8")
            self._app_cache = text
            self._csp = _app_csp(text) if text else CSP
            self._app_loaded = True
        return self._app_cache

    @staticmethod
    def _matches(supplied: str, expected: str) -> bool:
        try:
            return bool(supplied) and secrets.compare_digest(supplied, expected)
        except (TypeError, ValueError):
            return False

    # -- helpers ----------------------------------------------------------
    def _event_frames(self, run_id: str | None, last_event_id: int | None):
        sub = self.bus.subscribe()
        if run_id is not None:
            for event in self.index.list_events(run_id, since=last_event_id or 0):
                try:
                    sub.put_nowait(_Replay(event))
                except Exception:
                    break
        return self.bus.stream(sub)

    def _test_provider(self, provider: dict) -> dict:
        import time as _time

        import httpx

        key_name = provider.get("key_name") or provider.get("id", "")
        value = self.keys.get(key_name)
        base_url = (provider.get("base_url") or "").rstrip("/")
        if not value:
            return {"ok": False, "reason": "no key", "detail": "paste a key first"}
        if not base_url:
            return {"ok": False, "reason": "no base_url", "detail": "set a base url"}
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
                models = [row.get("id") for row in (payload.get("data") or [])][:50]
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


@dataclass
class _Replay:
    event: dict
    type: str = "replay"
    seq: int = 0
    ts: float = 0.0

    def sse(self) -> str:
        return "event: message\ndata: " + json.dumps(self.event, default=str) + "\n\n"


class _Context:
    def __init__(self, method, path, query, headers, body, params, server: Server):
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
        self.params = params
        self.server = server
        self.page = max(1, int(query.get("page", "1") or 1))
        self.limit = min(500, max(1, int(query.get("size", "50") or 50)))
        self.offset = (self.page - 1) * self.limit
        self.last_event_id = int(query.get("last_event_id", "0") or 0) or None

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
                 runner=None, config=None, workers: int = 2) -> Server:
    from .runner import run_scan

    base = Path(base) if base else Path.home() / ".netcast3r"
    index = Index(base / "netcast3r.db")
    bus = EventBus()
    keys = KeyStore(base)
    jobs = JobManager(index, bus, runner or run_scan, workers=workers)
    server = Server(index, bus, jobs, keys, config=config, token=secrets.token_urlsafe(24))
    jobs.recover()
    return server


def serve(host: str = "127.0.0.1", port: int = 7857, *, open_browser: bool = True,
          results_dir: str | Path = "results", base: Path | None = None,
          runner=None, config=None, auth_required: bool = True) -> Server:
    server = build_server(results_dir=results_dir, base=base, runner=runner, config=config)
    server.auth_required = auth_required
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.app = server  # type: ignore[attr-defined]
    httpd.daemon_threads = True
    url = f"http://{host}:{httpd.server_address[1]}/?token={server.token}"
    print(f"NetCast3r API on {url}")
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
        server.jobs.shutdown(wait=False)
        server.index.close()
        httpd.server_close()
    return server
