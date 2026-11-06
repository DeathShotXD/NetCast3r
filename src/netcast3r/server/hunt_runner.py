"""Standalone dashboard hunt.

A hunt is a deterministic, read-only pass over one mission target: scope,
fingerprint, a few safe surface paths, a research technique plan, a chain plan,
and explicit hypotheses. It does not need OpenCode, Hermes, or any external
agent; the dashboard can start it and watch it in Live Runs.

It creates hypotheses, never findings. A hypothesis is a precise question with
an expected observation; it still has to be tested.
"""

from __future__ import annotations

import json
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from .agent_runtime import LocalPlane
from .events import Event


class HuntRunner:
    def __init__(self, server, workers: int = 4):
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

    def _fallback_target(self, mission_id: str, skip=None) -> str:
        """Pick a reachable in-scope seed when the mission apex does not answer.

        A wildcard programme like ``*.gov.pk`` often has an apex that does not
        resolve or serve HTTP while dozens of child hosts do. Without this the
        deterministic hunt fails on its first request every time.
        """
        from ..scope import ScopeManager

        try:
            mission = self.server.index.get_mission(mission_id) or {}
        except Exception:  # noqa: BLE001
            mission = {}
        entries = [str(mission.get("target") or "").strip()]
        entries.extend(str(item) for item in (mission.get("scope") or []))
        scope = ScopeManager(in_scope=[entry for entry in entries if entry])
        skip = set(skip or ())

        def in_scope(url: str) -> bool:
            return bool(url) and url not in skip and scope.is_in_scope(url)

        try:
            endpoints = self.server.index.list_graph_nodes(
                mission_id, kind="endpoint")
        except Exception:  # noqa: BLE001
            endpoints = []
        ranked: list[tuple[int, str]] = []
        for node in endpoints:
            key = str(node.get("key") or "")
            if not key.startswith("http") or not in_scope(key):
                continue
            data = node.get("data")
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except ValueError:
                    data = {}
            status = (data or {}).get("status") if isinstance(data, dict) else None
            ranked.append((0 if status in (200, 301, 302, 401, 403) else 1, key))
        ranked.sort()
        if ranked:
            # Rotate the seed across runs so a wildcard programme is not
            # hammered through the same first host every time.
            offset = int(mission.get("run_count") or 0) % len(ranked)
            return (ranked[offset:] + ranked[:offset])[0][1]
        try:
            hosts = self.server.index.list_graph_nodes(mission_id, kind="host")
        except Exception:  # noqa: BLE001
            hosts = []
        for node in hosts:
            key = str(node.get("key") or "").strip()
            if not key:
                continue
            url = key if "://" in key else f"https://{key}"
            if in_scope(url):
                return url
        return ""

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
        try:
            probe = self._call(registry, "http_probe", {
                "target": target, "mission_id": mission_id,
                "method": "GET", "max_bytes": 65536, "timeout": 15})
        except RuntimeError as exc:
            probe = None
            tried = {target}
            last_error: RuntimeError = exc
            for _ in range(4):
                fallback = self._fallback_target(mission_id, skip=tried)
                if not fallback:
                    break
                tried.add(fallback)
                scope = self._call(registry, "scope_check",
                                   {"target": fallback, "mission_id": mission_id})
                if not scope.get("in_scope"):
                    continue
                emit(Event(type="log", agent="hunt", stage="fingerprint",
                           payload={"text": (f"{target} unreachable ({last_error}); "
                                             f"pivoting to in-scope seed {fallback}")}))
                try:
                    probe = self._call(registry, "http_probe", {
                        "target": fallback, "mission_id": mission_id,
                        "method": "GET", "max_bytes": 65536, "timeout": 15})
                except RuntimeError as inner:
                    last_error = inner
                    continue
                target = fallback
                host = (urlsplit(target).hostname or host)
                break
            if probe is None:
                raise last_error
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
        workflow_inventory: dict = {}
        try:
            workflow_inventory = self._call(registry, "web_surface_inventory", {
                "target": target, "mission_id": mission_id,
                "max_bytes": 131072, "timeout": 12})
            if workflow_inventory.get("object_candidates"):
                signals.extend(["api", "idor", "bola"])
            if workflow_inventory.get("ssrf_candidates"):
                signals.append("ssrf")
            for form in workflow_inventory.get("forms") or []:
                action = str(form.get("action") or "").lower()
                if any(token in action for token in (
                        "login", "signin", "reset", "forgot", "oauth", "register")):
                    signals.extend(["auth", "ato", "session"])
        except RuntimeError:
            workflow_inventory = {}
        # Enrich signals from the evidence graph so continuous hunts rotate
        # through auth, API, and tech-specific angles instead of two staples.
        graph_paths: list[str] = []
        try:
            for node in self.server.index.list_graph_nodes(
                    mission_id, kind="technology")[:12]:
                label = str(node.get("label") or node.get("name") or "").strip()
                if label:
                    signals.append(label.lower())
            for node in self.server.index.list_graph_nodes(
                    mission_id, kind="endpoint")[:20]:
                label = str(node.get("label") or node.get("name") or "").strip()
                if not label:
                    continue
                graph_paths.append(label)
                low = label.lower()
                if any(token in low for token in
                       ("/auth", "oauth", "oidc", "login", "sso", "callback",
                        "consent", "token", "session")):
                    signals.extend(["oauth", "auth", "session"])
                if "/api" in low or "graphql" in low:
                    signals.extend(["api", "idor", "bola"])
                if any(token in low for token in
                       ("upload", "import", "webhook", "proxy", "fetch", "pdf")):
                    signals.append("ssrf")
        except Exception:  # noqa: BLE001 - graph enrichment is best effort
            pass
        # De-dupe signals while preserving order.
        seen_sig: set[str] = set()
        signals = [s for s in signals
                   if not (s in seen_sig or seen_sig.add(s))]

        safe_paths = [
            "/robots.txt", "/.well-known/security.txt", "/sitemap.xml",
            "/login", "/signin", "/register", "/signup", "/auth", "/oauth",
            "/api", "/api/", "/admit", "/result", "/results", "/dashboard",
            "/apply", "/account", "/profile", "/admin",
            "/forgot-password", "/reset-password", "/upload",
        ]
        # Rotate a few graph endpoints into the safe surface pass.
        for path in graph_paths:
            if path.startswith("http"):
                continue
            if not path.startswith("/"):
                path = "/" + path
            if path not in safe_paths and len(safe_paths) < 18:
                safe_paths.append(path.split("?", 1)[0][:120])
        surface = []
        # surface_map holds the live auth/api/object anchors (host + path +
        # bucket) that notes and falsifiable hypotheses are built from.
        surface_map: list[dict] = []
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
            status = response.get("status")
            surface.append({"path": path, "status": status,
                            "bytes": response.get("bytes"),
                            "tls_insecure": bool(response.get("tls_insecure"))})
            emit(Event(type="fetch", agent="hunt", stage="surface", payload={
                "url": target.rstrip("/") + path,
                "status": status}))
            # Live auth/API surfaces should bias technique ranking immediately.
            kind = _classify_path(path)
            if kind == "auth":
                signals.extend(["oauth", "auth", "session", "ato"])
            elif kind in ("api", "object"):
                signals.extend(["api", "idor", "bola"])
            if _is_live(status) and kind in ("auth", "api", "object"):
                surface_map.append({"host": host, "path": path,
                                    "status": int(status or 0), "kind": kind})

        # Also fingerprint sibling in-scope hosts so one hunt does basic recon
        # across the live subdomain set, not only the seed URL.
        sibling_hits = self._probe_scope_hosts(
            registry, mission_id, target, emit, cancel)
        for hit in sibling_hits:
            for token in (hit.get("signals") or []):
                signals.append(str(token).lower())
            sib_host = str(hit.get("host") or "")
            for entry in (hit.get("paths") or []):
                p = str(entry.get("path") or "")
                k = _classify_path(p)
                if k in ("auth", "api", "object"):
                    surface_map.append({"host": sib_host, "path": p,
                                        "status": int(entry.get("status") or 0),
                                        "kind": k})

        try:
            note_body = {
                "seed": target,
                "probe_status": probe.get("status"),
                "title": title,
                "server": headers.get("server"),
                "tls_insecure": bool(probe.get("tls_insecure")),
                "workflow_inventory": {
                    "counts": workflow_inventory.get("counts") or {},
                    "parameters": (workflow_inventory.get("parameters") or [])[:40],
                    "object_candidates": (
                        workflow_inventory.get("object_candidates") or [])[:20],
                    "ssrf_candidates": (
                        workflow_inventory.get("ssrf_candidates") or [])[:20],
                },
                "surface": surface[:24],
                "siblings": sibling_hits[:12],
            }
            self.server.index.add_agent_note(
                mission_id, "hunt.recon",
                f"Recon: {host} status={probe.get('status')}",
                json.dumps(note_body, default=str)[:4000],
                run_id=run_id)
        except Exception:  # noqa: BLE001
            pass

        # De-dupe signals after surface enrichment.
        seen_sig = set()
        signals = [s for s in signals if not (s in seen_sig or seen_sig.add(s))]

        # A single-page app answers every route with one small static shell, so
        # a 200 on /admit or /login is reachability of the SPA, not a live
        # object or auth endpoint. Detect it so leads push the real applicant
        # API (referenced in the JS bundle) instead of guessing shell routes.
        spa_shell, shell_bytes = _detect_spa_shell(surface)

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
            "target": target, "signals": signals, "limit": 8})
        chains = self._call(registry, "chain_plan", {
            "target": target, "signals": signals, "limit": 4})

        # Rich map note the swarm can resume from: portal path map, auth and
        # object/api surfaces, a sibling host table, and the critical chains
        # worth running. This is the hand-off artefact, not a raw dump.
        try:
            auth_rows = [f"{r['host']}{r['path']} ({r['status']})"
                         for r in surface_map if r["kind"] == "auth"]
            object_rows = [f"{r['host']}{r['path']} ({r['status']})"
                           for r in surface_map if r["kind"] in ("object", "api")]
            sibling_table = [{
                "host": sib.get("host"), "status": sib.get("status"),
                "server": sib.get("server"),
                "tls_insecure": bool(sib.get("tls_insecure")),
                "paths": [f"{p['path']}:{p['status']}"
                          for p in (sib.get("paths") or [])],
            } for sib in sibling_hits]
            suggested_chains = [{
                "id": c.get("id"), "title": c.get("title"),
                "impact": c.get("impact"),
                "why": (c.get("why") or [])[:4],
                "first_steps": (c.get("steps") or [])[:3],
            } for c in (chains.get("items") or [])[:4]]
            if spa_shell:
                critical_chains_to_run = [
                    (f"SPA shell: every route returns a {shell_bytes}-byte shell "
                     "- parse the JS bundle for the real applicant API base"),
                    "BOLA/IDOR on the real /api object endpoint (swap the id)",
                    "OAuth redirect_uri / state abuse -> code or token theft",
                ]
            else:
                critical_chains_to_run = [
                    "BOLA on admit/result object (swap the applicant/roll id)",
                    "Dual-account IDOR on an API object by id (two sessions)",
                    "OAuth redirect_uri / state abuse -> code or token theft",
                ]
            map_body = {
                "seed_host": host,
                "path_map": [f"{r['host']}{r['path']} [{r['kind']}] {r['status']}"
                             for r in surface_map],
                "auth_surfaces": auth_rows,
                "object_api_surfaces": object_rows,
                "siblings": sibling_table,
                "suggested_chains": suggested_chains,
                "spa_shell": bool(spa_shell),
                "shell_bytes": int(shell_bytes),
                "critical_chains_to_run": critical_chains_to_run,
            }
            self.server.index.add_agent_note(
                mission_id, "hunt.map",
                (f"Surface map: {host} "
                 f"({len(surface_map)} auth/api/object anchors, "
                 f"{len(sibling_hits)} siblings)"),
                json.dumps(map_body, default=str)[:8000],
                run_id=run_id)
        except Exception:  # noqa: BLE001 - the map note is best effort
            pass

        # Rotate which ranked techniques become leads across continuous runs.
        run_count = 0
        try:
            mission = self.server.index.get_mission(mission_id) or {}
            run_count = len(mission.get("runs") or [])
        except Exception:  # noqa: BLE001
            run_count = 0
        ranked = list(techniques.get("items") or [])
        if ranked:
            offset = run_count % max(1, len(ranked))
            ranked = ranked[offset:] + ranked[:offset]

        open_titles: set[str] = set()
        open_techs: set[str] = set()
        try:
            open_items, _ = self.server.index.list_hypotheses(
                mission_id=mission_id, status="open", limit=200)
            for item in open_items:
                open_titles.add(str(item.get("title") or "").casefold())
                tech = str(item.get("technique") or "").casefold()
                if tech:
                    open_techs.add(tech)
        except Exception:  # noqa: BLE001
            pass

        hypotheses = []

        def _open_lead(title: str, tech_id: str, rationale: str, expected: str,
                       lead_target: str = "") -> None:
            if cancel.is_set() or len(hypotheses) >= 5:
                return
            if title.casefold() in open_titles:
                return
            if tech_id and tech_id.casefold() in open_techs:
                return
            try:
                hypothesis = self._call(registry, "hypothesis_create", {
                    "title": title,
                    "target": lead_target or target, "mission_id": mission_id,
                    "technique": tech_id,
                    "rationale": rationale,
                    "expected": expected,
                })
            except RuntimeError:
                return
            if hypothesis.get("id") and title.casefold() not in open_titles:
                hypotheses.append(hypothesis)
                open_titles.add(title.casefold())
                if tech_id:
                    open_techs.add(tech_id.casefold())
                emit(Event(type="log", agent="hunt", stage="hypotheses", payload={
                    "text": f"hypothesis: {hypothesis.get('title')}"}))

        # Portal-shaped surfaces get falsifiable critical-chain leads first.
        # Each lead names a concrete (host, path) anchor plus the object to
        # swap and the proof, so the swarm can act without re-deriving scope.
        auth_surfaces = [r for r in surface_map if r["kind"] == "auth"]
        api_surfaces = [r for r in surface_map if r["kind"] == "api"]
        object_surfaces = [r for r in surface_map if r["kind"] == "object"]

        def _anchor(rows, *tokens):
            for row in rows:
                low = str(row.get("path") or "").lower()
                if any(token in low for token in tokens):
                    return row
            return None

        # 1) BOLA on the admit/result object (the classic exam-portal chain).
        obj = _anchor(object_surfaces, "admit", "result")
        if obj:
            loc = f"{obj['host']}{obj['path']}"
            _open_lead(
                (f"BOLA on {loc}: swapping the applicant/roll id returns "
                 f"another candidate's record"),
                "bola",
                (f"{obj['path']} answered {obj['status']} on {obj['host']}; "
                 f"object id looks guessable/sequential"),
                (f"two sessions where account A reads account B's record via "
                 f"{obj['path']} with only the id changed"),
                f"https://{obj['host']}/")

        # 2) Dual-account IDOR on the API (or profile/account) object by id.
        api = (api_surfaces[0] if api_surfaces else
               _anchor(object_surfaces, "profile", "account", "dashboard"))
        if api:
            loc = f"{api['host']}{api['path']}"
            _open_lead(
                (f"Dual-account IDOR on {loc}: account A reads account B's "
                 f"object by id"),
                "idor",
                (f"{api['path']} answered {api['status']} on {api['host']}; "
                 f"enumerate object id across two authenticated accounts"),
                (f"raw req/res where account A retrieves account B's record via "
                 f"{api['path']} without authorization"),
                f"https://{api['host']}/")

        # 3) OAuth redirect_uri abuse when an oauth/sso surface answers;
        #    otherwise a login/register surface gets a session/reset ATO lead.
        oauth = _anchor(auth_surfaces, "oauth", "callback", "sso", "consent",
                        "oidc")
        login = _anchor(auth_surfaces, "login", "signin", "register", "signup")
        if oauth:
            loc = f"{oauth['host']}{oauth['path']}"
            _open_lead(
                (f"OAuth redirect_uri abuse on {loc}: loose redirect/state "
                 f"allows code or token theft"),
                "oauth",
                (f"{oauth['path']} answered {oauth['status']} on "
                 f"{oauth['host']}; test redirect_uri allowlist and state"),
                (f"a crafted authorize request on {oauth['path']} that leaks "
                 f"the code/token to an attacker-controlled redirect"),
                f"https://{oauth['host']}/")
        elif login:
            loc = f"{login['host']}{login['path']}"
            _open_lead(
                (f"Session/reset ATO on {loc}: password-reset host header or "
                 f"session fixation enables account takeover"),
                "auth-ato",
                (f"{login['path']} answered {login['status']} on "
                 f"{login['host']}; test reset-token host, session fixation"),
                (f"raw req/res taking over an account via {login['path']} "
                 f"without the owner's proof"),
                f"https://{login['host']}/")

        # 4) Password-reset token abuse: a distinct ATO angle from session
        #    fixation, seeded whenever a reset/forgot or login surface answers.
        reset = _anchor(auth_surfaces, "reset", "forgot", "recover",
                        "password") or login
        if reset:
            loc = f"{reset['host']}{reset['path']}"
            _open_lead(
                (f"Password-reset token abuse on {loc}: Host-header or "
                 f"predictable token leaks the reset link to an attacker"),
                "auth-reset-token",
                (f"{reset['path']} answered {reset['status']} on "
                 f"{reset['host']}; test Host/X-Forwarded-Host in the reset "
                 f"mail link and token entropy/reuse"),
                (f"raw req/res where a reset for account B is driven to an "
                 f"attacker-controlled link or a guessed token, taking over B"),
                f"https://{reset['host']}/")

        # 5) SQLi authentication bypass on a login surface (raw differential).
        if login:
            loc = f"{login['host']}{login['path']}"
            _open_lead(
                (f"SQLi auth bypass on {loc}: an injection in the login "
                 f"parameter bypasses authentication or errors the database"),
                "auth-sqli-login-bypass",
                (f"{login['path']} answered {login['status']} on "
                 f"{login['host']}; send a baseline vs injection differential "
                 f"on the username/password field"),
                (f"raw req/res where an injection payload on {login['path']} "
                 f"bypasses auth or returns a SQL error the baseline does not"),
                f"https://{login['host']}/")

        # 6) Upload policy abuse when an upload surface answers.
        upload = _anchor(object_surfaces + api_surfaces,
                         *_UPLOAD_TOKENS)
        if upload:
            loc = f"{upload['host']}{upload['path']}"
            _open_lead(
                (f"Unrestricted upload on {loc}: extension/MIME handling lets "
                 f"an inert canary be stored and served dangerously"),
                "upload-policy",
                (f"{upload['path']} answered {upload['status']} on "
                 f"{upload['host']}; probe extension and content-type handling "
                 f"with inert canaries"),
                (f"raw upload-policy response showing a canary stored and "
                 f"served with an executable or dangerous content-type"),
                f"https://{upload['host']}/")

        # 7) SPA shell: path-guessing is settled, so force the real applicant
        #    API out of the JS bundle before any further object probing.
        if spa_shell:
            _open_lead(
                (f"Applicant API discovery on {host}: the SPA shell hides the "
                 f"real object endpoints behind a JS bundle"),
                "spa-api-extract",
                (f"{host} returns an identical {shell_bytes}-byte shell for "
                 f"every route and /api/* 404s; the real applicant API base is "
                 f"referenced inside the JS bundle, not at guessed paths"),
                (f"raw req/res against a real /api object endpoint parsed from "
                 f"the bundle that returns applicant data and enables a "
                 f"BOLA/IDOR test"),
                f"https://{host}/")

        for item in ranked:
            if cancel.is_set() or len(hypotheses) >= 5:
                break
            title = f"Test {item['title']} on {host}"
            tech_id = str(item.get("id") or "")
            _open_lead(
                title, tech_id,
                ", ".join(item.get("why") or []) or item.get("class", ""),
                item.get("proof") or "a reproducible effect")

        try:
            critical_techs = {"bola", "idor", "oauth", "auth-ato", "ssrf", "ssti",
                              "sqli", "rce", "auth", "ato"}
            lead_rows = []
            for hyp in hypotheses:
                tech = str(hyp.get("technique") or "").lower()
                lead_rows.append({
                    "hypothesis_id": hyp.get("id"),
                    "title": hyp.get("title"),
                    "technique": tech,
                    "target": hyp.get("target"),
                    "priority": ("critical" if tech in critical_techs
                                 or any(token in tech for token in critical_techs)
                                 else "high"),
                })
            lead_rows.sort(
                key=lambda row: (0 if row["priority"] == "critical" else 1,
                                 str(row.get("title") or "")))
            if lead_rows:
                top = lead_rows[:3]
                self.server.index.add_agent_note(
                    mission_id, "hunt.critical",
                    (f"Critical leads: {host} "
                     f"({len(top)} prioritized for director)"),
                    json.dumps({
                        "seed_host": host,
                        "top_leads": top,
                        "all_leads": lead_rows[:8],
                        "director_hint": (
                            "Run portal BOLA/IDOR/OAuth chains before generic "
                            "technique rotation on this mission."
                        ),
                    }, default=str)[:4000],
                    run_id=run_id)
        except Exception:  # noqa: BLE001 - hand-off note is best effort
            pass

        summary = {
            "mode": "hunt", "target": target, "title": title,
            "pages": 1 + len(surface), "signals": len(signals),
            "endpoints": len(variants), "leads": len(hypotheses),
            "parameters": len(workflow_inventory.get("parameters") or []),
            "techniques": len(techniques.get("items") or []),
            "chains": len(chains.get("items") or []),
            "findings": 0,
        }
        emit(Event(type="log", agent="hunt", stage="hypotheses", payload={
            "text": (f"hunt complete: {len(hypotheses)} hypotheses, "
                     f"{len(techniques.get('items') or [])} techniques, "
                     f"0 findings")}))
        return summary


    def _probe_scope_hosts(self, registry, mission_id: str, seed: str, emit,
                           cancel) -> list[dict]:
        """Hit other in-scope hostnames so recon is not seed-blind.

        Each returned hit carries a small path map (path -> status) for the
        auth and object surfaces that actually answer on the sibling, so the
        caller can fold live portals into notes and falsifiable hypotheses.
        """
        mission = self.server.index.get_mission(mission_id) or {}
        seed_host = (urlsplit(seed if "://" in seed else "https://" + seed)
                     .hostname or "").lower()
        hosts: list[str] = []
        for entry in (mission.get("scope") or []):
            text = str(entry or "").strip().lower()
            if not text or text == seed_host:
                continue
            if "://" in text:
                host = urlsplit(text).hostname or ""
            else:
                host = text.split("/")[0]
            if host and host != seed_host and host not in hosts:
                hosts.append(host)
        # Prefer applicant portals over apex marketing sites.
        portal_prefixes = ("apply.", "online.", "cp.", "portal.", "www.")
        preferred = [h for h in hosts if h.startswith(portal_prefixes)]
        ordered = preferred + [h for h in hosts if h not in preferred]
        hits: list[dict] = []
        for host in ordered[:6]:
            if cancel.is_set():
                break
            url = f"https://{host}/"
            try:
                probe = self._call(registry, "http_probe", {
                    "target": url, "mission_id": mission_id,
                    "method": "GET", "max_bytes": 32768, "timeout": 12})
            except RuntimeError:
                continue
            status = int(probe.get("status") or 0)
            if status <= 0:
                continue
            sigs = []
            if host.startswith(("apply.", "online.", "cp.", "portal.")):
                sigs.extend(["auth", "ato", "idor", "bola"])
            paths: list[dict] = []
            # Map the applicant-portal auth/object surface on the richest
            # siblings, not just the apex, so cross-host IDOR/BOLA has anchors.
            if host.startswith(("apply.", "online.", "cp.", "portal.")) or "login" in host:
                for path in ("/login", "/register", "/admit", "/result",
                             "/results", "/api", "/account", "/profile",
                             "/dashboard"):
                    if cancel.is_set():
                        break
                    try:
                        response = self._call(registry, "http_request", {
                            "target": f"https://{host}{path}",
                            "mission_id": mission_id, "method": "GET",
                            "max_bytes": 16384, "timeout": 10,
                            "follow_redirects": False})
                    except RuntimeError:
                        continue
                    pstatus = int(response.get("status") or 0)
                    emit(Event(type="fetch", agent="hunt", stage="sibling",
                               payload={"url": f"https://{host}{path}",
                                        "status": pstatus}))
                    if _is_live(pstatus):
                        paths.append({"path": path, "status": pstatus})
                        kind = _classify_path(path)
                        if kind == "auth":
                            sigs.extend(["oauth", "auth", "session", "ato"])
                        elif kind in ("object", "api"):
                            sigs.extend(["api", "idor", "bola"])
            hit = {
                "host": host,
                "url": probe.get("url") or url,
                "status": status,
                "tls_insecure": bool(probe.get("tls_insecure")),
                "server": (probe.get("headers") or {}).get("server"),
                "signals": sigs,
                "paths": paths,
            }
            hits.append(hit)
            emit(Event(type="fetch", agent="hunt", stage="sibling", payload={
                "url": hit["url"], "status": status,
                "text": f"sibling host {host} -> {status}"}))
        return hits


_AUTH_TOKENS = ("login", "signin", "sign-in", "register", "signup", "sign-up",
                "auth", "oauth", "oidc", "sso", "callback", "consent", "token",
                "session", "reset", "forgot", "recover", "password")
_OBJECT_TOKENS = ("admit", "result", "profile", "account", "dashboard",
                  "apply", "candidate", "application", "card", "hall-ticket")
_API_TOKENS = ("/api", "graphql", "/v1", "/v2", "/rest")
_UPLOAD_TOKENS = ("upload", "import", "attachment", "document", "/file")
_RESET_TOKENS = ("reset", "forgot", "recover", "password")


def _detect_spa_shell(surface: list) -> tuple[bool, int]:
    """Spot a single-page-app catch-all shell in the surface pass.

    Returns ``(True, shell_bytes)`` when at least four distinct routes answer
    200 with the same small body size, which means path-guessing is settled and
    the real object/auth API lives behind the JS bundle, not these routes.
    """
    sizes = [int(row.get("bytes") or 0) for row in (surface or [])
             if row.get("status") == 200 and isinstance(row.get("bytes"), int)]
    sizes = [size for size in sizes if size > 0]
    if len(sizes) < 4:
        return False, 0
    size, freq = Counter(sizes).most_common(1)[0]
    if freq >= 4 and size <= 8192:
        return True, int(size)
    return False, 0


def _is_upload_path(path: str) -> bool:
    low = str(path or "").lower()
    return any(token in low for token in _UPLOAD_TOKENS)


def _is_reset_path(path: str) -> bool:
    low = str(path or "").lower()
    return any(token in low for token in _RESET_TOKENS)


def _is_live(status) -> bool:
    """A surface is worth noting when it exists, even behind auth."""
    try:
        code = int(status or 0)
    except (TypeError, ValueError):
        return False
    return code in (200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403)


def _classify_path(path: str) -> str:
    """Bucket a path into auth / api / object / other for notes + hypotheses."""
    low = str(path or "").lower()
    if any(token in low for token in _API_TOKENS):
        return "api"
    if any(token in low for token in _AUTH_TOKENS):
        return "auth"
    if any(token in low for token in _OBJECT_TOKENS):
        return "object"
    return "other"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
