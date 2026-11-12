"""The NetCast3r MCP server.

Speaks MCP over stdio, exposes the typed tool registry, and publishes a
heartbeat the UI can display. All workspace state lives behind the control
plane; this process is a policy-enforcing adapter, not a second source of
truth.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import signal
import sys
import threading
import time
from pathlib import Path

from .. import __version__, control
from . import protocol
from .protocol import Dispatcher, RpcError, error_response, write_message
from .tools import (
    DEFAULT_POLICY,
    POLICIES,
    ToolContext,
    ToolError,
    ToolRegistry,
    catalog,
    mcp_tools,
)

SERVER_NAME = "netcast3r"
SERVER_TITLE = "NetCast3r"
# MCP logging levels, in syslog order. A client moves the bar with
# logging/setLevel; the server emits notifications/message at or above it.
LOG_LEVELS = ("debug", "info", "notice", "warning", "error",
              "critical", "alert", "emergency")
LOG_RANK = {name: index for index, name in enumerate(LOG_LEVELS)}
DEFAULT_LOG_LEVEL = "info"
INSTRUCTIONS = """NetCast3r is a proof-first bug bounty workspace. You are driving its real \
control plane through MCP.

Rules that are enforced, not suggestions:
1. Active tools need a mission_id or an explicit scope list. A target alone is not an \
authorization. Out-of-scope rules win.
2. Read findings, runs, and reports before drawing conclusions. Never invent a finding, \
a validation result, a provider status, or an approval.
3. High-risk tools (deletes, approval decisions) require an approved approval in \
supervised mode, or confirm=true in full mode. Approvals are bound to the tool name and \
argument hash and can be spent once.
4. Prefer a mission: create it, check scope, start a run, read events and findings, then \
triage with evidence. The database, not the chat, is the record.
5. Secret values are masked at the index boundary. Do not try to reconstruct or guess \
them.
6. Browse with resources instead of guessing ids: read netcast3r://missions, then a \
template like netcast3r://missions/{mission_id}, netcast3r://runs/{run_id}/events, or \
netcast3r://findings/{finding_id}. Use completion/complete to autocomplete those ids.
7. Two tools call back to you, the client. sampling_complete runs a completion on your \
own model (you may decline), and client_roots lists the filesystem roots you expose. \
Both need the matching client capability advertised at initialize.
"""

RESOURCES = (
    ("netcast3r://status", "Workspace status",
     "Control-plane version, policy, counters, and active runs.", "application/json"),
    ("netcast3r://missions", "Missions",
     "Missions with run, finding, and approval counts.", "application/json"),
    ("netcast3r://runs", "Runs", "Recent scans and their counters.", "application/json"),
    ("netcast3r://findings", "Findings", "Recent findings with masked values.", "application/json"),
    ("netcast3r://submissions", "Submissions",
     "Filed reports, platform outcomes, and recorded payouts.", "application/json"),
    ("netcast3r://approvals", "Approvals", "Pending and decided approval requests.",
     "application/json"),
    ("netcast3r://tool-calls", "Tool calls", "The MCP audit trail.", "application/json"),
    ("netcast3r://providers", "Providers",
     "Configured model providers, masked keys, and health.", "application/json"),
    ("netcast3r://director", "Director",
     "The autonomous director: engagement, in-flight runs, eligibility.",
     "application/json"),
    ("netcast3r://brain", "Brain loop",
     "The steward loop: running state, model, turns, last focus.", "application/json"),
    ("netcast3r://checklists", "Checklists",
     "The coverage catalog every mission is measured against.", "application/json"),
    ("netcast3r://agents", "Agent roster",
     "Pipeline agents, mesh roles, the steward, and the lane/model each uses.",
     "application/json"),
    ("netcast3r://helix/scripts", "Toolsmith scripts",
     "The durable scripts Helix wrote for itself, with their last run.",
     "application/json"),
    ("netcast3r://mcp", "MCP server",
     "The MCP server's live state: policy, client, advertised capabilities.",
     "application/json"),
    ("netcast3r://policy", "MCP policy",
     "The active policy and the full tool catalogue.", "application/json"),
)

# Parameterised resources: a client can browse one entity at a time instead of
# pulling a 50-row list and filtering it in the model.
RESOURCE_TEMPLATES = (
    {"uriTemplate": "netcast3r://missions/{mission_id}", "name": "Mission",
     "description": "One mission with its counts and metadata.",
     "mimeType": "application/json"},
    {"uriTemplate": "netcast3r://missions/{mission_id}/coverage", "name": "Mission coverage",
     "description": "The coverage ledger and next checks for one mission.",
     "mimeType": "application/json"},
    {"uriTemplate": "netcast3r://runs/{run_id}", "name": "Run",
     "description": "One run with its options and counters.",
     "mimeType": "application/json"},
    {"uriTemplate": "netcast3r://runs/{run_id}/events", "name": "Run events",
     "description": "The event log for one run.", "mimeType": "application/json"},
    {"uriTemplate": "netcast3r://findings/{finding_id}", "name": "Finding",
     "description": "One finding with its evidence and publish gate.",
     "mimeType": "application/json"},
    {"uriTemplate": "netcast3r://findings/{finding_id}/artifacts", "name": "Finding artifacts",
     "description": "The evidence artifacts attached to one finding.",
     "mimeType": "application/json"},
    {"uriTemplate": "netcast3r://helix/scripts/{script_id}", "name": "Toolsmith script",
     "description": "One script Helix wrote for itself, with its source and last run.",
     "mimeType": "application/json"},
)

# uri -> (control-plane path, query) for the fixed resources.
_STATIC_RESOURCES: dict[str, tuple[str, dict]] = {
    "netcast3r://status": ("/api/v1/meta", {}),
    "netcast3r://missions": ("/api/v1/missions", {"size": 50}),
    "netcast3r://runs": ("/api/v1/runs", {"size": 50}),
    "netcast3r://findings": ("/api/v1/findings", {"size": 50}),
    "netcast3r://submissions": ("/api/v1/submissions", {"size": 50}),
    "netcast3r://approvals": ("/api/v1/approvals", {"size": 50}),
    "netcast3r://tool-calls": ("/api/v1/tool-calls", {"size": 50}),
    "netcast3r://providers": ("/api/v1/providers", {}),
    "netcast3r://director": ("/api/v1/director", {}),
    "netcast3r://brain": ("/api/v1/brain/loop", {}),
    "netcast3r://checklists": ("/api/v1/checklists", {}),
    "netcast3r://agents": ("/api/v1/agents", {}),
    "netcast3r://helix/scripts": ("/api/v1/helix/scripts", {"limit": 50}),
    "netcast3r://mcp": ("/api/v1/mcp", {}),
}

# uriTemplate -> regex + resolver for the parameterised resources.
_TEMPLATE_RESOURCES = (
    (re.compile(r"^netcast3r://missions/([^/]+)/coverage$"),
     lambda m: (f"/api/v1/missions/{m.group(1)}/coverage", {})),
    (re.compile(r"^netcast3r://missions/([^/]+)$"),
     lambda m: (f"/api/v1/missions/{m.group(1)}", {})),
    (re.compile(r"^netcast3r://runs/([^/]+)/events$"),
     lambda m: (f"/api/v1/runs/{m.group(1)}/events", {})),
    (re.compile(r"^netcast3r://runs/([^/]+)$"),
     lambda m: (f"/api/v1/runs/{m.group(1)}", {})),
    (re.compile(r"^netcast3r://findings/([^/]+)/artifacts$"),
     lambda m: (f"/api/v1/findings/{m.group(1)}/artifacts", {})),
    (re.compile(r"^netcast3r://findings/([^/]+)$"),
     lambda m: (f"/api/v1/findings/{m.group(1)}", {})),
    (re.compile(r"^netcast3r://helix/scripts/([^/]+)$"),
     lambda m: (f"/api/v1/helix/scripts/{m.group(1)}", {})),
)

# argument name -> (list path, page param, label fields) for completion/complete.
_COMPLETIONS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "mission_id": ("/api/v1/missions", "size", ("title", "target")),
    "run_id": ("/api/v1/runs", "size", ("title", "target")),
    "finding_id": ("/api/v1/findings", "size", ("title", "severity")),
    "script_id": ("/api/v1/helix/scripts", "limit", ("name", "purpose")),
    "session_id": ("/api/v1/brain/sessions", "limit", ("title", "agent")),
}

PROMPTS = (
    {
        "name": "recon-mission",
        "title": "Recon a mission",
        "description": "Turn a mission into a scoped, evidence-backed recon run.",
        "arguments": [{"name": "mission_id", "description": "Mission id", "required": True}],
    },
    {
        "name": "triage-findings",
        "title": "Triage findings",
        "description": "Read findings and propose triage grounded in run evidence.",
        "arguments": [{"name": "mission_id", "description": "Optional mission id",
                       "required": False}],
    },
    {
        "name": "write-report",
        "title": "Draft a run report",
        "description": "Draft a submission-ready report from a real run and its findings.",
        "arguments": [{"name": "run_id", "description": "Run id", "required": True}],
    },
    {
        "name": "review-approval",
        "title": "Review an approval",
        "description": "Summarize a pending high-risk action for a human decision.",
        "arguments": [{"name": "approval_id", "description": "Approval id", "required": True}],
    },
)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class MCPServer:
    def __init__(self, plane, policy: str = DEFAULT_POLICY, base: Path | None = None,
                 actor: str = "mcp", transport: str = "stdio"):
        if policy not in POLICIES:
            raise ValueError(f"unknown MCP policy: {policy}")
        self.plane = plane
        self.policy = policy
        self.base = base
        self.actor = actor
        self.transport = transport
        self.started_at = _now()
        self.last_call_at = ""
        self.calls = 0
        self.initialized = False
        self.protocol_version = protocol.LATEST_PROTOCOL
        self.client_info: dict = {}
        self._notifier = None  # set by run(), so a call can emit progress
        self.log_level = DEFAULT_LOG_LEVEL
        # Resource subscriptions: uri -> last serialised content. A watcher
        # thread polls them and emits notifications/resources/updated on change.
        self._subs: dict[str, str] = {}
        self._sub_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._watcher: threading.Thread | None = None
        self._stop = threading.Event()
        # Client transport, filled in by run(). Enables server->client requests
        # (sampling, roots); anything else received while waiting is queued so
        # the main loop handles it, never a reentrant handler.
        self._stdin = None
        self._stdout = None
        self._inbox: list[dict] = []
        self._req_seq = 0
        self.client_capabilities: dict = {}
        self.registry = ToolRegistry(ToolContext(
            plane=plane, policy=policy, base=base, actor=actor))
        self.registry.ctx.client = self
        self.state_path = control.mcp_state_path(base)
        self.dispatcher = self._build_dispatcher()

    # -- state -------------------------------------------------------------
    def _write_state(self) -> None:
        try:
            control.write_mcp_state(self.base, {
                "schema": 1,
                "pid": os.getpid(),
                "transport": self.transport,
                "policy": self.policy,
                "backend": getattr(self.plane, "kind", "unknown"),
                "plane_url": getattr(self.plane, "url", ""),
                "started_at": self.started_at,
                "last_call_at": self.last_call_at,
                "calls": self.calls,
                "tools": self.registry.ctx.tool_count,
                "protocol_version": self.protocol_version,
                "client": self.client_info,
                "client_capabilities": sorted(self.client_capabilities),
                "initialized": self.initialized,
                "version": __version__,
                "base": str(self.base or ""),
            })
        except Exception:  # noqa: BLE001 - a heartbeat must not kill the protocol
            pass

    def close(self) -> None:
        self._stop.set()
        control.remove_mcp_state(self.base, pid=os.getpid())

    # -- protocol ----------------------------------------------------------
    def _build_dispatcher(self) -> Dispatcher:
        dispatcher = Dispatcher()

        @dispatcher.method("initialize")
        def initialize(params):
            requested = str(params.get("protocolVersion") or protocol.LATEST_PROTOCOL)
            self.protocol_version = (requested if requested in protocol.PROTOCOL_VERSIONS
                                     else protocol.LATEST_PROTOCOL)
            info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
            name = str(info.get("name") or "mcp")[:80]
            version = str(info.get("version") or "")[:40]
            self.client_info = {"name": name, "version": version}
            caps = params.get("capabilities")
            self.client_capabilities = caps if isinstance(caps, dict) else {}
            # A local stdio client is the operator on this machine, so it may
            # manage mission lifecycles. A remote HTTP peer is an agent unless
            # it overrides the actor explicitly.
            override = str(os.environ.get("NETCAST3R_MCP_ACTOR") or "").strip()
            if override:
                self.actor = override
            elif self.transport == "stdio":
                self.actor = "operator:stdio"
            else:
                self.actor = f"mcp:{name}/{version}" if version else f"mcp:{name}"
            self.registry.ctx.actor = self.actor
            self.initialized = True
            self._write_state()
            return {
                "protocolVersion": self.protocol_version,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": True, "listChanged": False},
                    "prompts": {"listChanged": False},
                    "completions": {},
                },
                "serverInfo": {"name": SERVER_NAME, "title": SERVER_TITLE,
                               "version": __version__},
                "instructions": INSTRUCTIONS,
            }

        @dispatcher.method("notifications/initialized")
        def initialized(params):
            self.initialized = True
            self._write_state()
            return {}

        @dispatcher.method("ping")
        def ping(params):
            return {}

        @dispatcher.method("logging/setLevel")
        def set_level(params):
            level = str(params.get("level") or "").strip().lower()
            if level not in LOG_LEVELS:
                raise RpcError(protocol.INVALID_PARAMS,
                               f"unknown log level: {level}")
            self.log_level = level
            self._write_state()
            return {}

        @dispatcher.method("tools/list")
        def tools_list(params):
            return {"tools": mcp_tools()}

        @dispatcher.method("tools/call")
        def tools_call(params):
            name = params.get("name")
            if not isinstance(name, str) or not name:
                raise RpcError(protocol.INVALID_PARAMS, "tool name required")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise RpcError(protocol.INVALID_PARAMS, "arguments must be an object")
            # A long tool can report progress if the client sent a token.
            meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
            token = meta.get("progressToken")
            self._notify_progress(token, 0, 1, f"running {name}")
            try:
                payload, is_error = self.registry.call(name, arguments, self.actor)
            except ToolError as exc:
                if exc.code == "unknown_tool":
                    raise RpcError(protocol.INVALID_PARAMS, exc.message)
                payload, is_error = exc.payload(), True
            self._notify_progress(
                token, 1, 1, f"{name} {'failed' if is_error else 'done'}")
            if is_error:
                code = ""
                if isinstance(payload, dict):
                    code = str((payload.get("error") or {}).get("code") or "")
                self._log("warning", "netcast3r.tools",
                          {"tool": name, "error": code or "error"})
            self.calls += 1
            self.last_call_at = _now()
            self._write_state()
            text = json.dumps(payload, indent=2, default=str)
            return {
                "content": [{"type": "text", "text": text}],
                "structuredContent": payload,
                "isError": is_error,
            }

        @dispatcher.method("resources/list")
        def resources_list(params):
            return {"resources": [
                {"uri": uri, "name": name, "description": description, "mimeType": mime}
                for uri, name, description, mime in RESOURCES
            ]}

        @dispatcher.method("resources/templates/list")
        def resource_templates(params):
            return {"resourceTemplates": [dict(item) for item in RESOURCE_TEMPLATES]}

        @dispatcher.method("resources/subscribe")
        def resources_subscribe(params):
            uri = str(params.get("uri") or "")
            if not uri:
                raise RpcError(protocol.INVALID_PARAMS, "uri required")
            self._read_resource(uri)  # validate the uri resolves before subscribing
            with self._sub_lock:
                self._subs[uri] = self._resource_state(uri)
            self._ensure_watcher()
            return {}

        @dispatcher.method("resources/unsubscribe")
        def resources_unsubscribe(params):
            uri = str(params.get("uri") or "")
            with self._sub_lock:
                self._subs.pop(uri, None)
            return {}

        @dispatcher.method("completion/complete")
        def completion_complete(params):
            ref = params.get("ref")
            argument = params.get("argument")
            if not isinstance(ref, dict) or not isinstance(argument, dict):
                raise RpcError(protocol.INVALID_PARAMS,
                               "ref and argument are required")
            return {"completion": self._complete(argument)}

        @dispatcher.method("resources/read")
        def resources_read(params):
            uri = str(params.get("uri") or "")
            payload = self._read_resource(uri)
            return {"contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(payload, indent=2, default=str),
            }]}

        @dispatcher.method("prompts/list")
        def prompts_list(params):
            return {"prompts": [
                {"name": item["name"], "title": item["title"],
                 "description": item["description"], "arguments": item["arguments"]}
                for item in PROMPTS
            ]}

        @dispatcher.method("prompts/get")
        def prompts_get(params):
            name = str(params.get("name") or "")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise RpcError(protocol.INVALID_PARAMS, "arguments must be an object")
            prompt = next((item for item in PROMPTS if item["name"] == name), None)
            if prompt is None:
                raise RpcError(protocol.INVALID_PARAMS, f"unknown prompt: {name}")
            return self._prompt(name, arguments)

        return dispatcher

    # -- notifications -----------------------------------------------------
    def set_notifier(self, notifier) -> None:
        """Install the transport's notification writer (stdout for stdio)."""
        self._notifier = notifier

    def _notify(self, method: str, params: dict) -> None:
        if self._notifier is None:
            return
        try:
            # One writer at a time: the watcher thread and a tool call may both
            # emit, and interleaved framing would corrupt the stream.
            with self._write_lock:
                self._notifier({"jsonrpc": "2.0", "method": method, "params": params})
        except Exception:  # noqa: BLE001 - a ping must never break a call
            pass

    def _notify_progress(self, token, progress: int, total: int, message: str) -> None:
        if token is None:
            return
        self._notify("notifications/progress", {
            "progressToken": token, "progress": progress,
            "total": total, "message": message})

    def _log(self, level: str, logger: str, data) -> None:
        """Emit notifications/message when the level clears the client's bar."""
        if LOG_RANK.get(level, len(LOG_LEVELS)) < LOG_RANK.get(self.log_level, 1):
            return
        self._notify("notifications/message",
                     {"level": level, "logger": logger, "data": data})

    # -- server -> client requests (sampling, roots) -----------------------
    def _supports(self, capability: str) -> bool:
        caps = self.client_capabilities
        return isinstance(caps, dict) and capability in caps

    def request(self, method: str, params: dict, timeout: float = 30.0) -> dict:
        """Send a request to the client and wait for its matching response.

        The client's answer arrives on the same stdin, so anything else that
        arrives while waiting is queued for the main loop instead of being
        handled reentrantly. The timeout is checked between reads: a client
        that never answers and never writes blocks until the stream closes.
        """
        if self._stdin is None or self._stdout is None:
            raise ToolError("no_client", "no client transport is attached")
        self._req_seq += 1
        request_id = f"srv-{self._req_seq}"
        with self._write_lock:
            write_message(self._stdout, {
                "jsonrpc": "2.0", "id": request_id,
                "method": method, "params": params})
        deadline = time.monotonic() + max(1.0, float(timeout))
        while True:
            try:
                incoming = protocol.read_message(self._stdin)
            except protocol.ParseError as exc:
                raise ToolError("client_error", f"malformed client JSON: {exc}")
            if incoming is None:
                raise ToolError("client_closed", "the client closed the stream")
            if (incoming.get("id") == request_id
                    and ("result" in incoming or "error" in incoming)):
                if incoming.get("error"):
                    error = incoming.get("error") or {}
                    raise ToolError("client_error",
                                    str(error.get("message") or "client error"))
                result = incoming.get("result")
                return result if isinstance(result, dict) else {"result": result}
            self._inbox.append(incoming)
            if time.monotonic() >= deadline:
                raise ToolError("client_timeout",
                                "the client did not answer in time")

    def sample(self, params: dict, timeout: float = 45.0) -> dict:
        """Ask the client to run a completion on its own model (MCP sampling)."""
        if not self._supports("sampling"):
            raise ToolError(
                "unsupported",
                "the client did not advertise the sampling capability")
        return self.request("sampling/createMessage", params, timeout=timeout)

    def client_roots(self, timeout: float = 20.0) -> dict:
        """Ask the client for its filesystem roots (MCP roots)."""
        if not self._supports("roots"):
            raise ToolError(
                "unsupported",
                "the client did not advertise the roots capability")
        return self.request("roots/list", {}, timeout=timeout)

    # -- resource subscriptions -------------------------------------------
    def _resource_state(self, uri: str) -> str:
        return json.dumps(self._read_resource(uri), sort_keys=True, default=str)

    def _ensure_watcher(self) -> None:
        if self._watcher is not None and self._watcher.is_alive():
            return
        self._stop.clear()
        self._watcher = threading.Thread(
            target=self._watch_loop, name="netcast3r-mcp-watch", daemon=True)
        self._watcher.start()

    def _watch_loop(self) -> None:
        while not self._stop.wait(4.0):
            with self._sub_lock:
                watched = list(self._subs.items())
            for uri, previous in watched:
                try:
                    current = self._resource_state(uri)
                except Exception:  # noqa: BLE001 - a resource can vanish mid-watch
                    continue
                if current != previous:
                    with self._sub_lock:
                        if uri in self._subs:
                            self._subs[uri] = current
                    self._notify("notifications/resources/updated", {"uri": uri})
                    self._log("debug", "netcast3r.resources", {"uri": uri})

    # -- resources ---------------------------------------------------------
    def _read_resource(self, uri: str) -> dict:
        if uri == "netcast3r://policy":
            return {"policy": self.policy, "tools": catalog(), "instructions": INSTRUCTIONS}
        target = _STATIC_RESOURCES.get(uri)
        if target is None:
            for pattern, resolve in _TEMPLATE_RESOURCES:
                match = pattern.match(uri)
                if match:
                    target = resolve(match)
                    break
        if target is None:
            raise RpcError(protocol.INVALID_PARAMS, f"unknown resource: {uri}")
        path, query = target
        try:
            return self.plane.request("GET", path, query=query)
        except Exception as exc:  # noqa: BLE001 - resource read boundary
            raise RpcError(protocol.INTERNAL_ERROR, f"resource read failed: {exc}")

    # -- completions -------------------------------------------------------
    def _complete(self, argument: dict) -> dict:
        """Autocomplete a prompt/template id argument from the live workspace."""
        name = str(argument.get("name") or "")
        prefix = str(argument.get("value") or "")
        try:
            limit = max(1, min(int(argument.get("limit") or 25), 100))
        except (TypeError, ValueError):
            limit = 25
        source = _COMPLETIONS.get(name)
        if source is None:
            return {"values": [], "hasMore": False}
        path, page_key, labels = source
        try:
            payload = self.plane.request(
                "GET", path, query={page_key: max(50, limit)})
        except Exception:  # noqa: BLE001 - completion is best effort
            return {"values": [], "hasMore": False}
        items = payload.get("items") if isinstance(payload, dict) else []
        values: list[str] = []
        low = prefix.lower()
        for item in items or []:
            if not isinstance(item, dict):
                continue
            ident = str(item.get("id") or "")
            if not ident:
                continue
            hay = " ".join(str(item.get(key) or "") for key in labels)
            if low and not (ident.lower().startswith(low) or low in hay.lower()):
                continue
            values.append(ident)
            if len(values) >= limit:
                break
        return {"values": values, "hasMore": False}

    # -- prompts -----------------------------------------------------------
    def _prompt(self, name: str, arguments: dict) -> dict:
        mission_id = str(arguments.get("mission_id") or "")
        run_id = str(arguments.get("run_id") or "")
        approval_id = str(arguments.get("approval_id") or "")
        if name == "recon-mission":
            if not mission_id:
                raise RpcError(protocol.INVALID_PARAMS, "mission_id required")
            text = (
                f"Recon mission {mission_id} with NetCast3r. First call missions_get and "
                "scope_check for its target. Then start one run with mission_start_run "
                "(read-only tier unless the mission explicitly allows more). While it runs, "
                "use runs_events and runs_get, then runs_inventory and findings_list. "
                "Report only what the evidence store contains. If scope is ambiguous, stop "
                "and ask the operator; do not broaden it."
            )
        elif name == "triage-findings":
            where = f"mission {mission_id}" if mission_id else "the workspace"
            text = (
                f"Triage findings for {where}. Call findings_list and findings_summary first, "
                "then findings_get for each candidate. Cross-check runs_inventory (validations, "
                "corroborations, reviews) before proposing a status. Use finding_triage only "
                "when a finding id and evidence support the decision. Never mark something "
                "confirmed because a pattern matched; a live validation or corroboration must "
                "exist."
            )
        elif name == "write-report":
            if not run_id:
                raise RpcError(protocol.INVALID_PARAMS, "run_id required")
            text = (
                f"Draft a bug bounty report from run {run_id}. Read runs_get, runs_report, "
                "findings_list, and runs_inventory for validations and corroborations. "
                "Include only reproducible facts, exact affected URLs, and the validation "
                "evidence that exists. If the run has no verified finding, say so and stop. "
                "Do not estimate impact that was not demonstrated."
            )
        elif name == "review-approval":
            if not approval_id:
                raise RpcError(protocol.INVALID_PARAMS, "approval_id required")
            text = (
                f"Review approval {approval_id} for a human. Fetch it with approvals_list or "
                "the control-plane API, restate the exact action, risk, requester, and bound "
                "arguments. Do not approve it yourself in supervised mode. End with a clear "
                "recommendation and the evidence a human needs to decide."
            )
        else:
            raise RpcError(protocol.INVALID_PARAMS, f"unknown prompt: {name}")
        return {
            "description": next(item["description"] for item in PROMPTS if item["name"] == name),
            "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
        }

    # -- loop --------------------------------------------------------------
    def handle(self, message: dict) -> dict | None:
        return self.dispatcher.dispatch(message)

    def run(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        self._stdin, self._stdout = stdin, stdout
        self.set_notifier(lambda message: write_message(stdout, message))
        self._write_state()
        try:
            while True:
                message = self._next_message(stdin)
                if message is None:
                    break
                response = self.handle(message)
                if response is not None:
                    write_message(stdout, response)
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            self.close()

    def _next_message(self, stdin):
        """The next inbound message: queued first, then the stream."""
        while True:
            if self._inbox:
                return self._inbox.pop(0)
            try:
                return protocol.read_message(stdin)
            except protocol.ParseError as exc:
                if self._stdout is None:
                    return None
                try:
                    write_message(self._stdout, error_response(
                        None, RpcError(protocol.PARSE_ERROR, str(exc))))
                except Exception:  # noqa: BLE001 - a dead stream ends the loop
                    return None
                continue


def run_stdio(plane, policy: str = DEFAULT_POLICY, base: Path | None = None) -> None:
    server = MCPServer(plane=plane, policy=policy, base=base)
    atexit.register(server.close)

    def stop(signum, frame):  # noqa: ARG001
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGHUP"):
        try:
            signal.signal(getattr(signal, name), stop)
        except (AttributeError, ValueError):
            pass
    server.run()
