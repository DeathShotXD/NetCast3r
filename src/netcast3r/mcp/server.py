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
import signal
import sys
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
    ("netcast3r://policy", "MCP policy",
     "The active policy and the full tool catalogue.", "application/json"),
)

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
        self.registry = ToolRegistry(ToolContext(
            plane=plane, policy=policy, base=base, actor=actor))
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
                "initialized": self.initialized,
                "version": __version__,
                "base": str(self.base or ""),
            })
        except Exception:  # noqa: BLE001 - a heartbeat must not kill the protocol
            pass

    def close(self) -> None:
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
            self.actor = f"{name}/{version}" if version else name
            self.registry.ctx.actor = self.actor
            self.initialized = True
            self._write_state()
            return {
                "protocolVersion": self.protocol_version,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
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
            try:
                payload, is_error = self.registry.call(name, arguments, self.actor)
            except ToolError as exc:
                if exc.code == "unknown_tool":
                    raise RpcError(protocol.INVALID_PARAMS, exc.message)
                payload, is_error = exc.payload(), True
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
            return {"resourceTemplates": []}

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

    # -- resources ---------------------------------------------------------
    def _read_resource(self, uri: str) -> dict:
        if uri == "netcast3r://policy":
            return {"policy": self.policy, "tools": catalog(), "instructions": INSTRUCTIONS}
        queries = {
            "netcast3r://status": ("/api/v1/meta", {}),
            "netcast3r://missions": ("/api/v1/missions", {"size": 50}),
            "netcast3r://runs": ("/api/v1/runs", {"size": 50}),
            "netcast3r://findings": ("/api/v1/findings", {"size": 50}),
            "netcast3r://submissions": ("/api/v1/submissions", {"size": 50}),
            "netcast3r://approvals": ("/api/v1/approvals", {"size": 50}),
            "netcast3r://tool-calls": ("/api/v1/tool-calls", {"size": 50}),
        }
        if uri not in queries:
            raise RpcError(protocol.INVALID_PARAMS, f"unknown resource: {uri}")
        path, query = queries[uri]
        try:
            return self.plane.request("GET", path, query=query)
        except Exception as exc:  # noqa: BLE001 - resource read boundary
            raise RpcError(protocol.INTERNAL_ERROR, f"resource read failed: {exc}")

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
        self._write_state()
        try:
            while True:
                try:
                    message = protocol.read_message(stdin)
                except protocol.ParseError as exc:
                    write_message(stdout, error_response(
                        None, RpcError(protocol.PARSE_ERROR, str(exc))))
                    continue
                if message is None:
                    break
                response = self.handle(message)
                if response is not None:
                    write_message(stdout, response)
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            self.close()


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
