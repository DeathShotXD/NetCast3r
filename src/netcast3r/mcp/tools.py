"""MCP tools: the full, typed surface an external agent may drive.

Every tool is a thin, validated adapter over the local control-plane API. The
rules live here, not in the prompt:

* tools have a risk tier and a JSON schema;
* `readonly`, `supervised`, and `full` policies gate those tiers;
* active work must name a mission or an explicit scope, and the target must
  match it;
* high-risk work needs a human decision, bound to a hash of the arguments,
  and each approval can be spent exactly once;
* every call is audited, including denied and failed attempts.

No tool fabricates a finding, provider health, approval, or scan result. If
the control plane has no data, the tool says so.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlsplit

import httpx

from .. import (authstore, browser, integrations, oast, pathdiff, pivot, quality,
                research, reveng, selfmodel, sqa, stix, surface, tempmail,
                threatintel, training)
from ..scope import ScopeManager

POLICIES = ("readonly", "supervised", "full")
RISK_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}
DEFAULT_POLICY = "supervised"

REDACT_KEYS = {"api_key", "apikey", "authorization", "cookie", "cookies", "password",
               "secret", "token", "private_key", "session", "set-cookie",
               "set_cookie", "x-api-key", "x-auth-token", "proxy-authorization",
               "body", "json", "form", "headers", "arguments", "token_value"}

METADATA_HOSTS = {"metadata.google.internal", "metadata.goog"}
METADATA_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}
IDENTITY_HOSTS = {
    "github.com", "gitlab.com", "bitbucket.org",
    "accounts.google.com", "login.microsoftonline.com", "login.live.com",
    "appleid.apple.com", "auth0.com", "okta.com", "onelogin.com",
    "duosecurity.com", "pingidentity.com",
}


class ToolError(Exception):
    def __init__(self, code: str, message: str, detail: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail

    def payload(self) -> dict:
        body = {"error": {"code": self.code, "message": self.message}}
        if self.detail:
            body["error"]["detail"] = self.detail
        return body


def _schema(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties,
            "required": required or [], "additionalProperties": False}


def _string(description: str, **extra) -> dict:
    return {"type": "string", "description": description, **extra}


def _integer(description: str, minimum=None, maximum=None, default=None) -> dict:
    schema = {"type": "integer", "description": description}
    if minimum is not None:
        schema["minimum"] = minimum
    if maximum is not None:
        schema["maximum"] = maximum
    if default is not None:
        schema["default"] = default
    return schema


def _boolean(description: str, default=None) -> dict:
    schema = {"type": "boolean", "description": description}
    if default is not None:
        schema["default"] = default
    return schema


def _object(description: str) -> dict:
    return {"type": "object", "description": description, "additionalProperties": True}


def _array(description: str, items: dict | None = None) -> dict:
    return {"type": "array", "description": description,
            "items": items or {"type": "string"}}


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    risk: str
    category: str
    input_schema: dict
    handler_name: str
    read_only: bool = False
    destructive: bool = False
    open_world: bool = False
    operator_only: bool = False

    def annotations(self) -> dict:
        return {
            "title": self.title,
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.read_only,
            "openWorldHint": self.open_world,
        }


def _validate(value, schema: dict, path: str = "arguments") -> None:
    """Validate the subset of JSON Schema this registry publishes.

    Small on purpose: no dependency, no surprise coercion. Unknown arguments
    are rejected, because an agent that guessed a field should be told.
    """
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise ToolError("invalid_arguments", f"{path} must be an object")
        properties = schema.get("properties") or {}
        for name in schema.get("required") or []:
            if name not in value:
                raise ToolError("invalid_arguments", f"{path}.{name} is required")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise ToolError("invalid_arguments",
                                f"unknown argument(s): {', '.join(unknown)}")
        for name, item in value.items():
            if name in properties:
                _validate(item, properties[name], f"{path}.{name}")
        return
    if kind == "array":
        if not isinstance(value, list):
            raise ToolError("invalid_arguments", f"{path} must be an array")
        item_schema = schema.get("items") or {}
        for index, item in enumerate(value):
            _validate(item, item_schema, f"{path}[{index}]")
        return
    if kind == "string":
        if not isinstance(value, str):
            raise ToolError("invalid_arguments", f"{path} must be a string")
    elif kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ToolError("invalid_arguments", f"{path} must be an integer")
    elif kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ToolError("invalid_arguments", f"{path} must be a number")
    elif kind == "boolean":
        if not isinstance(value, bool):
            raise ToolError("invalid_arguments", f"{path} must be a boolean")
    if "enum" in schema and value not in schema["enum"]:
        raise ToolError("invalid_arguments", f"{path} must be one of: "
                        + ", ".join(str(item) for item in schema["enum"]))
    if "minimum" in schema and isinstance(value, (int, float)) and value < schema["minimum"]:
        raise ToolError("invalid_arguments", f"{path} must be >= {schema['minimum']}")
    if "maximum" in schema and isinstance(value, (int, float)) and value > schema["maximum"]:
        raise ToolError("invalid_arguments", f"{path} must be <= {schema['maximum']}")


SENSITIVE_TOOL_ARGS = {("browser_type", "text")}


def audit_args(tool_name: str, arguments: dict) -> dict:
    """Redact credentials and typed text before the audit write."""
    clean = redact_payload(arguments)
    for name, key in SENSITIVE_TOOL_ARGS:
        if name == tool_name and isinstance(clean, dict) and key in clean:
            clean[key] = "[redacted]"
    return clean


def redact_payload(value, key: str = ""):
    """Remove obvious credentials before anything reaches the audit table."""
    if key.lower() in REDACT_KEYS:
        return "[redacted]"
    if isinstance(value, dict):
        return {str(name): redact_payload(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [redact_payload(item, key) for item in value]
    return value


def args_digest(tool_name: str, arguments: dict) -> str:
    clean = {key: value for key, value in (arguments or {}).items()
             if key not in {"approval_id", "confirm"}}
    raw = json.dumps([tool_name, clean], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class RateLimiter:
    """Per-process sliding windows. Cheap, predictable, and auditable."""

    LIMITS = {
        "default": (180, 60.0),
        "mutation": (40, 60.0),
        "scan": (6, 3600.0),
        "probe": (60, 60.0),
        "request": (90, 60.0),
        "oracle": (600, 60.0),
        "race": (20, 60.0),
        "wait": (6, 60.0),
    }

    def __init__(self):
        self._calls: dict[str, list[float]] = {}

    def check(self, bucket: str) -> None:
        limit, window = self.LIMITS.get(bucket, self.LIMITS["default"])
        now = time.monotonic()
        calls = [stamp for stamp in self._calls.get(bucket, []) if now - stamp < window]
        if len(calls) >= limit:
            raise ToolError("rate_limited",
                            f"{bucket} rate limit reached ({limit} per {int(window)}s)")
        calls.append(now)
        self._calls[bucket] = calls


@dataclass
class ToolContext:
    plane: object
    policy: str = DEFAULT_POLICY
    base: Path | None = None
    limiter: RateLimiter = field(default_factory=RateLimiter)
    actor: str = "agent"
    tool_count: int = 0
    mission_id: str = ""


def _call(ctx: ToolContext, method: str, path: str, query: dict | None = None, body=None):
    try:
        return ctx.plane.request(method, path, query=query, body=body)
    except Exception as exc:  # PlaneError and transport failures both land here
        status = int(getattr(exc, "status", 0) or 0)
        detail = str(getattr(exc, "detail", "") or "")
        if status == 404:
            raise ToolError("not_found", str(exc), detail)
        if status == 409:
            raise ToolError("conflict", str(exc), detail)
        if status == 400:
            raise ToolError("invalid_arguments", str(exc), detail)
        raise ToolError("control_plane", str(exc), detail)


def _mission(ctx: ToolContext, mission_id: str) -> dict:
    mission = _call(ctx, "GET", f"/api/v1/missions/{mission_id}")
    if not mission:
        raise ToolError("not_found", "mission not found")
    return mission


def _scope_entries(mission: dict | None, extra=None) -> list[str]:
    entries: list[str] = []
    if mission:
        target = str(mission.get("target") or "").strip()
        if target:
            entries.append(target)
        entries.extend(str(item) for item in (mission.get("scope") or []) if str(item).strip())
    entries.extend(str(item).strip() for item in (extra or []) if str(item).strip())
    seen, unique = set(), []
    for entry in entries:
        if entry not in seen:
            seen.add(entry)
            unique.append(entry)
    return unique


def _target_host(target: str) -> str:
    raw = (target or "").strip()
    if "://" in raw:
        try:
            return (urlsplit(raw).hostname or "").lower()
        except ValueError:
            return ""
    return raw.split("/", 1)[0].split(":", 1)[0].lower().rstrip(".")


def _deny_metadata(target: str) -> None:
    host = _target_host(target)
    if host in METADATA_HOSTS or host.endswith(".metadata.google.internal"):
        raise ToolError("scope_denied", "cloud metadata hosts are never in scope")
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return
    for info in infos:
        address = str(info[4][0]).lower()
        if address in METADATA_IPS or address.startswith("fe80:"):
            raise ToolError("scope_denied", "link-local and metadata addresses are never in scope")


def _require_scope(ctx: ToolContext, target: str, mission_id: str = "",
                   extra_scope=None, probe: bool = False) -> dict:
    mission = _mission(ctx, mission_id) if mission_id else None
    entries = _scope_entries(mission, extra_scope)
    if not entries:
        raise ToolError(
            "scope_denied",
            "active tools need a mission_id or an explicit scope list",
            "a target alone is not an authorization",
        )
    manager = ScopeManager(in_scope=entries)
    if not manager.is_in_scope(target):
        raise ToolError(
            "scope_denied",
            f"target is outside the declared scope: {target}",
            "out-of-scope rules win; add the target to the mission only if the program allows it",
        )
    if probe:
        _deny_metadata(target)
    return {"mission": mission, "scope": entries,
            "classification": manager.classify(target)}


def _scan_options(raw: dict | None) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ToolError("invalid_arguments", "options must be an object")
    allowed = {"depth", "tier", "rate", "delay", "timeout", "retries", "max_pages",
               "subdomains", "wayback", "random_agent", "resume"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ToolError("invalid_arguments", f"unknown scan option(s): {', '.join(unknown)}")
    options = dict(raw)
    if "tier" in options and options["tier"] not in {"read", "write", "full"}:
        raise ToolError("invalid_arguments", "options.tier must be read, write, or full")
    for key, low, high in (("depth", 0, 9), ("rate", 0.1, 50), ("delay", 0, 60),
                           ("timeout", 1, 120), ("retries", 0, 5), ("max_pages", 1, 5000)):
        if key in options:
            value = options[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ToolError("invalid_arguments", f"options.{key} must be a number")
            if value < low or value > high:
                raise ToolError("invalid_arguments",
                                f"options.{key} must be between {low} and {high}")
    for key in ("subdomains", "wayback", "random_agent", "resume"):
        if key in options and not isinstance(options[key], bool):
            raise ToolError("invalid_arguments", f"options.{key} must be a boolean")
    return options


def _page(items_key: str = "items") -> dict:
    return {"type": "object", "properties": {}}


# -- handlers -------------------------------------------------------------

def tool_status(ctx: ToolContext, args: dict) -> dict:
    meta = _call(ctx, "GET", "/api/v1/meta")
    summary = _call(ctx, "GET", "/api/v1/summary")
    runs = _call(ctx, "GET", "/api/v1/runs", {"status": "running", "size": 20})
    return {
        "ok": True,
        "plane": ctx.plane.kind,
        "plane_url": getattr(ctx.plane, "url", ""),
        "policy": ctx.policy,
        "tool_count": ctx.tool_count,
        "api": meta,
        "summary": summary,
        "active_runs": runs.get("items", []),
    }


def missions_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/missions", {
        "status": args.get("status", ""), "size": args.get("limit", 50),
        "page": args.get("page", 1)})


def missions_get(ctx: ToolContext, args: dict) -> dict:
    return _mission(ctx, args["mission_id"])


def missions_create(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in
            ("title", "target", "objective", "status", "autonomy", "budget", "scope", "plan")
            if key in args}
    return _call(ctx, "POST", "/api/v1/missions", body=body)


def missions_update(ctx: ToolContext, args: dict) -> dict:
    mission_id = args.pop("mission_id")
    return _call(ctx, "PATCH", f"/api/v1/missions/{mission_id}", body=args)


def missions_delete(ctx: ToolContext, args: dict) -> dict:
    mission_id = args["mission_id"]
    return _call(ctx, "DELETE", f"/api/v1/missions/{mission_id}")


def missions_attach_run(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", f"/api/v1/missions/{args['mission_id']}/runs",
                 body={"run_id": args["run_id"]})


def mission_start_run(ctx: ToolContext, args: dict) -> dict:
    mission = _mission(ctx, args["mission_id"])
    target = str(args.get("target") or mission.get("target") or "").strip()
    if not target:
        raise ToolError("invalid_arguments", "mission has no target")
    _require_scope(ctx, target, args["mission_id"])
    body = {"target": target, "options": _scan_options(args.get("options"))}
    return _call(ctx, "POST", f"/api/v1/missions/{mission['id']}/runs", body=body)


def agent_status(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/missions/{args['mission_id']}/agent")


def agent_start(ctx: ToolContext, args: dict) -> dict:
    mission = _mission(ctx, args["mission_id"])
    target = str(mission.get("target") or "").strip()
    if not target:
        raise ToolError("invalid_arguments", "mission has no target")
    _require_scope(ctx, target, mission["id"])
    body = {key: args[key] for key in
            ("use_model", "max_tasks", "max_seconds", "max_model_calls",
             "allow_manual", "restart", "role") if key in args}
    return _call(ctx, "POST", f"/api/v1/missions/{mission['id']}/agent/start", body=body)


def agent_pause(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", f"/api/v1/missions/{args['mission_id']}/agent/pause")


def agent_resume(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", f"/api/v1/missions/{args['mission_id']}/agent/resume")


def agent_stop(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", f"/api/v1/missions/{args['mission_id']}/agent/stop")


def scan_start(ctx: ToolContext, args: dict) -> dict:
    mission_id = str(args.get("mission_id") or "")
    mission = _mission(ctx, mission_id) if mission_id else None
    target = str(args.get("target") or (mission or {}).get("target") or "").strip()
    if not target:
        raise ToolError("invalid_arguments", "target required")
    _require_scope(ctx, target, mission_id, args.get("scope"))
    options = _scan_options(args.get("options"))
    run = _call(ctx, "POST", "/api/v1/runs", body={"target": target, "options": options})
    if mission_id:
        try:
            _call(ctx, "POST", f"/api/v1/missions/{mission_id}/runs",
                  body={"run_id": run["id"]})
        except ToolError as exc:
            return {"run": run, "mission_id": mission_id,
                    "warning": f"run started but mission link failed: {exc.message}"}
    return {"run": run, "mission_id": mission_id or None}


def runs_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/runs", {
        "status": args.get("status", ""), "q": args.get("q", ""),
        "size": args.get("limit", 50), "page": args.get("page", 1)})


def runs_get(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/runs/{args['run_id']}")


def runs_events(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/runs/{args['run_id']}/events",
                 {"since": args.get("since", 0)})


def runs_stop(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", f"/api/v1/runs/{args['run_id']}/stop")


def runs_resume(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", f"/api/v1/runs/{args['run_id']}/resume")


def runs_delete(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "DELETE", f"/api/v1/runs/{args['run_id']}")


def runs_report(ctx: ToolContext, args: dict) -> dict:
    result = _call(ctx, "GET", f"/api/v1/runs/{args['run_id']}/report")
    text = str(result.get("text") or "")
    limit = args.get("max_chars", 200000)
    truncated = len(text) > limit
    return {"run_id": args["run_id"], "report": text[:limit],
            "chars": len(text), "truncated": truncated}


def runs_inventory(ctx: ToolContext, args: dict) -> dict:
    kinds = {"subdomains", "pages", "assets", "js", "endpoints", "secrets", "candidates",
             "validations", "corroborations", "reviews", "findings", "stages"}
    kind = args.get("kind", "endpoints")
    if kind not in kinds:
        raise ToolError("invalid_arguments", f"unknown inventory kind: {kind}")
    return _call(ctx, "GET", f"/api/v1/runs/{args['run_id']}/inventory",
                 {"kind": kind, "limit": args.get("limit", 500)})


def findings_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/findings", {
        "run_id": args.get("run_id", ""), "severity": args.get("severity", ""),
        "status": args.get("status", ""), "q": args.get("q", ""),
        "sort": args.get("sort", "created_at"),
        "size": args.get("limit", 50), "page": args.get("page", 1)})


def findings_get(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/findings/{args['finding_id']}")


def findings_summary(ctx: ToolContext, args: dict) -> dict:
    run_id = str(args.get("run_id") or "")
    if run_id:
        return {"run_id": run_id, "summary": _call(
            ctx, "GET", f"/api/v1/runs/{run_id}/summary")}
    return {"summary": _call(ctx, "GET", "/api/v1/summary")}


def finding_triage(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in ("status", "notes", "tags", "severity_override")
            if key in args}
    return _call(ctx, "PATCH", f"/api/v1/findings/{args['finding_id']}", body=body)


def findings_create(ctx: ToolContext, args: dict) -> dict:
    body = {key: value for key, value in args.items()
            if key in {"title", "severity", "run_id", "impact", "evidence", "source",
                       "secret_type", "value", "confidence", "tags", "notes",
                       "fingerprint"}}
    return _call(ctx, "POST", "/api/v1/findings", body=body)


def finding_artifact_add(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in ("name", "content", "encoding", "content_type")
            if key in args}
    return _call(ctx, "POST", f"/api/v1/findings/{args['finding_id']}/artifacts",
                 body=body)


def finding_artifact_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/findings/{args['finding_id']}/artifacts")


def finding_artifact_get(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET",
                 f"/api/v1/findings/{args['finding_id']}/artifacts/{args['artifact_id']}",
                 {"content": 1})


def report_quality(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/findings/{args['finding_id']}/quality")


def program_rank(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/programs/rank")


def surface_diff(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/runs/{args['run_id']}/diff", {
        "against": args["against"], "limit": args.get("limit", 200)})


def self_audit(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/self-audit")


def diagnostics(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/diagnostics")


def expertise_profile(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/expertise", {"limit": args.get("limit", 50)})


def stix_export(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/stix/export", {
        "mission_id": args.get("mission_id", ""),
        "severity": args.get("severity", ""),
        "limit": args.get("limit", 100)})


def taxii_collections(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/taxii/collections", {
        "api_root": args.get("api_root", "")})


def taxii_poll(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/taxii/objects", {
        "api_root": args.get("api_root", ""),
        "collection_id": args.get("collection_id", ""),
        "added_after": args.get("added_after", ""),
        "limit": args.get("limit", 100)})


def _run_recon(ctx: ToolContext, args: dict, mode: str) -> dict:
    tool = str(args.get("tool") or "").strip().lower()
    catalog = integrations.TOOL_CATALOG
    if tool not in catalog:
        raise ToolError("invalid_arguments", f"unknown tool: {tool}")
    if catalog[tool][0] != mode:
        raise ToolError("invalid_arguments",
                        f"{tool} is a {catalog[tool][0]} tool, not {mode}")
    target = str(args.get("target") or "").strip()
    if not target:
        raise ToolError("invalid_arguments", "target is required")
    mission_id = str(args.get("mission_id") or "")
    scope = args.get("scope")
    _require_scope(ctx, target, mission_id, scope, probe=True)
    try:
        result = integrations.run_tool(tool, target, timeout=int(args.get("timeout", 180)),
                                       base=ctx.base)
    except integrations.ToolRunError as exc:
        raise ToolError("invalid_arguments", str(exc))
    result["mission_id"] = mission_id
    return result


def recon_passive(ctx: ToolContext, args: dict) -> dict:
    return _run_recon(ctx, args, "passive")


def fetch_artifact(ctx: ToolContext, args: dict) -> dict:
    target = str(args.get("target") or "").strip()
    if not target:
        raise ToolError("invalid_arguments", "target is required")
    mission_id = str(args.get("mission_id") or "")
    scope = args.get("scope")
    _require_scope(ctx, target, mission_id, scope, probe=True)
    headers = {"user-agent": "NetCast3r-MCP/0.1", "accept": "*/*"}
    profile_name = str(args.get("auth_profile") or "").strip()
    if profile_name:
        profile = authstore.get_profile(profile_name, base=ctx.base)
        if profile is None:
            raise ToolError("invalid_arguments", f"unknown auth profile: {profile_name}")
        headers.update(profile.request_headers())
    name = str(args.get("name") or "") or target.rstrip("/").split("/")[-1] or "artifact.bin"
    try:
        return integrations.fetch_to_file(
            target, name, base=ctx.base,
            max_bytes=int(args.get("max_bytes", 10 * 1024 * 1024)),
            verify_tls=bool(args.get("verify_tls", True)),
            timeout=float(args.get("timeout", 30)), headers=headers)
    except integrations.ToolRunError as exc:
        raise ToolError("invalid_arguments", str(exc))


def test_case_run(ctx: ToolContext, args: dict) -> dict:
    """Run a small, ordered set of requests with explicit assertions.

    This is the precise-manual path: the operator states the request and the
    expected status/body, and the harness records pass/fail with evidence. It is
    not a scanner and it never invents a finding.
    """
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ToolError("invalid_arguments", "steps must be a non-empty array")
    if len(steps) > 12:
        raise ToolError("invalid_arguments", "a test case is limited to 12 steps")
    mission_id = str(args.get("mission_id") or "")
    base = str(args.get("base_url") or "").strip()
    if not base and mission_id:
        mission = _mission(ctx, mission_id)
        base = str(mission.get("target") or "")
    if base and "://" not in base:
        base = "https://" + base
    fail_fast = bool(args.get("fail_fast", True))
    results = []
    passed = failed = 0
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise ToolError("invalid_arguments", f"step {index} must be an object")
        method = str(step.get("method") or "GET").upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ToolError("invalid_arguments", f"step {index} has an unsupported method")
        url = str(step.get("url") or "")
        path = str(step.get("path") or "")
        target = url or (base.rstrip("/") + path if base else "")
        if not target:
            raise ToolError("invalid_arguments", f"step {index} needs url, path, or base_url")
        call_args = {"target": target, "method": method,
                     "mission_id": mission_id, "scope": args.get("scope")}
        for key in ("headers", "auth_profile", "body", "json", "form",
                    "follow_redirects", "verify_tls", "max_bytes", "timeout"):
            if key in step:
                call_args[key] = step[key]
        try:
            response = http_request(ctx, call_args)
            actual = int(response.get("status") or 0)
            body = str(response.get("body") or "")
            headers = response.get("headers") or {}
        except ToolError as exc:
            results.append({"step": index, "name": step.get("name", ""),
                            "target": target, "method": method, "pass": False,
                            "error": f"{exc.code}: {exc.message}"})
            failed += 1
            if fail_fast:
                break
            continue
        expected = step.get("expect_status", step.get("status"))
        checks = []
        if expected is not None:
            want = expected if isinstance(expected, list) else [expected]
            checks.append({"check": "status", "ok": actual in [int(item) for item in want],
                           "expected": want, "actual": actual})
        else:
            checks.append({"check": "status", "ok": 100 <= actual < 500,
                           "expected": "100-499", "actual": actual})
        contains = step.get("expect_body_contains")
        if contains:
            checks.append({"check": "body_contains", "ok": str(contains) in body,
                           "expected": str(contains)[:120], "actual": body[:200]})
        absent = step.get("expect_body_absent")
        if absent:
            checks.append({"check": "body_absent", "ok": str(absent) not in body,
                           "expected": f"not {str(absent)[:120]}", "actual": body[:200]})
        expect_header = step.get("expect_header")
        if isinstance(expect_header, dict):
            for name, value in expect_header.items():
                actual_header = str(headers.get(str(name).lower(), ""))
                checks.append({"check": f"header:{name}", "ok": str(value) in actual_header,
                               "expected": str(value), "actual": actual_header[:160]})
        ok = all(item["ok"] for item in checks)
        results.append({"step": index, "name": step.get("name", ""), "target": target,
                        "method": method, "status": actual, "pass": ok,
                        "checks": checks, "body_sample": body[:240],
                        "elapsed_ms": response.get("elapsed_ms")})
        if ok:
            passed += 1
        else:
            failed += 1
            if fail_fast:
                break
    return {"name": str(args.get("name") or "test case"), "steps": len(steps),
            "passed": passed, "failed": failed, "results": results,
            "ok": failed == 0,
            "note": ("Assertions and raw responses are recorded per step. This harness "
                     "does not decide that a target is vulnerable.")}


def hypothesis_create(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in
            ("title", "target", "mission_id", "technique", "rationale", "expected")
            if key in args}
    return _call(ctx, "POST", "/api/v1/hypotheses", body=body)


def hypothesis_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/hypotheses", {
        "mission_id": args.get("mission_id", ""), "status": args.get("status", ""),
        "q": args.get("q", ""), "limit": args.get("limit", 50),
        "offset": args.get("offset", 0)})


def hypothesis_get(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/hypotheses/{args['hypothesis_id']}")


def hypothesis_test(ctx: ToolContext, args: dict) -> dict:
    """Run a hypothesis as an assertion-based test case and record the verdict."""
    hypothesis = _call(ctx, "GET", f"/api/v1/hypotheses/{args['hypothesis_id']}")
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ToolError("invalid_arguments", "steps must be a non-empty array")
    mission_id = str(args.get("mission_id") or hypothesis.get("mission_id") or "")
    call_args = {"name": hypothesis.get("title") or "hypothesis test",
                 "steps": steps, "mission_id": mission_id,
                 "scope": args.get("scope"),
                 "base_url": args.get("base_url") or hypothesis.get("target"),
                 "fail_fast": args.get("fail_fast", True)}
    result = test_case_run(ctx, call_args)
    if result.get("ok"):
        status = "supported"
    elif any(item.get("error") for item in result.get("results", [])):
        status = "inconclusive"
    else:
        status = "refuted"
    updated = _call(ctx, "PATCH", f"/api/v1/hypotheses/{args['hypothesis_id']}",
                    body={"status": status,
                          "test": {"steps": steps, "base_url": call_args["base_url"]},
                          "result": result})
    return {"hypothesis": updated, "status": status, "test_result": result,
            "note": ("A supported hypothesis is still not a finding; promote it with "
                     "impact and evidence before triage.")}


def hypothesis_promote(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in
            ("title", "severity", "impact", "evidence", "tags", "source")
            if key in args}
    return _call(ctx, "POST", f"/api/v1/hypotheses/{args['hypothesis_id']}/promote",
                 body=body)


def training_plan(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/training/plan", {
        "category": args.get("category", ""),
        "difficulty": args.get("difficulty", ""),
        "source": args.get("source", ""),
        "limit": args.get("limit", 5)})


def training_status(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/training",
                 {"source": args.get("source", "")})


def training_sources(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/training/sources")


def training_record(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in
            ("lab_slug", "status", "lesson", "evidence", "notes", "instance_url",
             "verified", "technique", "mission_id") if key in args}
    return _call(ctx, "POST", "/api/v1/training/record", body=body)


def training_verify(ctx: ToolContext, args: dict) -> dict:
    target = str(args.get("instance_url") or "").strip()
    host = (urlsplit(target).hostname or "").lower()
    if not host:
        raise ToolError("invalid_arguments", "instance_url must be an http(s) URL")
    academy = host == "web-security-academy.net" or host.endswith(
        ".web-security-academy.net")
    loopback = host in {"localhost", "127.0.0.1", "::1", "[::1]"}
    lab = next((item for item in training.catalog()
                if any(str(entry).lower() == host or
                       (str(entry).lower().startswith("*.")
                        and host.endswith(str(entry).lower()[1:]))
                       for entry in item.get("hosts") or [])), None)
    if not academy:
        if lab is None:
            raise ToolError(
                "invalid_arguments",
                "instance_url must belong to a bundled training pack")
        if not loopback:
            mission_id = str(args.get("mission_id") or "").strip()
            scope = args.get("scope")
            if not mission_id and not scope:
                raise ToolError(
                    "scope_denied",
                    "a non-local training host needs a mission_id or explicit scope")
    expects = args.get("expect") or []
    if isinstance(expects, str):
        expects = [expects]
    if not academy and not expects:
        raise ToolError(
            "invalid_arguments",
            "non-Academy verification needs the expect markers that prove the exercise")
    profile = str(args.get("browser_profile") or "").strip()
    verified_via = "http"
    if profile:
        try:
            snap = browser.snapshot(profile, base=ctx.base)
        except Exception as exc:  # browser failures are transport failures here
            raise ToolError("request_failed", f"browser check failed: {exc}")
        snap_host = (urlsplit(str(snap.get("url") or "")).hostname or "").lower()
        if snap_host != host:
            raise ToolError(
                "scope_denied",
                f"browser profile is on {snap_host or 'an unknown host'}, not {host}")
        body = str(snap.get("text") or "") + "\n" + str(snap.get("html") or "")
        status = 200
        verified_via = "browser"
    else:
        request = {
            "target": target, "method": "GET", "max_bytes": 262144,
            "timeout": 30, "follow_redirects": True}
        if academy:
            request["scope"] = ["web-security-academy.net",
                                "*.web-security-academy.net"]
        elif loopback:
            request["scope"] = [host]
        else:
            request["mission_id"] = str(args.get("mission_id") or "")
            request["scope"] = args.get("scope")
        try:
            response = http_request(ctx, request)
        except ToolError as exc:
            raise ToolError("request_failed", f"lab check failed: {exc.message}")
        body = str(response.get("body") or "")
        status = response.get("status")
    solved = (training.verify_signal(body) if academy
              else training.verify_text(body, expects))
    excerpt = ""
    marker = "congratulations" if academy else (
        str(expects[0]).strip().lower() if expects else "")
    if solved and marker:
        lower = body.lower()
        index = lower.find(marker)
        if index >= 0:
            excerpt = body[max(0, index - 100):index + 300].replace("\n", " ")
    return {
        "instance_url": target,
        "source": (lab or {}).get("source", "portswigger"),
        "solved": solved,
        "status": status,
        "verified_via": verified_via,
        "evidence": excerpt or "the expected marker was not found in the response",
        "note": ("Academy labs expose their own congratulations banner. Other packs "
                 "need explicit expect markers. Record the evidence with training_record."),
    }


def skill_packs(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/skill-packs")


def ui_audit(ctx: ToolContext, args: dict) -> dict:
    try:
        return sqa.audit_pages(
            ctx.base,
            routes=args.get("routes"),
            viewport={"width": args.get("width", 1440),
                      "height": args.get("height", 900)},
            headless=bool(args.get("headless", True)))
    except Exception as exc:  # noqa: BLE001 - surface the browser reason
        raise ToolError("audit_failed", f"UI audit failed: {type(exc).__name__}",
                        str(exc))


def technique_search(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/techniques", {
        "q": args.get("query", ""), "tag": args.get("tag", ""),
        "rarity": args.get("rarity", ""), "impact": args.get("impact", ""),
        "limit": args.get("limit", 20)})


def technique_plan(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/techniques/plan", {
        "target": args.get("target", ""), "tech": args.get("tech", ""),
        "signals": ",".join(str(item) for item in (args.get("signals") or [])),
        "tags": ",".join(str(item) for item in (args.get("tags") or [])),
        "limit": args.get("limit", 6)})


def research_sources(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/research/sources")


def hunt_plan(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/hunt-plan", {
        "mission_id": args["mission_id"], "tech": args.get("tech", ""),
        "signals": ",".join(str(item) for item in (args.get("signals") or [])),
        "limit": args.get("limit", 6)})


def research_ingest(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in ("url", "title", "notes", "tags")
            if key in args}
    return _call(ctx, "POST", "/api/v1/research/ingest", body=body)


def selfmodel_snapshot(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/selfmodel")


def selfmodel_gaps(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/selfmodel/gaps",
                 {"limit": args.get("limit", 6)})


def selfmodel_evolve(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", "/api/v1/selfmodel/evolve",
                 body={"limit": args.get("limit", 3)})


def upgrade_propose(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in
            ("title", "rationale", "evidence", "area", "priority") if key in args}
    return _call(ctx, "POST", "/api/v1/upgrades", body=body)


def upgrade_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/upgrades", {
        "status": args.get("status", ""), "area": args.get("area", ""),
        "limit": args.get("limit", 100)})


def upgrade_update(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in ("status", "rationale") if key in args}
    return _call(ctx, "PATCH", f"/api/v1/upgrades/{args['proposal_id']}", body=body)


def toolbook(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/toolbook", {
        "q": args.get("query", ""), "name": args.get("name", "")})


def burp_status(ctx: ToolContext, args: dict) -> dict:
    config = integrations.load_burp_config(ctx.base)
    if not config["configured"]:
        return {"ok": False, "configured": False,
                "note": ("Set NETCAST3R_BURP_URL (and optionally NETCAST3R_BURP_TOKEN) "
                         "or write ~/.netcast3r/integrations.json with "
                         "{\"burp\": {\"url\": \"http://127.0.0.1:9876\"}}.")}
    client = integrations.BurpClient(config["url"], config["token"])
    try:
        status = client.status()
    except integrations.BurpError as exc:
        return {"ok": False, "configured": True, "url": config["url"],
                "error": str(exc)}
    status["configured"] = True
    return status


def _burp_scope_check(ctx: ToolContext, arguments: dict, mission_id: str,
                      scope) -> None:
    target_keys = {"url", "uri", "target", "host", "hostname", "endpoint", "base_url",
                   "domain", "destination", "dest", "address", "origin",
                   "redirect", "redirect_uri", "callback"}
    for key, value in (arguments or {}).items():
        if key in target_keys and isinstance(value, str) and value.strip():
            _require_scope(ctx, value, mission_id, scope, probe=True)
        elif isinstance(value, dict):
            _burp_scope_check(ctx, value, mission_id, scope)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _burp_scope_check(ctx, item, mission_id, scope)
        elif key in {"request", "raw", "raw_request"} and isinstance(value, str):
            match = __import__("re").search(r"(?im)^host:\s*(\S+)", value)
            if match:
                _require_scope(ctx, match.group(1), mission_id, scope, probe=True)


def sandbox_run(ctx: ToolContext, args: dict) -> dict:
    command = args.get("command")
    if not isinstance(command, list):
        raise ToolError("invalid_arguments", "command must be an array of strings")
    try:
        return integrations.sandbox_run(
            str(args.get("image") or "python:3.12-slim"), [str(part) for part in command],
            stdin=str(args.get("stdin") or ""), timeout=int(args.get("timeout", 60)),
            base=ctx.base)
    except integrations.ToolRunError as exc:
        raise ToolError("invalid_arguments", str(exc))


def mcp_servers_list(ctx: ToolContext, args: dict) -> dict:
    servers = integrations.load_mcp_servers(ctx.base)
    return {"items": [{"name": name, "transport": item["transport"],
                       "target": item.get("url", "") or " ".join(item.get("command") or [])}
                      for name, item in servers.items()],
            "total": len(servers),
            "note": ("Configure outbound servers under mcp_servers in "
                     "~/.netcast3r/integrations.json. Tokens are never returned.")}


def mcp_server_tools(ctx: ToolContext, args: dict) -> dict:
    servers = integrations.load_mcp_servers(ctx.base)
    config = servers.get(str(args.get("server") or ""))
    if not config:
        raise ToolError("not_found", "configured MCP server not found")
    try:
        return integrations.mcp_server_tools(config)
    except integrations.BurpError as exc:
        raise ToolError("control_plane", f"MCP server failed: {exc}")


def mcp_server_call(ctx: ToolContext, args: dict) -> dict:
    servers = integrations.load_mcp_servers(ctx.base)
    config = servers.get(str(args.get("server") or ""))
    if not config:
        raise ToolError("not_found", "configured MCP server not found")
    arguments = args.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise ToolError("invalid_arguments", "arguments must be an object")
    _burp_scope_check(ctx, arguments, str(args.get("mission_id") or ""),
                      args.get("scope"))
    try:
        return integrations.mcp_server_call(config, str(args["tool"]), arguments)
    except integrations.BurpError as exc:
        raise ToolError("control_plane", f"MCP server call failed: {exc}")


def burp_call(ctx: ToolContext, args: dict) -> dict:
    config = integrations.load_burp_config(ctx.base)
    if not config["configured"]:
        raise ToolError("invalid_arguments",
                        "Burp MCP is not configured; set NETCAST3R_BURP_URL")
    arguments = args.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise ToolError("invalid_arguments", "arguments must be an object")
    _burp_scope_check(ctx, arguments, str(args.get("mission_id") or ""),
                      args.get("scope"))
    client = integrations.BurpClient(config["url"], config["token"])
    try:
        return client.call_tool(str(args["tool"]), arguments)
    except integrations.BurpError as exc:
        raise ToolError("control_plane", f"Burp MCP call failed: {exc}")


def lessons_record(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in (
        "title", "lesson", "technique", "context", "outcome", "next_step", "tags",
        "mission_id", "run_id", "task_id", "source", "confidence") if key in args}
    return _call(ctx, "POST", "/api/v1/lessons", body=body)


def lessons_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/lessons", {
        "q": args.get("q", ""), "tag": args.get("tag", ""),
        "outcome": args.get("outcome", ""), "limit": args.get("limit", 50)})


def lessons_get(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/lessons/{args['lesson_id']}")


def lesson_reflect(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in ("tool_call_id", "run_id") if args.get(key)}
    if not body:
        raise ToolError("invalid_arguments", "tool_call_id or run_id is required")
    return _call(ctx, "POST", "/api/v1/lessons/reflect", body=body)


def skills_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/skills", {
        "q": args.get("q", ""), "limit": args.get("limit", 50),
        "status": args.get("status", "")})


def skills_get(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/skills/{args['name']}")


def skills_use(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", f"/api/v1/skills/{args['name']}/use",
                 body={"success": bool(args.get("success", True))})


def skills_status(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "PATCH", f"/api/v1/skills/{args['name']}",
                 body={"status": args["status"]})


def skills_upsert(ctx: ToolContext, args: dict) -> dict:
    body = {key: args[key] for key in (
        "name", "body", "title", "description", "tags", "source") if key in args}
    return _call(ctx, "POST", "/api/v1/skills", body=body)


def next_actions(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/missions/{args['mission_id']}/next-actions")


def threatintel_query(ctx: ToolContext, args: dict) -> dict:
    query = str(args.get("query") or "").strip()
    if not query:
        raise ToolError("invalid_arguments", "query is required")
    try:
        return threatintel.search(
            query, token=os.environ.get("GITHUB_TOKEN", ""),
            limit=max(1, min(int(args.get("limit", 10)), 20)))
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))
    except RuntimeError as exc:
        raise ToolError("control_plane", f"threat intel lookup failed: {exc}")


def threatintel_cve(ctx: ToolContext, args: dict) -> dict:
    cve_id = str(args.get("cve_id") or "").strip()
    if not cve_id:
        raise ToolError("invalid_arguments", "cve_id is required")
    try:
        return threatintel.search(
            cve_id, token=os.environ.get("GITHUB_TOKEN", ""),
            limit=max(1, min(int(args.get("limit", 10)), 20)))
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))
    except RuntimeError as exc:
        raise ToolError("control_plane", f"threat intel lookup failed: {exc}")


def threatintel_repro(ctx: ToolContext, args: dict) -> dict:
    cve_id = str(args.get("cve_id") or "").strip()
    if not cve_id:
        raise ToolError("invalid_arguments", "cve_id is required")
    try:
        return threatintel.reproduction_plan(
            cve_id, target=str(args.get("target") or ""),
            token=os.environ.get("GITHUB_TOKEN", ""), base=ctx.base)
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))
    except RuntimeError as exc:
        raise ToolError("control_plane", f"threat intel lookup failed: {exc}")


def token_pivot(ctx: ToolContext, args: dict) -> dict:
    mission_id = str(args.get("mission_id") or "").strip()
    if not mission_id:
        raise ToolError("invalid_arguments", "token_pivot requires a mission_id")
    mission = _mission(ctx, mission_id)
    hosts = [str(item).strip() for item in (args.get("hosts") or []) if str(item).strip()]
    if not hosts:
        target = str(mission.get("target") or "").strip()
        if target:
            hosts.append(target)
        for entry in mission.get("scope") or []:
            entry = str(entry).strip()
            if entry and not entry.startswith("!") and "*" not in entry:
                hosts.append(entry)
        hosts = list(dict.fromkeys(hosts))
    if not hosts:
        raise ToolError("invalid_arguments",
                        "no hosts to test; pass hosts or give the mission a concrete target")
    if len(hosts) > pivot.MAX_HOSTS:
        raise ToolError("invalid_arguments", f"at most {pivot.MAX_HOSTS} hosts per pivot")
    for host in hosts:
        _require_scope(ctx, host, mission_id, None, probe=True)
    try:
        result = pivot.pivot(hosts, str(args.get("header") or "Authorization"),
                             str(args["token_value"]), path=str(args.get("path") or "/"),
                             timeout=float(args.get("timeout", 10)),
                             delay=float(args.get("delay", 0.25)))
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))
    result["mission_id"] = mission_id
    return result


def submissions_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/submissions", {
        "status": args.get("status", ""),
        "mission_id": args.get("mission_id", ""),
        "finding_id": args.get("finding_id", ""),
        "platform": args.get("platform", ""),
        "size": args.get("limit", 50), "page": args.get("page", 1)})


def submissions_get(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", f"/api/v1/submissions/{args['submission_id']}")


def submissions_summary(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/submissions/summary")


def submissions_create(ctx: ToolContext, args: dict) -> dict:
    body = {key: value for key, value in args.items()
            if key in {"title", "platform", "program", "target", "severity", "status",
                       "mission_id", "finding_id", "run_id", "bounty_cents", "currency",
                       "external_id", "url", "report_path", "notes"}}
    return _call(ctx, "POST", "/api/v1/submissions", body=body)


def submissions_update(ctx: ToolContext, args: dict) -> dict:
    body = {key: value for key, value in args.items()
            if key not in {"submission_id", "approval_id", "confirm"}}
    return _call(ctx, "PATCH", f"/api/v1/submissions/{args['submission_id']}", body=body)


def submissions_delete(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "DELETE", f"/api/v1/submissions/{args['submission_id']}")


def approvals_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/approvals", {
        "status": args.get("status", ""), "mission_id": args.get("mission_id", ""),
        "size": args.get("limit", 50), "page": args.get("page", 1)})


def approval_request(ctx: ToolContext, args: dict) -> dict:
    mission_id = args["mission_id"]
    _mission(ctx, mission_id)
    payload = redact_payload(args.get("payload") or {})
    tool_name = str(args.get("tool") or "").strip()
    if tool_name:
        arguments = args.get("arguments")
        arguments = arguments if isinstance(arguments, dict) else {}
        payload["tool"] = tool_name
        payload["args_digest"] = args_digest(tool_name, arguments)
    body = {
        "mission_id": mission_id,
        "action": args["action"],
        "risk": args.get("risk", "medium"),
        "requested_by": ctx.actor,
        "reason": args.get("reason", ""),
        "payload": payload,
        "run_id": args.get("run_id", ""),
    }
    return _call(ctx, "POST", "/api/v1/approvals", body=body)


def approval_decide(ctx: ToolContext, args: dict) -> dict:
    mission_id = args.get("mission_id")
    approval = _call(ctx, "GET", f"/api/v1/approvals/{args['approval_id']}")
    if mission_id and approval.get("mission_id") != mission_id:
        raise ToolError("conflict", "approval belongs to a different mission")
    return _call(ctx, "POST", f"/api/v1/approvals/{args['approval_id']}/decision",
                 body={"decision": args["decision"],
                       "decided_by": args.get("decided_by", "operator"),
                       "reason": args.get("reason", "")})


def providers_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/providers/health")


def provider_test(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "POST", f"/api/v1/providers/{args['provider_id']}/test")


def scope_check(ctx: ToolContext, args: dict) -> dict:
    mission = _mission(ctx, args["mission_id"]) if args.get("mission_id") else None
    entries = _scope_entries(mission, args.get("scope"))
    if not entries:
        return {"target": args["target"], "in_scope": False, "classification": "unknown",
                "rules": [], "reason": "no mission or scope supplied"}
    manager = ScopeManager(in_scope=entries)
    return {"target": args["target"], "in_scope": manager.is_in_scope(args["target"]),
            "classification": manager.classify(args["target"]), "rules": entries}


def http_probe(ctx: ToolContext, args: dict) -> dict:
    target = args["target"].strip()
    url = target if "://" in target else "https://" + target
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ToolError("invalid_arguments", "target must be an http(s) URL or hostname")
    _require_scope(ctx, target, args.get("mission_id", ""), args.get("scope"), probe=True)
    method = args.get("method", "GET").upper()
    if method not in {"GET", "HEAD"}:
        raise ToolError("invalid_arguments", "probe supports GET and HEAD only")
    maximum = int(args.get("max_bytes", 65536))
    maximum = max(1024, min(maximum, 262144))
    started = time.monotonic()
    try:
        with httpx.Client(timeout=args.get("timeout", 15), trust_env=False,
                          follow_redirects=False,
                          headers={"user-agent": "NetCast3r-MCP/0.1"}) as client:
            with client.stream(method, url) as response:
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    if size + len(chunk) > maximum:
                        chunks.append(chunk[: maximum - size])
                        size = maximum
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                body = b"".join(chunks)
                headers = {key.lower(): value for key, value in response.headers.items()
                           if key.lower() in {"content-type", "content-length", "server",
                                              "location", "allow", "x-powered-by",
                                              "strict-transport-security"}}
                return {
                    "target": target,
                    "url": str(response.url),
                    "status": response.status_code,
                    "method": method,
                    "headers": headers,
                    "body": body.decode("utf-8", "replace"),
                    "bytes": len(body),
                    "truncated": size >= maximum,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                }
    except httpx.HTTPError as exc:
        raise ToolError("probe_failed", f"probe failed: {type(exc).__name__}", str(exc))


def http_request(ctx: ToolContext, args: dict) -> dict:
    """One scoped HTTP request with a named auth profile and manual redirects.

    This is the authenticated counterpart to ``http_probe``: it can carry a
    session, a JSON or form body, and any method a web application accepts.
    Every hop is re-checked against the same scope, so a redirect cannot walk
    the request onto an out-of-scope or metadata host.
    """
    target = args["target"].strip()
    url = target if "://" in target else "https://" + target
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ToolError("invalid_arguments", "target must be an http(s) URL or hostname")
    method = str(args.get("method", "GET")).upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ToolError("invalid_arguments", "unsupported method")
    mission_id = str(args.get("mission_id") or "")
    scope = args.get("scope")
    _require_scope(ctx, target, mission_id, scope, probe=True)

    headers: dict[str, str] = {"user-agent": "NetCast3r-MCP/0.1",
                               "accept": "*/*"}
    profile_name = str(args.get("auth_profile") or "").strip()
    if profile_name:
        profile = authstore.get_profile(profile_name, base=ctx.base)
        if profile is None:
            raise ToolError("invalid_arguments", f"unknown auth profile: {profile_name}")
        headers.update(profile.request_headers())

    supplied = args.get("headers") or {}
    if not isinstance(supplied, dict):
        raise ToolError("invalid_arguments", "headers must be an object")
    has_cookie = any(str(name).strip().lower() == "cookie" for name in supplied)
    if has_cookie:
        # A caller-supplied cookie replaces the profile cookie in any casing.
        headers = {key: value for key, value in headers.items()
                   if key.lower() != "cookie"}
    for raw_name, raw_value in supplied.items():
        name = str(raw_name).strip()
        value = str(raw_value)
        if not name or any(char in name for char in "\r\n:") or "\r" in value or "\n" in value:
            raise ToolError("invalid_arguments", f"invalid header: {name[:40]!r}")
        headers[name] = value

    body = args.get("body")
    payload_json = args.get("json")
    payload_form = args.get("form")
    chosen = [item for item in (body, payload_json, payload_form) if item is not None]
    if len(chosen) > 1:
        raise ToolError("invalid_arguments", "use only one of body, json, or form")
    content: bytes | None = None
    if payload_json is not None:
        if not isinstance(payload_json, dict):
            raise ToolError("invalid_arguments", "json must be an object")
        content = json.dumps(payload_json).encode("utf-8")
        headers.setdefault("content-type", "application/json")
    elif payload_form is not None:
        if not isinstance(payload_form, dict):
            raise ToolError("invalid_arguments", "form must be an object")
        content = urlencode(payload_form, doseq=True).encode("utf-8")
        headers.setdefault("content-type", "application/x-www-form-urlencoded")
    elif body is not None:
        if not isinstance(body, str):
            raise ToolError("invalid_arguments", "body must be a string")
        content = body.encode("utf-8")
    if content is not None and len(content) > 1_048_576:
        raise ToolError("invalid_arguments", "request body is larger than 1 MiB")

    maximum = int(args.get("max_bytes", 65536))
    maximum = max(1024, min(maximum, 524288))
    timeout = float(args.get("timeout", 15))
    timeout = max(1.0, min(timeout, 60.0))
    follow = bool(args.get("follow_redirects", False))
    max_hops = int(args.get("max_redirects", 5)) if follow else 0
    max_hops = max(0, min(max_hops, 5))
    verify_tls = bool(args.get("verify_tls", True))

    redirects: list[dict] = []
    blocked = ""
    started = time.monotonic()
    current = url
    current_method = method
    current_content = content
    status = 0
    response_headers: dict[str, str] = {}
    set_cookie: list[str] = []
    text = ""
    size = 0
    truncated = False

    try:
        with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False,
                          verify=verify_tls) as client:
            for hop in range(max_hops + 1):
                with client.stream(current_method, current, headers=headers,
                                   content=current_content) as response:
                    chunks, read = [], 0
                    for chunk in response.iter_bytes():
                        if read + len(chunk) > maximum:
                            chunks.append(chunk[: maximum - read])
                            read = maximum
                            truncated = True
                            break
                        chunks.append(chunk)
                        read += len(chunk)
                    raw = b"".join(chunks)
                    status = response.status_code
                    response_headers = {}
                    for key, value in response.headers.multi_items():
                        lower = key.lower()
                        if lower == "set-cookie":
                            set_cookie.append(value)
                        elif lower in response_headers:
                            response_headers[lower] += ", " + value
                        else:
                            response_headers[lower] = value
                    text = raw.decode("utf-8", "replace")
                    size = len(raw)
                    location = response.headers.get("location", "")
                if not (follow and status in {301, 302, 303, 307, 308} and location):
                    break
                if hop >= max_hops:
                    break
                next_url = urljoin(current, location)
                next_parts = urlsplit(next_url)
                if next_parts.scheme not in {"http", "https"}:
                    blocked = f"redirect scheme is not http(s): {next_parts.scheme}"
                    break
                try:
                    _require_scope(ctx, next_url, mission_id, scope, probe=True)
                except ToolError as exc:
                    blocked = exc.message
                    break
                redirects.append({"status": status, "from": current, "to": next_url})
                if urlsplit(current).hostname != next_parts.hostname:
                    # never carry a session across a host boundary
                    for key in list(headers):
                        if key.lower() in {"cookie", "authorization"}:
                            headers.pop(key, None)
                if status in {301, 302, 303} and current_method not in {"GET", "HEAD"}:
                    current_method = "GET"
                    current_content = None
                    headers.pop("content-type", None)
                    headers.pop("Content-Type", None)
                current = next_url
    except httpx.HTTPError as exc:
        raise ToolError("request_failed", f"request failed: {type(exc).__name__}", str(exc))

    return {
        "target": target,
        "url": current,
        "method": current_method,
        "status": status,
        "headers": response_headers,
        "set_cookie": set_cookie,
        "body": text,
        "bytes": size,
        "truncated": truncated,
        "redirects": redirects,
        "blocked_redirect": blocked,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


def http_upload(ctx: ToolContext, args: dict) -> dict:
    """One scoped multipart upload. The file is held in memory, never written."""
    target = str(args.get("target") or "").strip()
    url = target if "://" in target else "https://" + target
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ToolError("invalid_arguments", "target must be an http(s) URL or hostname")
    method = str(args.get("method") or "POST").upper()
    if method not in {"POST", "PUT", "PATCH"}:
        raise ToolError("invalid_arguments", "upload method must be POST, PUT, or PATCH")
    mission_id = str(args.get("mission_id") or "")
    scope = args.get("scope")
    _require_scope(ctx, target, mission_id, scope, probe=True)

    field = str(args.get("field") or "file").strip()
    filename = str(args.get("filename") or "upload.bin").strip()
    if not field or any(ch in field for ch in "\r\n\"") or not filename \
            or "\r" in filename or "\n" in filename:
        raise ToolError("invalid_arguments", "invalid multipart field or filename")
    raw = args.get("content")
    if raw is None:
        raise ToolError("invalid_arguments", "content is required")
    if args.get("content_base64"):
        try:
            content = base64.b64decode(str(raw), validate=True)
        except ValueError as exc:
            raise ToolError("invalid_arguments", f"content is not valid base64: {exc}")
    else:
        content = str(raw).encode("utf-8")
    if len(content) > 1_048_576:
        raise ToolError("invalid_arguments", "upload is larger than 1 MiB")
    content_type = str(args.get("content_type") or "application/octet-stream")
    form = args.get("form") or {}
    if not isinstance(form, dict):
        raise ToolError("invalid_arguments", "form must be an object")

    headers: dict[str, str] = {"user-agent": "NetCast3r-MCP/0.1", "accept": "*/*"}
    profile_name = str(args.get("auth_profile") or "").strip()
    if profile_name:
        profile = authstore.get_profile(profile_name, base=ctx.base)
        if profile is None:
            raise ToolError("invalid_arguments", f"unknown auth profile: {profile_name}")
        headers.update(profile.request_headers())
    supplied = args.get("headers") or {}
    if not isinstance(supplied, dict):
        raise ToolError("invalid_arguments", "headers must be an object")
    if any(str(name).strip().lower() == "cookie" for name in supplied):
        headers = {key: value for key, value in headers.items()
                   if key.lower() != "cookie"}
    for raw_name, raw_value in supplied.items():
        name = str(raw_name).strip()
        value = str(raw_value)
        if not name or any(char in name for char in "\r\n:") or "\r" in value or "\n" in value:
            raise ToolError("invalid_arguments", f"invalid header: {name[:40]!r}")
        if name.lower() == "content-type":
            continue  # httpx must own the multipart boundary
        headers[name] = value

    maximum = max(1024, min(int(args.get("max_bytes", 65536)), 524288))
    timeout = max(1.0, min(float(args.get("timeout", 30)), 60.0))
    verify_tls = bool(args.get("verify_tls", True))
    started = time.monotonic()
    try:
        with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False,
                          verify=verify_tls) as client:
            with client.stream(
                    method, url, headers=headers,
                    files={field: (filename, content, content_type)},
                    data={str(key): str(value) for key, value in form.items()}) as response:
                chunks, read, truncated = [], 0, False
                for chunk in response.iter_bytes():
                    if read + len(chunk) > maximum:
                        chunks.append(chunk[: maximum - read])
                        truncated = True
                        break
                    chunks.append(chunk)
                    read += len(chunk)
                body = b"".join(chunks).decode("utf-8", "replace")
                response_headers = {}
                set_cookie = []
                for key, value in response.headers.multi_items():
                    lower = key.lower()
                    if lower == "set-cookie":
                        set_cookie.append(value)
                    elif lower in response_headers:
                        response_headers[lower] += ", " + value
                    else:
                        response_headers[lower] = value
                status = response.status_code
    except httpx.HTTPError as exc:
        raise ToolError("request_failed", f"upload failed: {type(exc).__name__}", str(exc))
    return {
        "target": target, "status": status, "headers": response_headers,
        "set_cookie": set_cookie, "body": body, "bytes": len(body),
        "truncated": truncated, "field": field, "filename": filename,
        "uploaded_bytes": len(content),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "note": "The file was held in memory and sent once; no copy was written.",
    }


def oracle_extract(ctx: ToolContext, args: dict) -> dict:
    """Extract a value through a boolean or time-based oracle.

    The caller supplies a template containing ``{{expr}}`` in the URL, a header,
    or the body. For each position and candidate character the tool renders
    ``expr_template`` and sends one scoped probe. This is the missing primitive
    for blind SQL injection, blind command injection, and similar oracles.
    """
    target = str(args.get("target") or "").strip()
    method = str(args.get("method") or "GET").upper()
    if method not in {"GET", "POST", "PUT", "PATCH"}:
        raise ToolError("invalid_arguments", "unsupported method")
    headers = args.get("headers") or {}
    if not isinstance(headers, dict):
        raise ToolError("invalid_arguments", "headers must be an object")
    body = args.get("body")
    if body is not None and not isinstance(body, str):
        raise ToolError("invalid_arguments", "body must be a string")
    target_template = target
    if "{{expr}}" not in target and "{{expr}}" not in str(body or "") \
            and not any("{{expr}}" in str(value) for value in headers.values()):
        raise ToolError("invalid_arguments",
                        "put {{expr}} in the target, a header, or the body")
    true_when = str(args.get("true_when") or "contains").lower()
    if true_when not in {"contains", "not_contains", "status", "time"}:
        raise ToolError("invalid_arguments",
                        "true_when must be contains, not_contains, status, or time")
    match = str(args.get("match") or "")
    if true_when in {"contains", "not_contains"} and not match:
        raise ToolError("invalid_arguments", "match is required for a body oracle")
    expected_status = int(args.get("expected_status") or 200)
    threshold_ms = int(args.get("threshold_ms") or 3000)
    query = str(args.get("query") or "")
    expr_template = str(args.get("expr_template")
                        or "ASCII(SUBSTRING(({query}),{pos},1))={char}")
    charset = str(args.get("charset")
                  or "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    max_length = max(1, min(int(args.get("max_length") or 32), 256))
    position_start = max(1, min(int(args.get("position_start") or 1), 4096))
    max_requests = max(1, min(int(args.get("max_requests") or 600), 2000))
    profile_name = str(args.get("auth_profile") or "").strip()
    mission_id = str(args.get("mission_id") or "")
    scope = args.get("scope")

    extracted = []
    requests = 0
    truncated = False

    def render(expr: str) -> tuple[str, dict, str | None]:
        url = target_template.replace("{{expr}}", quote(expr, safe=""))
        rendered_headers = {str(key): str(value).replace("{{expr}}", expr)
                            for key, value in headers.items()}
        rendered_body = (body.replace("{{expr}}", expr)
                         if isinstance(body, str) else None)
        return url, rendered_headers, rendered_body

    for position in range(position_start, position_start + max_length):
        found = ""
        for char in charset:
            if requests >= max_requests:
                truncated = True
                break
            expr = (expr_template.replace("{query}", query)
                    .replace("{pos}", str(position))
                    .replace("{char}", str(ord(char))))
            url, rendered_headers, rendered_body = render(expr)
            ctx.limiter.check("oracle")
            probe = {
                "target": url, "method": method, "headers": rendered_headers,
                "auth_profile": profile_name, "mission_id": mission_id,
                "scope": scope, "max_bytes": 131072, "timeout": 20,
                "follow_redirects": False,
            }
            if rendered_body is not None:
                probe["body"] = rendered_body
            response = http_request(ctx, probe)
            requests += 1
            status = int(response.get("status") or 0)
            text = str(response.get("body") or "")
            elapsed = int(response.get("elapsed_ms") or 0)
            if true_when == "contains":
                hit = match.lower() in text.lower()
            elif true_when == "not_contains":
                hit = match.lower() not in text.lower()
            elif true_when == "status":
                hit = status == expected_status
            else:
                hit = elapsed >= threshold_ms
            if hit:
                found = char
                break
        if not found:
            break
        extracted.append(found)
        if len(extracted) >= max_length or requests >= max_requests:
            break
    value = "".join(extracted)
    return {
        "target": target, "method": method, "true_when": true_when,
        "value": value, "length": len(value), "requests": requests,
        "max_requests": max_requests, "truncated": truncated,
        "positions": position_start + len(value) - 1 if value else position_start,
        "evidence": (f"extracted {len(value)} character(s) through a "
                     f"{true_when} oracle in {requests} probe(s)"),
        "note": ("Each probe is scope-checked and rate-limited. Stop at the "
                 "minimum value that proves the bug."),
    }


def race_run(ctx: ToolContext, args: dict) -> dict:
    """Send a bounded concurrent burst of the same scoped request.

    This is not a single-packet attack; it is a reproducible concurrent burst
    for check-then-act tests. Every response is kept so the caller can compare
    the invariant instead of trusting one status code.
    """
    target = str(args.get("target") or "").strip()
    url = target if "://" in target else "https://" + target
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ToolError("invalid_arguments", "target must be an http(s) URL or hostname")
    method = str(args.get("method") or "POST").upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
        raise ToolError("invalid_arguments", "unsupported method")
    mission_id = str(args.get("mission_id") or "")
    scope = args.get("scope")
    _require_scope(ctx, target, mission_id, scope, probe=True)

    count = max(2, min(int(args.get("count") or 10), 50))
    concurrency = max(1, min(int(args.get("concurrency") or count), count, 50))
    timeout = max(1.0, min(float(args.get("timeout", 20)), 60.0))
    maximum = max(256, min(int(args.get("max_bytes", 16384)), 65536))
    verify_tls = bool(args.get("verify_tls", True))

    headers: dict[str, str] = {"user-agent": "NetCast3r-MCP/0.1", "accept": "*/*"}
    profile_name = str(args.get("auth_profile") or "").strip()
    if profile_name:
        profile = authstore.get_profile(profile_name, base=ctx.base)
        if profile is None:
            raise ToolError("invalid_arguments", f"unknown auth profile: {profile_name}")
        headers.update(profile.request_headers())
    supplied = args.get("headers") or {}
    if not isinstance(supplied, dict):
        raise ToolError("invalid_arguments", "headers must be an object")
    if any(str(name).strip().lower() == "cookie" for name in supplied):
        headers = {key: value for key, value in headers.items()
                   if key.lower() != "cookie"}
    for raw_name, raw_value in supplied.items():
        name = str(raw_name).strip()
        value = str(raw_value)
        if not name or any(char in name for char in "\r\n:") or "\r" in value or "\n" in value:
            raise ToolError("invalid_arguments", f"invalid header: {name[:40]!r}")
        headers[name] = value

    content: bytes | None = None
    payload_json = args.get("json")
    payload_form = args.get("form")
    raw_body = args.get("body")
    if sum(item is not None for item in (payload_json, payload_form, raw_body)) > 1:
        raise ToolError("invalid_arguments", "use only one of body, json, or form")
    if payload_json is not None:
        content = json.dumps(payload_json).encode("utf-8")
        headers.setdefault("content-type", "application/json")
    elif payload_form is not None:
        content = urlencode(payload_form, doseq=True).encode("utf-8")
        headers.setdefault("content-type", "application/x-www-form-urlencoded")
    elif raw_body is not None:
        content = str(raw_body).encode("utf-8")

    ctx.limiter.check("race")
    started = time.monotonic()

    def send(_index: int) -> dict:
        began = time.monotonic()
        try:
            with httpx.Client(timeout=timeout, trust_env=False,
                              follow_redirects=False,
                              verify=verify_tls) as client:
                with client.stream(method, url, headers=headers,
                                   content=content) as response:
                    chunks, read = [], 0
                    for chunk in response.iter_bytes():
                        if read + len(chunk) > maximum:
                            chunks.append(chunk[: maximum - read])
                            break
                        chunks.append(chunk)
                        read += len(chunk)
                    body = b"".join(chunks)
                    return {
                        "status": response.status_code,
                        "bytes": len(body),
                        "body": body.decode("utf-8", "replace"),
                        "body_sha256": hashlib.sha256(body).hexdigest()[:16],
                        "elapsed_ms": int((time.monotonic() - began) * 1000),
                    }
        except httpx.HTTPError as exc:
            return {"status": 0, "bytes": 0, "body": "",
                    "error": f"{type(exc).__name__}: {exc}",
                    "elapsed_ms": int((time.monotonic() - began) * 1000)}

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        responses = list(pool.map(send, range(count)))
    statuses: dict[str, int] = {}
    shapes: dict[str, int] = {}
    for response in responses:
        statuses[str(response["status"])] = statuses.get(
            str(response["status"]), 0) + 1
        shapes[response["body_sha256"]] = shapes.get(
            response["body_sha256"], 0) + 1
    return {
        "target": target, "method": method, "count": count,
        "concurrency": concurrency, "responses": responses,
        "statuses": statuses, "body_shapes": shapes,
        "distinct_statuses": len(statuses),
        "distinct_bodies": len(shapes),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "note": ("A duplicate side effect is the proof. Compare the invariant "
                 "before and after; a different status is only a lead."),
    }


def rea_analyze(ctx: ToolContext, args: dict) -> dict:
    path = str(args.get("path") or "").strip()
    if not path:
        raise ToolError("invalid_arguments", "path is required")
    kind = str(args.get("kind") or "auto").strip().lower()
    try:
        return reveng.rea_plan(
            path, kind=kind, goal=str(args.get("goal") or ""),
            max_files=args.get("max_files", 4000),
            timeout=args.get("timeout", 240),
            keep=bool(args.get("keep", False)))
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))
    except OSError as exc:
        raise ToolError("read_failed", f"could not read the artifact: {exc.strerror or exc}")


def reveng_analyze(ctx: ToolContext, args: dict) -> dict:
    """Analyze a local artifact the operator legitimately holds.

    Nothing leaves the machine and nothing is executed. The result is a set of
    leads with file and line numbers; a finding is still recorded separately
    after it is confirmed against the live target.
    """
    path = str(args.get("path") or "").strip()
    if not path:
        raise ToolError("invalid_arguments", "path is required")
    kind = str(args.get("kind") or "auto").strip().lower()
    options = {
        "max_files": args.get("max_files", 4000),
        "timeout": args.get("timeout", 240),
        "keep": bool(args.get("keep", False)),
    }
    try:
        result = reveng.analyze(kind, path, **options)
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))
    except OSError as exc:
        raise ToolError("read_failed", f"could not read the artifact: {exc.strerror or exc}")
    if args.get("markdown"):
        result["report_markdown"] = reveng.render_markdown(result)
    return result


def http_path_diff(ctx: ToolContext, args: dict) -> dict:
    """Compare a baseline request with a bounded set of path variants.

    Authorization layers and routers often disagree about percent-encoding.
    This sends the same request to literal, encoded, case-varied, and
    slash-varied paths, then labels where the responses diverge. Non-safe
    methods are refused unless the caller explicitly opts in, because replaying
    a POST against a handler can create state.
    """
    target = str(args.get("target") or "").strip()
    url = target if "://" in target else "https://" + target
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ToolError("invalid_arguments", "target must be an http(s) URL or hostname")
    method = str(args.get("method", "GET")).upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ToolError("invalid_arguments", "unsupported method")
    if method not in {"GET", "HEAD", "OPTIONS"} and not args.get("allow_unsafe_method"):
        raise ToolError("invalid_arguments",
                        "non-safe methods can create state; set allow_unsafe_method=true "
                        "only when replaying the request is safe")
    mission_id = str(args.get("mission_id") or "")
    scope = args.get("scope")
    _require_scope(ctx, target, mission_id, scope, probe=True)

    limit = max(2, min(int(args.get("max_variants", 12)), pathdiff.MAX_VARIANTS))
    delay = max(0.0, min(float(args.get("delay", 0.2)), 2.0))
    variants = pathdiff.build_variants(parts.path or "/", limit=limit)
    shared = {
        "method": method,
        "mission_id": mission_id,
        "scope": scope,
        "auth_profile": args.get("auth_profile", ""),
        "headers": args.get("headers") or {},
        "body": args.get("body"),
        "json": args.get("json"),
        "form": args.get("form"),
        "max_bytes": args.get("max_bytes", 32768),
        "timeout": args.get("timeout", 15),
        "follow_redirects": bool(args.get("follow_redirects", False)),
        "verify_tls": bool(args.get("verify_tls", True)),
    }
    rows: list[dict] = []
    baseline: dict = {}
    for index, variant in enumerate(variants):
        if index:
            time.sleep(delay)
        call_args = {**shared, "target": pathdiff.target_for(url, variant["path"])}
        try:
            response = http_request(ctx, call_args)
        except ToolError as exc:
            rows.append({"label": variant["label"], "path": variant["path"],
                         "status": 0, "bytes": 0, "body": "",
                         "error": f"{exc.code}: {exc.message}"})
            continue
        row = {
            "label": variant["label"],
            "path": variant["path"],
            "status": response.get("status", 0),
            "bytes": response.get("bytes", 0),
            "body": response.get("body", ""),
            "body_hash": pathdiff._digest(response.get("body", "")),
            "url": response.get("url", ""),
        }
        if variant["label"] == "baseline":
            baseline = row
        rows.append(row)

    if not baseline:
        raise ToolError("request_failed", "the baseline request did not return a response")
    comparison = pathdiff.compare(baseline, rows)
    comparison["target"] = url
    comparison["method"] = method
    comparison["requests"] = len(rows)
    comparison["auth_profile"] = args.get("auth_profile", "")
    return comparison


def inbox_create(ctx: ToolContext, args: dict) -> dict:
    try:
        box = tempmail.create_mailbox(
            base=ctx.base, domain=str(args.get("domain") or ""),
            prefix=str(args.get("prefix") or "nc3r"),
            provider=str(args.get("provider") or "mail.tm"))
    except tempmail.MailError as exc:
        raise ToolError("mailbox_failed", str(exc))
    return {"mailbox": box.public()}


def inbox_providers(ctx: ToolContext, args: dict) -> dict:
    return {
        "items": [
            {"provider": "mail.tm", "mode": "password", "custom_domain": True},
            {"provider": "guerrillamail", "mode": "session", "custom_domain": False},
        ],
        "default": "mail.tm",
        "note": "Some programs reject disposable domains; record the block and use "
                "the browser session for a human-owned address instead.",
    }


def inbox_list(ctx: ToolContext, args: dict) -> dict:
    items = tempmail.list_mailboxes(base=ctx.base)
    return {"items": items, "total": len(items)}


def inbox_read(ctx: ToolContext, args: dict) -> dict:
    box = tempmail.get_mailbox(args["mailbox_id"], base=ctx.base)
    if box is None:
        raise ToolError("not_found", "mailbox not found")
    try:
        client = tempmail.client_for(box)
        if args.get("message_id"):
            return {"message": client.read(box, str(args["message_id"]), base=ctx.base)}
        return {"mailbox": box.public(), "items": client.messages(box, base=ctx.base)}
    except tempmail.MailError as exc:
        raise ToolError("mailbox_failed", str(exc))


def inbox_wait(ctx: ToolContext, args: dict) -> dict:
    box = tempmail.get_mailbox(args["mailbox_id"], base=ctx.base)
    if box is None:
        raise ToolError("not_found", "mailbox not found")
    try:
        message = tempmail.client_for(box).wait(
            box, base=ctx.base, timeout=args.get("timeout", 180),
            interval=args.get("interval", 4), match=str(args.get("match") or ""),
            since_id=str(args.get("since_id") or ""))
    except tempmail.MailError as exc:
        raise ToolError("mailbox_failed", str(exc))
    return {"found": message is not None, "message": message}


def oast_create(ctx: ToolContext, args: dict) -> dict:
    try:
        session = oast.create_session(base=ctx.base, label=str(args.get("label") or ""))
    except oast.OastError as exc:
        raise ToolError("callback_failed", str(exc))
    return {"session": session.public()}


def oast_list(ctx: ToolContext, args: dict) -> dict:
    items = oast.list_sessions(base=ctx.base)
    return {"items": items, "total": len(items)}


def oast_poll(ctx: ToolContext, args: dict) -> dict:
    session = oast.get_session(args["session_id"], base=ctx.base)
    if session is None:
        raise ToolError("not_found", "callback session not found")
    try:
        items = oast.OastClient(base_url=session.base_url).poll(
            session, base=ctx.base, since=args.get("since"),
            limit=args.get("limit", 50))
    except oast.OastError as exc:
        raise ToolError("callback_failed", str(exc))
    cursor = max((item.get("created_at") or 0) for item in items) if items else args.get("since", 0)
    return {"session": session.public(), "items": items, "total": len(items),
            "cursor": cursor}


def oast_delete(ctx: ToolContext, args: dict) -> dict:
    session = oast.get_session(args["session_id"], base=ctx.base)
    if session is None:
        raise ToolError("not_found", "callback session not found")
    try:
        removed = oast.OastClient(base_url=session.base_url).delete(session, base=ctx.base)
    except oast.OastError as exc:
        raise ToolError("callback_failed", str(exc))
    return {"session_id": session.id, "deleted": removed}


def auth_profile_set(ctx: ToolContext, args: dict) -> dict:
    try:
        profile = authstore.set_profile(
            args["name"], headers=args.get("headers"), cookies=args.get("cookies"),
            note=str(args.get("note") or ""), base=ctx.base)
    except authstore.AuthError as exc:
        raise ToolError("invalid_arguments", str(exc))
    return {"profile": profile}


def auth_profile_list(ctx: ToolContext, args: dict) -> dict:
    items = authstore.list_profiles(base=ctx.base)
    return {"items": items, "total": len(items)}


def auth_profile_delete(ctx: ToolContext, args: dict) -> dict:
    removed = authstore.delete_profile(args["name"], base=ctx.base)
    if not removed:
        raise ToolError("not_found", "auth profile not found")
    return {"name": args["name"], "deleted": True}


def auth_profile_import(ctx: ToolContext, args: dict) -> dict:
    try:
        profile = authstore.from_storage_state(
            args["path"], args["name"], domain=str(args.get("domain") or ""),
            base=ctx.base)
    except authstore.AuthError as exc:
        raise ToolError("invalid_arguments", str(exc))
    return {"profile": profile}


# -- browser --------------------------------------------------------------

def _browser_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except browser.BrowserError as exc:
        raise ToolError("browser_error", str(exc), exc.detail)


def _browser_scope(ctx: ToolContext, url: str, mission_id: str, scope,
                   purpose: str = "target") -> None:
    if not url or url == "about:blank":
        return
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ToolError("invalid_arguments", "url must be http(s) or about:blank")
    host = (parts.hostname or "").lower().rstrip(".")
    if purpose == "identity":
        if not any(host == allowed or host.endswith("." + allowed)
                   for allowed in IDENTITY_HOSTS):
            raise ToolError("scope_denied",
                            f"{host} is not a recognised identity provider",
                            "use purpose=target for ordinary navigation")
        return
    _require_scope(ctx, url, mission_id, scope, probe=True)


def browser_open(ctx: ToolContext, args: dict) -> dict:
    url = str(args.get("url") or "about:blank").strip()
    _browser_scope(ctx, url, str(args.get("mission_id") or ""), args.get("scope"),
                   str(args.get("purpose") or "target"))
    result = _browser_call(browser.launch, args["profile"], url, base=ctx.base,
                           headless=bool(args.get("headless")))
    return {"browser": result}


def browser_status(ctx: ToolContext, args: dict) -> dict:
    return {"browser": _browser_call(browser.status, args["profile"], base=ctx.base)}


def browser_list(ctx: ToolContext, args: dict) -> dict:
    items = _browser_call(browser.profiles, base=ctx.base)
    return {"items": items, "total": len(items)}


def browser_goto(ctx: ToolContext, args: dict) -> dict:
    url = str(args["url"]).strip()
    _browser_scope(ctx, url, str(args.get("mission_id") or ""), args.get("scope"),
                   str(args.get("purpose") or "target"))
    result = _browser_call(browser.goto, args["profile"], url, base=ctx.base,
                           timeout=int(args.get("timeout") or browser.DEFAULT_TIMEOUT))
    return {"page": result}


def browser_snapshot(ctx: ToolContext, args: dict) -> dict:
    return _browser_call(browser.snapshot, args["profile"], base=ctx.base,
                         include_text=bool(args.get("include_text", True)))


def browser_click(ctx: ToolContext, args: dict) -> dict:
    return _browser_call(browser.click, args["profile"], base=ctx.base,
                         ref=str(args.get("ref") or ""),
                         selector=str(args.get("selector") or ""),
                         button=str(args.get("button") or "left"),
                         timeout=int(args.get("timeout") or 10_000))


def browser_type(ctx: ToolContext, args: dict) -> dict:
    return _browser_call(browser.type_text, args["profile"], args["text"],
                         base=ctx.base, ref=str(args.get("ref") or ""),
                         selector=str(args.get("selector") or ""),
                         submit=bool(args.get("submit")),
                         clear=bool(args.get("clear", True)),
                         timeout=int(args.get("timeout") or 10_000))


def browser_press(ctx: ToolContext, args: dict) -> dict:
    return _browser_call(browser.press, args["profile"], args["key"], base=ctx.base,
                         ref=str(args.get("ref") or ""),
                         selector=str(args.get("selector") or ""))


def browser_wait(ctx: ToolContext, args: dict) -> dict:
    return _browser_call(browser.wait, args["profile"], base=ctx.base,
                         until=str(args.get("until") or "time"),
                         value=str(args.get("value") or ""),
                         timeout=int(args.get("timeout") or 30_000))


def browser_screenshot(ctx: ToolContext, args: dict) -> dict:
    return _browser_call(browser.screenshot, args["profile"], base=ctx.base,
                         full_page=bool(args.get("full_page")))


def browser_capture(ctx: ToolContext, args: dict) -> dict:
    return _browser_call(browser.capture, args["profile"], args["name"],
                         base=ctx.base, domain=str(args.get("domain") or ""),
                         storage_key=str(args.get("storage_key") or ""),
                         header=str(args.get("header") or ""))


def browser_eval(ctx: ToolContext, args: dict) -> dict:
    result = _browser_call(browser.evaluate, args["profile"], args["expression"],
                           base=ctx.base)
    return {"result": result}


def browser_close(ctx: ToolContext, args: dict) -> dict:
    return _browser_call(browser.close, args["profile"], base=ctx.base)


def tool_calls_list(ctx: ToolContext, args: dict) -> dict:
    return _call(ctx, "GET", "/api/v1/tool-calls", {
        "tool": args.get("tool", ""), "status": args.get("status", ""),
        "mission_id": args.get("mission_id", ""), "run_id": args.get("run_id", ""),
        "size": args.get("limit", 50), "page": args.get("page", 1)})


# -- registry -------------------------------------------------------------

_HANDLERS = {name[5:]: value for name, value in globals().items() if name.startswith("tool_")}
_HANDLERS.update({
    "missions_list": missions_list,
    "missions_get": missions_get,
    "missions_create": missions_create,
    "missions_update": missions_update,
    "missions_delete": missions_delete,
    "missions_attach_run": missions_attach_run,
    "mission_start_run": mission_start_run,
    "agent_status": agent_status,
    "agent_start": agent_start,
    "agent_pause": agent_pause,
    "agent_resume": agent_resume,
    "agent_stop": agent_stop,
    "scan_start": scan_start,
    "runs_list": runs_list,
    "runs_get": runs_get,
    "runs_events": runs_events,
    "runs_stop": runs_stop,
    "runs_resume": runs_resume,
    "runs_delete": runs_delete,
    "runs_report": runs_report,
    "runs_inventory": runs_inventory,
    "findings_list": findings_list,
    "findings_get": findings_get,
    "findings_summary": findings_summary,
    "findings_create": findings_create,
    "finding_artifact_add": finding_artifact_add,
    "finding_artifact_list": finding_artifact_list,
    "finding_artifact_get": finding_artifact_get,
    "report_quality": report_quality,
    "program_rank": program_rank,
    "stix_export": stix_export,
    "surface_diff": surface_diff,
    "self_audit": self_audit,
    "diagnostics": diagnostics,
    "expertise_profile": expertise_profile,
    "taxii_collections": taxii_collections,
    "taxii_poll": taxii_poll,
    "recon_passive": recon_passive,
    "fetch_artifact": fetch_artifact,
    "test_case_run": test_case_run,
    "hypothesis_create": hypothesis_create,
    "hypothesis_list": hypothesis_list,
    "hypothesis_get": hypothesis_get,
    "hypothesis_test": hypothesis_test,
    "hypothesis_promote": hypothesis_promote,
    "training_plan": training_plan,
    "training_status": training_status,
    "training_sources": training_sources,
    "training_record": training_record,
    "training_verify": training_verify,
    "skill_packs": skill_packs,
    "ui_audit": ui_audit,
    "technique_search": technique_search,
    "technique_plan": technique_plan,
    "research_sources": research_sources,
    "research_ingest": research_ingest,
    "hunt_plan": hunt_plan,
    "selfmodel_snapshot": selfmodel_snapshot,
    "selfmodel_gaps": selfmodel_gaps,
    "selfmodel_evolve": selfmodel_evolve,
    "upgrade_propose": upgrade_propose,
    "upgrade_list": upgrade_list,
    "upgrade_update": upgrade_update,
    "toolbook": toolbook,
    "burp_status": burp_status,
    "burp_call": burp_call,
    "mcp_servers_list": mcp_servers_list,
    "sandbox_run": sandbox_run,
    "mcp_server_tools": mcp_server_tools,
    "mcp_server_call": mcp_server_call,
    "token_pivot": token_pivot,
    "threatintel_query": threatintel_query,
    "threatintel_cve": threatintel_cve,
    "threatintel_repro": threatintel_repro,
    "lessons_record": lessons_record,
    "lessons_list": lessons_list,
    "lessons_get": lessons_get,
    "lesson_reflect": lesson_reflect,
    "skills_list": skills_list,
    "skills_get": skills_get,
    "skills_upsert": skills_upsert,
    "skills_use": skills_use,
    "skills_status": skills_status,
    "next_actions": next_actions,
    "finding_triage": finding_triage,
    "submissions_list": submissions_list,
    "submissions_get": submissions_get,
    "submissions_summary": submissions_summary,
    "submissions_create": submissions_create,
    "submissions_update": submissions_update,
    "submissions_delete": submissions_delete,
    "approvals_list": approvals_list,
    "approval_request": approval_request,
    "approval_decide": approval_decide,
    "providers_list": providers_list,
    "provider_test": provider_test,
    "scope_check": scope_check,
    "http_probe": http_probe,
    "http_request": http_request,
    "http_upload": http_upload,
    "oracle_extract": oracle_extract,
    "race_run": race_run,
    "http_path_diff": http_path_diff,
    "reveng_analyze": reveng_analyze,
    "rea_analyze": rea_analyze,
    "inbox_create": inbox_create,
    "inbox_providers": inbox_providers,
    "inbox_list": inbox_list,
    "inbox_read": inbox_read,
    "inbox_wait": inbox_wait,
    "oast_create": oast_create,
    "oast_list": oast_list,
    "oast_poll": oast_poll,
    "oast_delete": oast_delete,
    "auth_profile_set": auth_profile_set,
    "auth_profile_list": auth_profile_list,
    "auth_profile_delete": auth_profile_delete,
    "auth_profile_import": auth_profile_import,
    "browser_open": browser_open,
    "browser_status": browser_status,
    "browser_list": browser_list,
    "browser_goto": browser_goto,
    "browser_snapshot": browser_snapshot,
    "browser_click": browser_click,
    "browser_type": browser_type,
    "browser_press": browser_press,
    "browser_wait": browser_wait,
    "browser_screenshot": browser_screenshot,
    "browser_capture": browser_capture,
    "browser_eval": browser_eval,
    "browser_close": browser_close,
    "tool_calls_list": tool_calls_list,
    "status": tool_status,
})


TOOLS: tuple[Tool, ...] = (
    Tool("status", "Workspace status",
         "Show the control-plane version, aggregate counters, active runs, and the "
         "policy this MCP server is enforcing.", "low", "workspace",
         _schema({}), "status", read_only=True),
    Tool("missions_list", "List missions",
         "List missions with run, finding, and pending-approval counts. Filter by status.",
         "low", "missions",
         _schema({"status": _string("draft, active, paused, done, or archived", enum=[
             "draft", "active", "paused", "done", "archived"]),
                  "limit": _integer("page size", 1, 200, 50),
                  "page": _integer("page number", 1)}), "missions_list", read_only=True),
    Tool("missions_get", "Get mission",
         "Fetch one mission with its linked runs.", "low", "missions",
         _schema({"mission_id": _string("mission id")}, ["mission_id"]),
         "missions_get", read_only=True),
    Tool("missions_create", "Create mission",
         "Create a mission. The target is recorded as the authorization boundary for "
         "later active tools; scope entries may include '!host' exclusions.",
         "medium", "missions",
         _schema({
             "title": _string("mission title"),
             "target": _string("primary target host or URL"),
             "objective": _string("what the mission is trying to prove"),
             "status": _string("initial status", enum=["draft", "active"]),
             "autonomy": _string("autonomy level", enum=["manual", "supervised", "autonomous"]),
             "budget": _object("budget object, e.g. {\"max_usd\": 25}"),
             "scope": _array("scope entries; '!host' is an exclusion"),
             "plan": _array("planned steps", {"type": "object"}),
         }, ["title", "target"]), "missions_create"),
    Tool("missions_update", "Update mission",
         "Change mission fields or status. Marking a mission done stamps its finish time.",
         "medium", "missions",
         _schema({
             "mission_id": _string("mission id"),
             "title": _string("new title"),
             "target": _string("new target"),
             "objective": _string("new objective"),
             "status": _string("new status", enum=["draft", "active", "paused", "done", "archived"]),
             "autonomy": _string("autonomy level", enum=["manual", "supervised", "autonomous"]),
             "budget": _object("budget object"),
             "scope": _array("scope entries"),
             "plan": _array("planned steps", {"type": "object"}),
         }, ["mission_id"]), "missions_update"),
    Tool("missions_delete", "Delete mission",
         "Delete a mission, its run links, and its approvals. Evidence files stay on disk. "
         "High risk: needs an approved approval in supervised mode.",
         "high", "missions",
         _schema({"mission_id": _string("mission id"),
                  "approval_id": _string("approved approval id"),
                  "confirm": _boolean("explicit confirmation (full policy)")},
                 ["mission_id"]), "missions_delete", destructive=True),
    Tool("missions_attach_run", "Attach run to mission",
         "Link an existing run to a mission without starting a new scan.",
         "medium", "missions",
         _schema({"mission_id": _string("mission id"), "run_id": _string("run id")},
                 ["mission_id", "run_id"]), "missions_attach_run"),
    Tool("mission_start_run", "Start mission scan",
         "Start a scan for a mission. The target must match the mission scope. "
         "The mission becomes active and the run is linked automatically.",
         "medium", "missions",
         _schema({"mission_id": _string("mission id"),
                  "target": _string("optional target override, must be in scope"),
                  "options": _object("scan options: depth, tier, rate, timeout, ...")},
                 ["mission_id"]), "mission_start_run", open_world=True),
    Tool("agent_status", "Mission agent status",
         "Read the bounded mission runtime: state, plan, task timeline, independent "
         "verification, budget use, and model calls. Read-only.",
         "low", "missions",
         _schema({"mission_id": _string("mission id")}, ["mission_id"]),
         "agent_status", read_only=True),
    Tool("agent_start", "Start mission agent",
         "Plan and run the bounded mission agent: scope check, one live probe, an "
         "inventory of existing evidence, an optional model analysis, and an "
         "independent verifier. Every action is a typed, audited tool call. The "
         "runtime never creates a finding, widens scope, or spends an approval.",
         "medium", "missions",
         _schema({"mission_id": _string("mission id"),
                  "use_model": _boolean("ask a model for one advisory analysis"),
                  "max_tasks": _integer("task cap", 4, 20, 8),
                  "max_seconds": _integer("wall-clock cap in seconds", 30, 7200, 600),
                  "max_model_calls": _integer("model call cap", 0, 20, 2),
                  "role": {"type": "string",
                           "enum": ["recon", "auth", "api", "validator", "reporter",
                                    "training"],
                           "default": "recon"},
                  "allow_manual": _boolean("allow a manual-autonomy mission to run"),
                  "restart": _boolean("replace an interrupted or finished plan")},
                 ["mission_id"]), "agent_start", open_world=True),
    Tool("agent_pause", "Pause mission agent",
         "Pause after the current task. The durable task list and evidence stay put.",
         "low", "missions",
         _schema({"mission_id": _string("mission id")}, ["mission_id"]),
         "agent_pause"),
    Tool("agent_resume", "Resume mission agent",
         "Continue a paused or interrupted plan from its first unfinished task.",
         "low", "missions",
         _schema({"mission_id": _string("mission id")}, ["mission_id"]),
         "agent_resume"),
    Tool("agent_stop", "Stop mission agent",
         "Cooperatively stop the mission runtime. Pending tasks are marked skipped and "
         "the stop is audited. Always low risk so any policy can kill a run.",
         "low", "missions",
         _schema({"mission_id": _string("mission id")}, ["mission_id"]),
         "agent_stop"),
    Tool("scan_start", "Start ad-hoc scan",
         "Start a scan. Requires a mission_id or an explicit scope list; a bare target "
         "is refused. Options are whitelisted and bounded.",
         "medium", "runs",
         _schema({"target": _string("target host or URL"),
                  "mission_id": _string("mission whose scope authorizes this scan"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "options": _object("scan options: depth, tier, rate, timeout, ...")},
                 ["target"]), "scan_start", open_world=True),
    Tool("runs_list", "List runs",
         "List scans, newest first, optionally filtered by status or target.",
         "low", "runs",
         _schema({"status": _string("queued, running, done, stopped, or error"),
                  "q": _string("target substring"),
                  "limit": _integer("page size", 1, 200, 50),
                  "page": _integer("page number", 1)}), "runs_list", read_only=True),
    Tool("runs_get", "Get run", "Fetch one run with options and counters.",
         "low", "runs", _schema({"run_id": _string("run id")}, ["run_id"]),
         "runs_get", read_only=True),
    Tool("runs_events", "Read run events",
         "Read the persisted event log for a run, optionally after a sequence number.",
         "low", "runs",
         _schema({"run_id": _string("run id"), "since": _integer("last seen sequence", 0)}),
         "runs_events", read_only=True),
    Tool("runs_stop", "Stop run", "Cooperatively stop an active run.",
         "medium", "runs", _schema({"run_id": _string("run id")}, ["run_id"]),
         "runs_stop", destructive=True),
    Tool("runs_resume", "Resume run",
         "Start a resume run from a finished run's checkpoint and evidence store.",
         "medium", "runs", _schema({"run_id": _string("parent run id")}, ["run_id"]),
         "runs_resume", open_world=True),
    Tool("runs_delete", "Delete run",
         "Delete a run, its findings, events, and (when no other run uses it) its evidence "
         "directory. High risk: needs an approved approval in supervised mode.",
         "high", "runs",
         _schema({"run_id": _string("run id"), "approval_id": _string("approved approval id"),
                  "confirm": _boolean("explicit confirmation (full policy)")},
                 ["run_id"]), "runs_delete", destructive=True),
    Tool("runs_report", "Read run report",
         "Read the Markdown report a run wrote, bounded by max_chars.",
         "low", "runs",
         _schema({"run_id": _string("run id"),
                  "max_chars": _integer("character cap", 1000, 500000, 200000)},
                 ["run_id"]), "runs_report", read_only=True),
    Tool("runs_inventory", "Read run inventory",
         "Read one evidence slice for a run: pages, js, endpoints, secrets, candidates, "
         "validations, reviews, findings, stages, or subdomains.",
         "low", "runs",
         _schema({"run_id": _string("run id"),
                  "kind": _string("inventory kind", enum=[
                      "subdomains", "pages", "assets", "js", "endpoints", "secrets",
                      "candidates", "validations", "corroborations", "reviews",
                      "findings", "stages"]),
                  "limit": _integer("row cap", 1, 5000, 500)},
                 ["run_id"]), "runs_inventory", read_only=True),
    Tool("findings_list", "List findings",
         "List findings with filters. Values are already masked by the index.",
         "low", "findings",
         _schema({"run_id": _string("run id"), "severity": _string("severity filter"),
                  "status": _string("triage status filter"), "q": _string("search text"),
                  "sort": _string("created_at, severity, confidence, or title"),
                  "limit": _integer("page size", 1, 200, 50),
                  "page": _integer("page number", 1)}), "findings_list", read_only=True),
    Tool("findings_get", "Get finding", "Fetch one finding and its triage state.",
         "low", "findings",
         _schema({"finding_id": _string("finding id")}, ["finding_id"]),
         "findings_get", read_only=True),
    Tool("findings_summary", "Finding summary",
         "Severity and triage counts for one run, or for the whole workspace.",
         "low", "findings",
         _schema({"run_id": _string("optional run id")}), "findings_summary", read_only=True),
    Tool("findings_create", "Record finding",
         "Record a finding you validated, with the evidence you can defend. A finding "
         "is never inferred from a scan or a model response; it exists only when an "
         "operator or agent writes it down. Secret values are masked before storage.",
         "medium", "findings",
         _schema({"title": _string("finding title"),
                  "severity": _string("validated severity", enum=[
                      "critical", "high", "medium", "low", "info", "unknown"]),
                  "run_id": _string("optional run id"),
                  "impact": _string("impact statement"),
                  "evidence": _string("evidence paths or a short summary"),
                  "source": _string("tool, module, or manual test that produced it"),
                  "secret_type": _string("finding type, e.g. manual, idor, auth_bypass"),
                  "value": _string("secret value; masked at storage"),
                  "confidence": {"type": "number", "description": "0 to 1",
                                 "minimum": 0, "maximum": 1},
                  "tags": _array("tags"),
                  "notes": _string("private notes"),
                  "fingerprint": _string("optional stable fingerprint for dedupe")},
                 ["title", "severity"]), "findings_create"),
    Tool("finding_artifact_add", "Attach evidence",
         "Store a text or base64 evidence file with a finding. Files are written 0600 "
         "under the NetCast3r base directory, hashed, and listed with a download URL. "
         "Use this for PoC logs, screenshots, and request captures so the finding keeps "
         "its own evidence after the conversation ends.",
         "medium", "findings",
         _schema({"finding_id": _string("finding id"),
                  "name": _string("file name"),
                  "content": _string("text, or base64 when encoding=base64"),
                  "encoding": _string("text or base64", enum=["text", "base64"]),
                  "content_type": _string("MIME type")},
                 ["finding_id", "name", "content"]), "finding_artifact_add"),
    Tool("finding_artifact_list", "List evidence",
         "List the evidence files attached to a finding.",
         "low", "findings",
         _schema({"finding_id": _string("finding id")}, ["finding_id"]),
         "finding_artifact_list", read_only=True),
    Tool("finding_artifact_get", "Read evidence",
         "Return one artifact with its content (text, or base64 for binary files) and "
         "its hash.",
         "low", "findings",
         _schema({"finding_id": _string("finding id"),
                  "artifact_id": _string("artifact id")},
                 ["finding_id", "artifact_id"]), "finding_artifact_get", read_only=True),
    Tool("report_quality", "Score a report",
         "Score one finding's report completeness from stored fields and evidence "
         "artifacts, and list what is missing. This measures the report, not whether "
         "the bug is valid or payable.",
         "low", "findings",
         _schema({"finding_id": _string("finding id")}, ["finding_id"]),
         "report_quality", read_only=True),
    Tool("program_rank", "Rank programs by recorded payout",
         "Aggregate the submission ledger by program, platform, and currency: real "
         "submissions, acceptances, paid rows, and bounty totals. No estimates and no "
         "currency conversion.",
         "low", "reports", _schema({}), "program_rank", read_only=True),
    Tool("surface_diff", "Diff two runs",
         "Compare the per-run inventories of two runs: subdomains, assets, JavaScript, "
         "endpoints, secret candidates, and findings added, removed, or changed. This is "
         "the continuous-monitoring primitive; it reads stored runs only.",
         "low", "runs",
         _schema({"run_id": _string("base run id"),
                  "against": _string("newer run id to compare"),
                  "limit": _integer("sample cap per category", 1, 1000, 200)},
                 ["run_id", "against"]), "surface_diff", read_only=True),
    Tool("self_audit", "Audit NetCast3r itself",
         "Check the local control plane's file permissions, secret-bearing state files, "
         "remote MCP configuration, remote-access switch, and posture. Read-only; does not "
         "scan the host or network.",
         "low", "workspace", _schema({}), "self_audit", read_only=True),
    Tool("diagnostics", "Run diagnostics",
         "Check SQLite integrity, table counts, file modes, route count, and tool count. "
         "Read-only and local.",
         "low", "workspace", _schema({}), "diagnostics", read_only=True),
    Tool("expertise_profile", "Show technology expertise",
         "Show this instance's per-technology exposure and success profile, derived only "
         "from recorded lessons. Different researchers build different expertise.",
         "low", "learning",
         _schema({"limit": _integer("technology cap", 1, 200, 50)}),
         "expertise_profile", read_only=True),
    Tool("stix_export", "Export findings as STIX 2.1",
         "Export findings as a STIX 2.1 bundle: an identity, one vulnerability object per "
         "finding with its CVE reference when present, and a report. No indicators are "
         "invented from scanner lines.",
         "low", "threat-intel",
         _schema({"mission_id": _string("optional mission id"),
                  "severity": _string("optional severity filter"),
                  "limit": _integer("finding cap", 1, 1000, 100)}),
         "stix_export", read_only=True),
    Tool("taxii_collections", "List TAXII collections",
         "Discover a configured TAXII 2.1 server and list its collections. Configure "
         "taxii.url (and token or user/password) in ~/.netcast3r/integrations.json.",
         "medium", "threat-intel",
         _schema({"api_root": _string("optional TAXII API root URL")}),
         "taxii_collections", open_world=True),
    Tool("taxii_poll", "Poll a TAXII collection",
         "Read objects from one TAXII 2.1 collection, optionally after a timestamp. "
         "Read-only; pushing to a remote server is a separate approved action.",
         "medium", "threat-intel",
         _schema({"api_root": _string("TAXII API root URL"),
                  "collection_id": _string("collection id"),
                  "added_after": _string("ISO timestamp cursor"),
                  "limit": _integer("object cap", 1, 1000, 100)},
                 ["api_root", "collection_id"]), "taxii_poll", open_world=True),
    Tool("recon_passive", "Passive recon tool",
         "Run an allowlisted passive tool (subfinder, httpx, katana, whatweb, gau, "
         "waybackurls) against one in-scope target. The command is fixed and run "
         "without a shell; output is bounded. Treat the output as leads.",
         "medium", "recon",
         _schema({"tool": _string("passive tool", enum=[
                     "subfinder", "httpx", "katana", "whatweb", "gau", "waybackurls"]),
                  "target": _string("in-scope domain or URL"),
                  "mission_id": _string("mission whose scope authorizes the run"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "timeout": _integer("timeout in seconds", 10, 600, 180)},
                 ["tool", "target"]), "recon_passive", open_world=True),
    Tool("fetch_artifact", "Fetch an artifact",
         "Download one in-scope URL to a local file under ~/.netcast3r/downloads/ so a "
         "reverse-engineering tool can read it past the response cap. The file is never "
         "executed. Scope is checked first; TLS verification can be disabled only for an "
         "authorized self-signed target.",
         "medium", "reverse-engineering",
         _schema({"target": _string("in-scope URL to download"),
                  "name": _string("local file name"),
                  "mission_id": _string("mission whose scope authorizes the download"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "auth_profile": _string("stored auth profile name"),
                  "verify_tls": _boolean("verify the target certificate (default true)", True),
                  "max_bytes": _integer("download cap", 1024, 20971520, 10485760),
                  "timeout": _integer("timeout in seconds", 1, 120, 30)},
                 ["target"]), "fetch_artifact", open_world=True),
    Tool("test_case_run", "Run a precise test case",
         "Run up to 12 ordered requests with explicit assertions on status, body, and "
         "headers. This is the manual precision path: no scanner, no guess. Each step is "
         "scope-checked and recorded with its raw response sample.",
         "medium", "web",
         _schema({"name": _string("test case name"),
                  "mission_id": _string("mission whose scope authorizes the steps"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "base_url": _string("optional base URL"),
                  "fail_fast": _boolean("stop at the first failed assertion", True),
                  "steps": _array("ordered steps", {"type": "object"})},
                 ["steps"]), "test_case_run", open_world=True),
    Tool("hypothesis_create", "Record a falsifiable hypothesis",
         "Write down one precise question about one in-scope target: the technique, "
         "why it should work here, and the observation that would support it. A "
         "hypothesis is not a finding and is never inferred from a scan.",
         "low", "findings",
         _schema({"title": _string("what you are testing"),
                  "target": _string("in-scope URL or host"),
                  "mission_id": _string("mission that owns this hypothesis"),
                  "technique": _string("technique or bug class"),
                  "rationale": _string("why this target should be vulnerable"),
                  "expected": _string("observation that would support it")},
                 ["title"]), "hypothesis_create"),
    Tool("hypothesis_list", "List hypotheses",
         "List recorded hypotheses, optionally filtered by mission, status, or text.",
         "low", "findings",
         _schema({"mission_id": _string("filter by mission"),
                  "status": _string("filter by status", enum=[
                      "open", "supported", "refuted", "inconclusive",
                      "promoted", "archived"]),
                  "q": _string("text filter"),
                  "limit": _integer("page size", 1, 200, 50),
                  "offset": _integer("offset", 0, 100000, 0)}),
         "hypothesis_list", read_only=True),
    Tool("hypothesis_get", "Get a hypothesis",
         "Read one hypothesis with its stored test and result.",
         "low", "findings",
         _schema({"hypothesis_id": _string("hypothesis id")}, ["hypothesis_id"]),
         "hypothesis_get", read_only=True),
    Tool("hypothesis_test", "Test a hypothesis",
         "Run the hypothesis as an explicit assertion-based test case (same engine as "
         "test_case_run), store the raw result, and mark it supported, refuted, or "
         "inconclusive. Requests are scope-checked by the mission.",
         "medium", "findings",
         _schema({"hypothesis_id": _string("hypothesis id"),
                  "steps": _array("ordered request/assertion steps", {"type": "object"}),
                  "mission_id": _string("override mission when the hypothesis has none"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "base_url": _string("override base URL"),
                  "fail_fast": _boolean("stop at the first failed assertion", True)},
                 ["hypothesis_id", "steps"]), "hypothesis_test", open_world=True),
    Tool("hypothesis_promote", "Promote a supported hypothesis",
         "Create a finding only from a hypothesis whose test case passed. The raw test "
         "result is attached automatically as evidence. Refused for open or refuted "
         "hypotheses and for duplicate promotion.",
         "medium", "findings",
         _schema({"hypothesis_id": _string("hypothesis id"),
                  "title": _string("finding title"),
                  "severity": _string("validated severity", enum=[
                      "critical", "high", "medium", "low", "info", "unknown"]),
                  "impact": _string("impact statement"),
                  "evidence": _string("evidence summary"),
                  "tags": _array("tags"),
                  "source": _string("source label")},
                 ["hypothesis_id", "title", "severity", "impact"]),
         "hypothesis_promote"),
    Tool("training_plan", "Plan training",
         "Choose the next labs across every bundled source (PortSwigger Academy, "
         "Acunetix testphp, local Juice Shop/DVWA/WebGoat ranges). The plan rotates "
         "across source and category, prefers an in-progress lab, then apprentice "
         "before practitioner before expert.",
         "low", "training",
         _schema({"category": _string("optional exact category"),
                  "difficulty": _string("apprentice, practitioner, or expert", enum=[
                      "apprentice", "practitioner", "expert"]),
                  "source": _string("optional pack source, e.g. acunetix-testphp"),
                  "limit": _integer("how many labs", 1, 25, 5)}),
         "training_plan", read_only=True),
    Tool("training_status", "Training status",
         "Show solved and in-progress labs by source, category, and difficulty, plus "
         "recent records. Progress is explicit and never inferred from a page view.",
         "low", "training",
         _schema({"source": _string("optional pack source")}),
         "training_status", read_only=True),
    Tool("training_sources", "List training sources",
         "List every bundled training source with its lab count, solved count, hosts, "
         "and setup command. Use it before planning a session.",
         "low", "training", _schema({}), "training_sources", read_only=True),
    Tool("training_record", "Record a lab result",
         "Record in-progress, solved, blocked, or skipped for one lab. A solved record "
         "needs evidence and a written lesson; that lesson updates expertise.",
         "medium", "training",
         _schema({"lab_slug": _string("catalogue slug, e.g. lab-retrieve-hidden-data"),
                  "status": _string("result", enum=[
                      "in_progress", "solved", "blocked", "skipped"]),
                  "lesson": _string("what you learned (required when solved)"),
                  "evidence": _string("banner text or artifact path (required when solved)"),
                  "notes": _string("private notes or next step"),
                  "instance_url": _string("the lab instance URL you tested"),
                  "verified": _boolean("the solved signal was verified", False),
                  "technique": _string("technique label"),
                  "mission_id": _string("optional training mission")},
                 ["lab_slug", "status"]), "training_record"),
    Tool("training_verify", "Verify a lab result",
         "Fetch one lab instance and check its solved signal. Academy hosts use the "
         "congratulations banner. Other bundled packs need explicit expect markers and "
         "a mission or scope; loopback ranges are allowed directly.",
         "low", "training",
         _schema({"instance_url": _string("lab instance URL"),
                  "expect": _array("strings that must all appear in the response",
                                   {"type": "string"}),
                  "browser_profile": _string(
                      "read the current page of this managed profile instead of HTTP"),
                  "mission_id": _string("mission authorising a non-local host"),
                  "scope": _array("explicit scope for a non-local host",
                                  {"type": "string"})},
                 ["instance_url"]), "training_verify", open_world=True),
    Tool("skill_packs", "List bundled skill packs",
         "List the advanced playbooks installed for every agent: injection, XSS, SSRF, "
         "auth, GraphQL, deserialization, upload, cache/smuggling, race, cloud, mobile, "
         "reversing, LLM, recon, reporting, and business logic. Read one with skills_get.",
         "low", "training", _schema({}), "skill_packs", read_only=True),
    Tool("ui_audit", "Audit the local dashboard",
         "Open the local dashboard in Chromium and audit the requested screens. "
         "It records console errors, failed requests, horizontal overflow, and "
         "one screenshot per screen. Read-only and local-only.",
         "low", "learning",
         _schema({"routes": _array("screens to audit, e.g. missions or live",
                                   {"type": "string"}),
                  "width": _integer("viewport width", 800, 2560, 1440),
                  "height": _integer("viewport height", 600, 1600, 900),
                  "headless": _boolean("run without a visible window", True)}),
         "ui_audit"),
    Tool("technique_search", "Search the technique library",
         "Search a curated library of less-saturated, high-impact techniques drawn "
         "from public 2025-2026 research: CSPT, cache deception, ORM leaks, "
         "error-based SSTI, OAuth/SCIM/MCP identity bugs, parser differentials, "
         "Next.js cache chains, XS-Leaks, and more.",
         "low", "research",
         _schema({"query": _string("text, class, signal, or tag"),
                  "tag": _string("exact tag, e.g. cspt or orm"),
                  "rarity": _string("rare, uncommon, or common"),
                  "impact": _string("critical, high, medium, or low"),
                  "limit": _integer("how many", 1, 100, 20)}),
         "technique_search", read_only=True),
    Tool("technique_plan", "Plan techniques for a target",
         "Rank techniques against a target host, technology, or observed signals. "
         "Each result carries the test steps, the minimum proof, tools, and public "
         "sources. A high score is a reason to test, not a finding.",
         "low", "research",
         _schema({"target": _string("target host or URL"),
                  "tech": _string("framework or stack, e.g. nextjs, django, graphql"),
                  "signals": _array("observed signals", {"type": "string"}),
                  "tags": _array("desired tags", {"type": "string"}),
                  "limit": _integer("how many", 1, 30, 6)}),
         "technique_plan", read_only=True),
    Tool("research_sources", "Technique library coverage",
         "Show the technique count by class and rarity. Use it to see which bug "
         "classes the library covers before choosing a hunt.",
         "low", "research", _schema({}), "research_sources", read_only=True),
    Tool("research_ingest", "Ingest a write-up",
         "Store a written digest of a public write-up, post, or talk as an active "
         "skill with its source URL. The caller must supply the distilled notes; "
         "the tool does not fetch or invent content.",
         "medium", "research",
         _schema({"url": _string("public source URL"),
                  "title": _string("short title"),
                  "notes": _string("distilled technique, at least 80 characters"),
                  "tags": _array("tags", {"type": "string"})},
                 ["url", "title", "notes"]), "research_ingest"),
    Tool("hunt_plan", "Build a mission hunt plan",
         "Combine a mission's target with the technique library into phases: scope, "
         "baseline, identity, technique tests, validation, and evidence. Read-only; "
         "it proposes tests and does not authorise a target.",
         "low", "research",
         _schema({"mission_id": _string("mission id"),
                  "tech": _string("framework or stack"),
                  "signals": _array("observed signals", {"type": "string"}),
                  "limit": _integer("how many techniques", 1, 30, 6)},
                 ["mission_id"]), "hunt_plan", read_only=True),
    Tool("selfmodel_snapshot", "Capability self-model",
         "Show a deterministic capability snapshot derived from stored training, skills, "
         "expertise, findings, missions, and submissions. No model guess is included.",
         "low", "learning", _schema({}), "selfmodel_snapshot", read_only=True),
    Tool("selfmodel_gaps", "Capability gap analysis",
         "Rank the weakest capability areas with one concrete next step each. Gaps come "
         "from the stored self-model, not from a prompt.",
         "low", "learning",
         _schema({"limit": _integer("how many gaps", 1, 30, 6)}),
         "selfmodel_gaps", read_only=True),
    Tool("selfmodel_evolve", "Propose upgrades from capability gaps",
         "Read the stored capability gaps and create one deduplicated, "
         "human-gated upgrade proposal per gap. Nothing is applied automatically.",
         "medium", "learning",
         _schema({"limit": _integer("how many gaps", 1, 10, 3)}),
         "selfmodel_evolve"),
    Tool("upgrade_propose", "Propose a framework upgrade",
         "Write a human-gated improvement proposal with evidence. Nothing is applied "
         "automatically; an operator decides whether to implement it.",
         "medium", "learning",
         _schema({"title": _string("short improvement title"),
                  "rationale": _string("why it matters, at least 20 characters"),
                  "evidence": _string("record, path, or observed gap that motivates it"),
                  "area": _string("capability area or general"),
                  "priority": _string("priority", enum=[
                      "low", "medium", "high", "critical"])},
                 ["title", "rationale", "evidence"]), "upgrade_propose"),
    Tool("upgrade_list", "List upgrade proposals",
         "List framework improvement proposals by status and area, highest priority "
         "first.",
         "low", "learning",
         _schema({"status": _string("proposed, accepted, rejected, or implemented"),
                  "area": _string("capability area"),
                  "limit": _integer("how many", 1, 500, 100)}),
         "upgrade_list", read_only=True),
    Tool("upgrade_update", "Decide on an upgrade proposal",
         "Move a proposal between proposed, accepted, rejected, and implemented. This "
         "records a human decision; it does not edit code.",
         "medium", "learning",
         _schema({"proposal_id": _string("upgrade proposal id"),
                  "status": _string("new status", enum=[
                      "proposed", "accepted", "rejected", "implemented"]),
                  "rationale": _string("decision note")},
                 ["proposal_id"]), "upgrade_update"),
    Tool("toolbook", "Search the toolbook",
         "Look up a Linux/web security tool: what it does, when to use it, one focused "
         "command, and the scope or rate-limit caution. Pass name for one entry.",
         "low", "training",
         _schema({"query": _string("search text"),
                  "name": _string("exact tool name, e.g. ffuf")}),
         "toolbook", read_only=True),
    Tool("burp_status", "Burp MCP status",
         "Connect to the configured Burp MCP server and list its tools. Configure with "
         "NETCAST3R_BURP_URL / NETCAST3R_BURP_TOKEN or ~/.netcast3r/integrations.json.",
         "low", "integrations", _schema({}), "burp_status", read_only=True),
    Tool("burp_call", "Call a Burp MCP tool",
         "Invoke one tool exposed by Burp MCP (proxy history, Repeater, scanner). URL, "
         "host, and raw Host headers in the arguments are checked against the mission "
         "scope first. High risk: needs an approval under supervised policy.",
         "high", "integrations",
         _schema({"tool": _string("Burp MCP tool name"),
                  "arguments": _object("tool arguments"),
                  "mission_id": _string("mission whose scope authorizes the call"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "approval_id": _string("approved approval id"),
                  "confirm": _boolean("explicit confirmation (full policy)")},
                 ["tool"]), "burp_call", open_world=True),
    Tool("mcp_servers_list", "List outbound MCP servers",
         "List the operator-configured MCP servers NetCast3r can call (HTTP or stdio). "
         "Use this to bridge Hermes Agent, Agent Zero, HexStrike, OpenCode, or an "
         "internal MCP server. Tokens are never returned.",
         "low", "integrations", _schema({}), "mcp_servers_list", read_only=True),
    Tool("sandbox_run", "Run in a Docker sandbox",
         "Run one short command in a locked-down container: no network, read-only root, "
         "dropped capabilities, non-root user, 256 MB memory, and no host mount. Use it to "
         "read or reproduce a PoC without touching the host or a target. High risk: needs "
         "an approval under supervised policy.",
         "high", "sandbox",
         _schema({"image": _string("allowlisted image", enum=list(integrations.SANDBOX_IMAGES)),
                  "command": _array("argv, no shell", {"type": "string"}),
                  "stdin": _string("optional script or data on stdin"),
                  "timeout": _integer("timeout in seconds", 5, 300, 60),
                  "approval_id": _string("approved approval id"),
                  "confirm": _boolean("explicit confirmation (full policy)")},
                 ["image", "command"]), "sandbox_run"),
    Tool("mcp_server_tools", "List an MCP server's tools",
         "Start one configured outbound MCP server, initialize it, and list its tools.",
         "medium", "integrations",
         _schema({"server": _string("configured server name")}, ["server"]),
         "mcp_server_tools", open_world=True),
    Tool("mcp_server_call", "Call an outbound MCP tool",
         "Invoke one tool on a configured outbound MCP server. URL, host, and raw Host "
         "headers in the arguments are checked against the mission scope first. High "
         "risk: needs an approval under supervised policy.",
         "high", "integrations",
         _schema({"server": _string("configured server name"),
                  "tool": _string("remote tool name"),
                  "arguments": _object("remote tool arguments"),
                  "mission_id": _string("mission whose scope authorizes the call"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "approval_id": _string("approved approval id"),
                  "confirm": _boolean("explicit confirmation (full policy)")},
                 ["server", "tool"]), "mcp_server_call", open_world=True),
    Tool("token_pivot", "Credential pivot",
         "Send a captured token, cookie, or API key to a bounded list of in-scope hosts "
         "and compare each response with an unauthenticated baseline. Reports where the "
         "credential changes the response; never follows a cross-host redirect. Requires "
         "a mission; every host is scope-checked first.",
         "medium", "post-exploitation",
         _schema({"token_value": _string("credential value; redacted from the audit"),
                  "header": _string("header name, default Authorization"),
                  "hosts": _array("hosts to test; defaults to the mission target and "
                                  "concrete scope entries"),
                  "path": _string("path to request, default /"),
                  "mission_id": _string("mission whose scope authorizes the test"),
                  "timeout": _integer("per-request timeout in seconds", 1, 60, 10),
                  "delay": {"type": "number", "description": "seconds between hosts",
                            "minimum": 0, "maximum": 5, "default": 0.25}},
                 ["token_value", "mission_id"]), "token_pivot", open_world=True),
    Tool("threatintel_query", "Threat intel search",
         "Search recent CVEs and PoCs across NVD, CISA KEV, GitHub repositories, GitHub "
         "advisories, and Sploitus. A CVE id returns the advisory, severity, exploitation "
         "status, and public repos; a keyword searches GitHub. Results keep their sources.",
         "low", "threat-intel",
         _schema({"query": _string("CVE id or keyword"),
                  "limit": _integer("results per source", 1, 20, 10)},
                 ["query"]), "threatintel_query", open_world=True),
    Tool("threatintel_cve", "CVE dossier",
         "Fetch the advisory, CVSS scores, CISA KEV status, GitHub advisories, and public "
         "PoC repositories for one CVE id.",
         "low", "threat-intel",
         _schema({"cve_id": _string("CVE id, e.g. CVE-2025-12345"),
                  "limit": _integer("PoC repos", 1, 20, 10)},
                 ["cve_id"]), "threatintel_cve", open_world=True),
    Tool("threatintel_repro", "Reproduction plan",
         "Build a cited, non-executing reproduction plan for one CVE from the advisory and "
         "the top public PoC READMEs. Extracts code blocks, flags destructive payloads, and "
         "lays out the smallest safe proof against an authorized target.",
         "low", "threat-intel",
         _schema({"cve_id": _string("CVE id"),
                  "target": _string("optional in-scope target to mention in the plan")},
                 ["cve_id"]), "threatintel_repro", open_world=True),
    Tool("lessons_record", "Record a lesson",
         "Persist a technique, failure, or correction you actually observed. Lessons are "
         "stored with the mission/run/task, tags, and confidence, and are recalled before "
         "later plans. Do not record a guess.",
         "medium", "learning",
         _schema({"title": _string("short lesson title"),
                  "lesson": _string("what happened and what to do differently"),
                  "technique": _string("tool or technique"),
                  "context": _string("target class or environment"),
                  "outcome": _string("success, failure, partial, or blocked", enum=[
                      "success", "failure", "partial", "blocked"]),
                  "next_step": _string("one concrete next action"),
                  "tags": _array("tags"),
                  "mission_id": _string("optional mission id"),
                  "run_id": _string("optional run id"),
                  "task_id": _string("optional agent task id"),
                  "source": _string("where the observation came from"),
                  "confidence": {"type": "number", "minimum": 0, "maximum": 1,
                                 "description": "0 to 1"}},
                 ["title", "lesson"]), "lessons_record"),
    Tool("lessons_list", "List lessons",
         "Search operational lessons by text, tag, or outcome.",
         "low", "learning",
         _schema({"q": _string("search text"), "tag": _string("tag filter"),
                  "outcome": _string("outcome filter", enum=[
                      "success", "failure", "partial", "blocked"]),
                  "limit": _integer("page size", 1, 500, 50)}),
         "lessons_list", read_only=True),
    Tool("lessons_get", "Get lesson", "Read one lesson in full.",
         "low", "learning",
         _schema({"lesson_id": _string("lesson id")}, ["lesson_id"]),
         "lessons_get", read_only=True),
    Tool("lesson_reflect", "Reflect on a record",
         "Derive a lesson from a stored tool call or run. Deterministic: it reads the real "
         "status and error, classifies the cause, and records the next step.",
         "low", "learning",
         _schema({"tool_call_id": _string("tool call id"),
                  "run_id": _string("run id")}), "lesson_reflect"),
    Tool("skills_list", "List skills",
         "List the operational skill documents agents can load before planning. "
         "Active skills are ranked first by use count.",
         "low", "learning",
         _schema({"q": _string("search text"),
                  "status": _string("draft, active, or retired", enum=[
                      "draft", "active", "retired"]),
                  "limit": _integer("page size", 1, 200, 50)}),
         "skills_list", read_only=True),
    Tool("skills_get", "Read a skill",
         "Return one skill document by name or id.", "low", "learning",
         _schema({"name": _string("skill name or id")}, ["name"]),
         "skills_get", read_only=True),
    Tool("skills_upsert", "Write a skill",
         "Create or version a markdown skill: a technique, checklist, or write-up digest. "
         "Use it when a test produced a reusable procedure, not for one-off noise.",
         "medium", "learning",
         _schema({"name": _string("stable skill name"),
                  "body": _string("markdown body"),
                  "title": _string("display title"),
                  "description": _string("one-line description"),
                  "tags": _array("tags"),
                  "source": _string("URL or record the skill came from")},
                 ["name", "body"]), "skills_upsert"),
    Tool("skills_use", "Mark a skill used",
         "Increment a skill's use count and, when the attempt succeeded, its success "
         "count. This is how the library learns which procedures actually work.",
         "medium", "learning",
         _schema({"name": _string("skill name or id"),
                  "success": _boolean("did the procedure work", True)},
                 ["name"]), "skills_use"),
    Tool("skills_status", "Change skill status",
         "Move a skill between draft, active, and retired. Retired skills are not "
         "recalled by the agent.",
         "medium", "learning",
         _schema({"name": _string("skill name or id"),
                  "status": _string("draft, active, or retired", enum=[
                      "draft", "active", "retired"])},
                 ["name", "status"]), "skills_status"),
    Tool("next_actions", "Suggest next actions",
         "Rank concrete next actions from the mission, findings, tool calls, and lessons. "
         "Deterministic and based only on stored records; confirm scope before running one.",
         "low", "learning",
         _schema({"mission_id": _string("mission id")}, ["mission_id"]),
         "next_actions", read_only=True),
    Tool("finding_triage", "Triage finding",
         "Set triage status, notes, tags, or a severity override on a finding.",
         "medium", "findings",
         _schema({"finding_id": _string("finding id"),
                  "status": _string("new, in_progress, confirmed, escalated, rejected, "
                                    "or false_positive", enum=[
                                        "new", "in_progress", "confirmed", "escalated",
                                        "rejected", "false_positive"]),
                  "notes": _string("operator notes"),
                  "tags": _array("tags"),
                  "severity_override": _string("override severity")},
                 ["finding_id"]), "finding_triage"),
    Tool("submissions_list", "List submissions",
         "List filed reports and their platform outcomes. This is a ledger of real "
         "submissions, not a prediction; the workspace does not create rows for you.",
         "low", "reports",
         _schema({"status": _string("submission status", enum=[
                     "draft", "ready", "submitted", "triaged", "accepted", "informative",
                     "duplicate", "rejected", "paid", "withdrawn"]),
                  "platform": _string("hacking platform", enum=[
                      "hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi", "other"]),
                  "mission_id": _string("mission id"),
                  "finding_id": _string("finding id"),
                  "limit": _integer("page size", 1, 200, 50),
                  "page": _integer("page number", 1)}), "submissions_list", read_only=True),
    Tool("submissions_get", "Get submission",
         "Fetch one submission with its mission, finding, and run context.",
         "low", "reports",
         _schema({"submission_id": _string("submission id")}, ["submission_id"]),
         "submissions_get", read_only=True),
    Tool("submissions_summary", "Submission summary",
         "Counts by status and recorded award/payout totals, grouped by currency. "
         "Only rows you recorded are counted.",
         "low", "reports", _schema({}), "submissions_summary", read_only=True),
    Tool("submissions_create", "Record submission",
         "Record a report you filed or are preparing. A submission is never inferred "
         "from a finding; it exists only when an operator or agent writes it down.",
         "medium", "reports",
         _schema({"title": _string("report title"),
                  "platform": _string("hacking platform", enum=[
                      "hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi", "other"]),
                  "program": _string("program handle or name"),
                  "target": _string("affected target"),
                  "severity": _string("reported severity", enum=[
                      "critical", "high", "medium", "low", "info"]),
                  "status": _string("submission status", enum=[
                      "draft", "ready", "submitted", "triaged", "accepted", "informative",
                      "duplicate", "rejected", "paid", "withdrawn"]),
                  "mission_id": _string("mission id"),
                  "finding_id": _string("finding id"),
                  "run_id": _string("run id"),
                  "bounty_cents": _integer("recorded award in cents", 0),
                  "currency": _string("three-letter currency code"),
                  "external_id": _string("platform report id"),
                  "url": _string("https report url"),
                  "report_path": _string("local report path"),
                  "notes": _string("private notes")},
                 ["title"]), "submissions_create"),
    Tool("submissions_update", "Update submission",
         "Change a submission's status, outcome, award, links, or notes. Status changes "
         "stamp submitted, decided, and paid times on first entry.",
         "medium", "reports",
         _schema({"submission_id": _string("submission id"),
                  "title": _string("report title"),
                  "platform": _string("hacking platform", enum=[
                      "hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi", "other"]),
                  "program": _string("program handle or name"),
                  "target": _string("affected target"),
                  "severity": _string("reported severity", enum=[
                      "critical", "high", "medium", "low", "info"]),
                  "status": _string("submission status", enum=[
                      "draft", "ready", "submitted", "triaged", "accepted", "informative",
                      "duplicate", "rejected", "paid", "withdrawn"]),
                  "mission_id": _string("mission id"),
                  "finding_id": _string("finding id"),
                  "run_id": _string("run id"),
                  "bounty_cents": _integer("recorded award in cents", 0),
                  "currency": _string("three-letter currency code"),
                  "external_id": _string("platform report id"),
                  "url": _string("https report url"),
                  "report_path": _string("local report path"),
                  "notes": _string("private notes")},
                 ["submission_id"]), "submissions_update"),
    Tool("submissions_delete", "Delete submission",
         "Delete a ledger entry. High risk: needs an approved approval in supervised "
         "mode, and confirm=true under full policy. This does not delete the report file.",
         "high", "reports",
         _schema({"submission_id": _string("submission id"),
                  "approval_id": _string("approved approval id"),
                  "confirm": _boolean("explicit confirmation (full policy)")},
                 ["submission_id"]), "submissions_delete", destructive=True),
    Tool("approvals_list", "List approvals",
         "List approval requests, optionally pending only or by mission.",
         "low", "governance",
         _schema({"status": _string("pending, approved, or rejected"),
                  "mission_id": _string("mission id"),
                  "limit": _integer("page size", 1, 200, 50),
                  "page": _integer("page number", 1)}), "approvals_list", read_only=True),
    Tool("approval_request", "Request approval",
         "Ask a human to approve a high-risk action. Pass the exact tool name and "
         "arguments you will use; the approval is bound to their hash and can be spent once.",
         "medium", "governance",
         _schema({"mission_id": _string("mission id"),
                  "action": _string("what the human is approving"),
                  "risk": _string("risk tier", enum=["low", "medium", "high", "critical"]),
                  "reason": _string("why this action is necessary"),
                  "tool": _string("tool name that will consume the approval"),
                  "arguments": _object("exact arguments the tool will receive"),
                  "payload": _object("extra context for the reviewer"),
                  "run_id": _string("optional run id")},
                 ["mission_id", "action"]), "approval_request"),
    Tool("approval_decide", "Decide approval",
         "Approve or reject a pending request. Operator-only: denied in supervised mode; "
         "full mode also requires confirm=true. High risk.",
         "high", "governance",
         _schema({"approval_id": _string("approval id"),
                  "decision": _string("approved or rejected", enum=["approved", "rejected"]),
                  "mission_id": _string("mission id for a cross-check"),
                  "decided_by": _string("operator identity"),
                  "reason": _string("decision reason"),
                  "confirm": _boolean("explicit confirmation (full policy)")},
                 ["approval_id", "decision"]), "approval_decide",
         destructive=True, operator_only=True),
    Tool("providers_list", "List providers",
         "Provider health, models, and whether a key is configured. Never returns the key.",
         "low", "providers", _schema({}), "providers_list", read_only=True),
    Tool("provider_test", "Test provider",
         "Make one real completion request to a provider and record the health result.",
         "medium", "providers",
         _schema({"provider_id": _string("provider id")}, ["provider_id"]),
         "provider_test", open_world=True),
    Tool("scope_check", "Check scope",
         "Classify a target against a mission or explicit scope without sending traffic.",
         "low", "scope",
         _schema({"target": _string("host or URL"),
                  "mission_id": _string("mission id"),
                  "scope": _array("explicit scope entries")},
                 ["target"]), "scope_check", read_only=True),
    Tool("http_probe", "HTTP probe",
         "Send one GET or HEAD request to an in-scope target. No custom headers, no "
         "redirect following, response body capped. Metadata and link-local hosts are refused.",
         "medium", "scope",
         _schema({"target": _string("in-scope host or URL"),
                  "mission_id": _string("mission whose scope authorizes the probe"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "method": _string("GET or HEAD", enum=["GET", "HEAD"]),
                  "max_bytes": _integer("response body cap", 1024, 262144, 65536),
                  "timeout": _integer("timeout in seconds", 1, 60, 15)},
                 ["target"]), "http_probe", open_world=True),
    Tool("http_request", "Authenticated HTTP request",
         "Send one scoped request with a named auth profile, custom headers, and a "
         "JSON, form, or raw body. Every redirect hop is re-checked against the same "
         "scope; metadata and link-local hosts are always refused. Use low volume and "
         "only against an authorized target.",
         "medium", "web",
         _schema({"target": _string("in-scope host or URL"),
                  "mission_id": _string("mission whose scope authorizes the request"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "method": _string("HTTP method", enum=[
                      "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
                  "headers": _object("extra request headers"),
                  "auth_profile": _string("stored auth profile name"),
                  "body": _string("raw request body"),
                  "json": _object("JSON request body"),
                  "form": _object("form request body"),
                  "follow_redirects": _boolean("follow up to max_redirects hops", False),
                  "max_redirects": _integer("redirect hop limit", 0, 5, 5),
                  "verify_tls": _boolean("verify the target certificate (default true); "
                                         "disable only for an authorized self-signed target",
                                         True),
                  "max_bytes": _integer("response body cap", 1024, 524288, 65536),
                  "timeout": _integer("timeout in seconds", 1, 60, 15)},
                 ["target"]), "http_request", open_world=True),
    Tool("http_upload", "Scoped multipart upload",
         "Send one multipart file upload with optional form fields and an auth "
         "profile. The file is held in memory, capped at 1 MiB, and the target is "
         "scope-checked. Use it to test extension, MIME, magic-byte, and storage "
         "handling without a shell.",
         "medium", "web",
         _schema({"target": _string("in-scope upload URL"),
                  "mission_id": _string("mission whose scope authorizes the upload"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "method": _string("upload method", enum=["POST", "PUT", "PATCH"]),
                  "headers": _object("extra request headers"),
                  "auth_profile": _string("stored auth profile name"),
                  "field": _string("multipart field name"),
                  "filename": _string("filename presented to the server"),
                  "content": _string("file content"),
                  "content_base64": _boolean("decode content from base64", False),
                  "content_type": _string("part content type"),
                  "form": _object("extra form fields"),
                  "verify_tls": _boolean("verify the target certificate", True),
                  "max_bytes": _integer("response body cap", 1024, 524288, 65536),
                  "timeout": _integer("timeout in seconds", 1, 60, 30)},
                 ["target", "content"]), "http_upload", open_world=True),
    Tool("oracle_extract", "Extract through a blind oracle",
         "Extract a value character by character through a boolean, status, or "
         "time-based oracle. Put {{expr}} in the URL, a header, or the body; the "
         "tool renders expr_template with {query}, {pos}, and {char} and sends one "
         "scoped, rate-limited probe per candidate. Use it for blind SQL injection, "
         "blind command injection, and similar oracles.",
         "medium", "web",
         _schema({"target": _string("in-scope URL, optionally containing {{expr}}"),
                  "method": _string("HTTP method", enum=[
                      "GET", "POST", "PUT", "PATCH"]),
                  "headers": _object("headers; values may contain {{expr}}"),
                  "body": _string("body template; may contain {{expr}}"),
                  "auth_profile": _string("stored auth profile name"),
                  "mission_id": _string("mission whose scope authorizes the probes"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "expr_template": _string("expression template using {query}, {pos}, {char}"),
                  "query": _string("subquery or value to extract"),
                  "charset": _string("candidate characters"),
                  "max_length": _integer("maximum characters to extract", 1, 256, 32),
                  "position_start": _integer("first character position", 1, 4096, 1),
                  "max_requests": _integer("hard probe cap", 1, 2000, 600),
                  "true_when": _string("oracle type", enum=[
                      "contains", "not_contains", "status", "time"]),
                  "match": _string("body text that indicates a true condition"),
                  "expected_status": _integer("status that indicates true", 100, 599, 200),
                  "threshold_ms": _integer("time threshold in milliseconds", 1, 60000, 3000)},
                 ["target"]), "oracle_extract", open_world=True),
    Tool("race_run", "Bounded concurrent burst",
         "Send the same scoped request N times concurrently and return every "
         "status, body shape, and elapsed time. Use it to test check-then-act "
         "flows such as coupons, refunds, OTP verification, and vote limits. "
         "It is a concurrent burst, not a single-packet attack; compare the "
         "invariant before and after.",
         "medium", "web",
         _schema({"target": _string("in-scope URL"),
                  "mission_id": _string("mission whose scope authorizes the burst"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "method": _string("HTTP method", enum=[
                      "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]),
                  "headers": _object("extra request headers"),
                  "auth_profile": _string("stored auth profile name"),
                  "body": _string("raw request body"),
                  "json": _object("JSON request body"),
                  "form": _object("form request body"),
                  "count": _integer("number of requests", 2, 50, 10),
                  "concurrency": _integer("parallel workers", 1, 50, 10),
                  "verify_tls": _boolean("verify the target certificate", True),
                  "max_bytes": _integer("per-response body cap", 256, 65536, 16384),
                  "timeout": _integer("per-request timeout in seconds", 1, 60, 20)},
                 ["target"]), "race_run", open_world=True),
    Tool("http_path_diff", "Path-variant differential",
         "Send the same request to literal, percent-encoded, case-varied, and slash-varied "
         "paths, then report where the status or body diverges. Useful for finding "
         "authorization checks that run before the router decodes the path. Non-safe "
         "methods require allow_unsafe_method because replaying a POST can create state.",
         "medium", "web",
         _schema({"target": _string("in-scope URL, including the path to vary"),
                  "mission_id": _string("mission whose scope authorizes the requests"),
                  "scope": _array("explicit scope entries when no mission is used"),
                  "method": _string("HTTP method", enum=[
                      "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
                  "allow_unsafe_method": _boolean("allow replaying POST/PUT/PATCH/DELETE", False),
                  "headers": _object("extra request headers"),
                  "auth_profile": _string("stored auth profile name"),
                  "body": _string("raw request body"),
                  "json": _object("JSON request body"),
                  "form": _object("form request body"),
                  "max_variants": _integer("variant cap", 2, 24, 12),
                  "delay": {"type": "number", "description": "seconds between requests",
                            "minimum": 0, "maximum": 2, "default": 0.2},
                  "follow_redirects": _boolean("follow up to 5 hops", False),
                  "verify_tls": _boolean("verify the target certificate (default true)", True),
                  "max_bytes": _integer("response body cap", 1024, 262144, 32768),
                  "timeout": _integer("timeout in seconds", 1, 60, 15)},
                 ["target"]), "http_path_diff", open_world=True),
    Tool("rea_analyze", "REA: reverse-engineer anything",
         "Run the local analyzer on an APK, binary, source tree, JavaScript "
         "bundle, or smart contract and return the observations plus a "
         "kind-specific REA next-step plan and tool set. Local and read-only.",
         "low", "reverse",
         _schema({"path": _string("local artifact path"),
                  "kind": _string("artifact kind", enum=[
                      "auto", "source", "js", "apk", "contract", "binary"]),
                  "goal": _string("what the reverse-engineering pass should answer"),
                  "max_files": _integer("source file cap", 1, 4000, 4000),
                  "timeout": _integer("APK analyzer timeout", 10, 900, 240),
                  "keep": _boolean("keep the APK extraction directory", False)},
                 ["path"]), "rea_analyze"),
    Tool("reveng_analyze", "Reverse-engineer a local artifact",
         "Analyze a source tree, APK, Solidity project, JS bundle, or PE/ELF binary you "
         "legitimately hold. Source and contract checks are text-only; APK analysis uses "
         "jadx or apktool when installed. Nothing is uploaded, executed, or run against a "
         "target. Results are leads with file and line numbers, not findings.",
         "medium", "reverse-engineering",
         _schema({"path": _string("local file or directory to analyze"),
                  "kind": _string("analysis kind", enum=list(reveng.KINDS)),
                  "max_files": _integer("source file cap", 1, 20000, 4000),
                  "timeout": _integer("decompiler timeout in seconds", 30, 900, 240),
                  "keep": _boolean("keep the decompiler work directory", False),
                  "markdown": _boolean("include a rendered markdown summary", False)},
                 ["path"]), "reveng_analyze", open_world=False),
    Tool("inbox_create", "Create inbox",
         "Create a disposable inbox for authorized account verification. mail.tm "
         "gives a password-backed account; guerrillamail gives a session-backed "
         "address. Credentials stay in a 0600 file and are never returned.",
         "low", "identity",
         _schema({"provider": {"type": "string",
                               "enum": list(tempmail.PROVIDERS),
                               "default": "mail.tm"},
                  "domain": _string("optional provider domain"),
                  "prefix": _string("local-part prefix")}), "inbox_create",
         open_world=True),
    Tool("inbox_providers", "List mailbox providers",
         "List the temporary-mail providers this workspace can create inboxes on.",
         "low", "identity", _schema({}), "inbox_providers", read_only=True),
    Tool("inbox_list", "List inboxes",
         "List the disposable inboxes created on this workspace. Credentials are masked.",
         "low", "identity", _schema({}), "inbox_list", read_only=True),
    Tool("inbox_read", "Read inbox",
         "List messages in an inbox, or read one message with its text, html, and links.",
         "low", "identity",
         _schema({"mailbox_id": _string("mailbox id or address"),
                  "message_id": _string("optional message id")},
                 ["mailbox_id"]), "inbox_read", read_only=True),
    Tool("inbox_wait", "Wait for mail",
         "Block until a matching message arrives or the timeout expires. Use after "
         "triggering a verification email; pass since_id to skip older mail.",
         "low", "identity",
         _schema({"mailbox_id": _string("mailbox id or address"),
                  "timeout": _integer("seconds to wait", 5, 300, 180),
                  "interval": _integer("poll interval in seconds", 2, 30, 4),
                  "match": _string("case-insensitive subject/body substring"),
                  "since_id": _string("last message id already triaged")},
                 ["mailbox_id"]), "inbox_wait", read_only=True),
    Tool("oast_create", "Create callback URL",
         "Create a unique webhook.site URL for out-of-band testing. The token stays "
         "in a 0600 file; only the callback URL is returned.",
         "medium", "callbacks",
         _schema({"label": _string("short label for this callback")}),
         "oast_create", open_world=True),
    Tool("oast_list", "List callback sessions",
         "List callback sessions created on this workspace.", "low", "callbacks",
         _schema({}), "oast_list", read_only=True),
    Tool("oast_poll", "Poll callbacks",
         "Read the requests that reached a callback URL, newest first. Pass the "
         "previous cursor as since to fetch only new hits.",
         "low", "callbacks",
         _schema({"session_id": _string("callback session id"),
                  "since": {"type": "number", "minimum": 0,
                            "description": "unix timestamp cursor"},
                  "limit": _integer("maximum hits", 1, 200, 50)},
                 ["session_id"]), "oast_poll", read_only=True),
    Tool("oast_delete", "Delete callback session",
         "Delete the remote callback endpoint and its local record. Medium risk.",
         "medium", "callbacks",
         _schema({"session_id": _string("callback session id")},
                 ["session_id"]), "oast_delete", destructive=True, open_world=True),
    Tool("auth_profile_set", "Store auth profile",
         "Store named headers and cookies for authenticated testing. Values are kept "
         "in a 0600 file and are never returned by a listing call.",
         "medium", "identity",
         _schema({"name": _string("profile name"),
                  "headers": _object("request headers"),
                  "cookies": _object("cookies"),
                  "note": _string("operator note")},
                 ["name"]), "auth_profile_set"),
    Tool("auth_profile_list", "List auth profiles",
         "List stored auth profile names and the header/cookie names they carry. "
         "No values are returned.", "low", "identity",
         _schema({}), "auth_profile_list", read_only=True),
    Tool("auth_profile_delete", "Delete auth profile",
         "Delete a stored auth profile.", "medium", "identity",
         _schema({"name": _string("profile name")}, ["name"]),
         "auth_profile_delete", destructive=True),
    Tool("auth_profile_import", "Import browser session",
         "Import cookies from a Playwright storage-state JSON file, optionally "
         "filtered to one domain, into a named auth profile.",
         "medium", "identity",
         _schema({"path": _string("path to storage-state JSON"),
                  "name": _string("profile name"),
                  "domain": _string("cookie domain filter")},
                 ["path", "name"]), "auth_profile_import"),
    Tool("browser_open", "Open browser",
         "Launch or reuse a persistent Chromium profile and navigate it. The "
         "window is a real desktop browser: a human can solve a challenge, finish "
         "an OAuth consent, or log in, and the agent can keep driving the same "
         "session. Target URLs are scope-checked; set purpose=identity only for a "
         "recognised identity provider.",
         "medium", "browser",
         _schema({"profile": _string("profile name, e.g. snapdeploy"),
                  "url": _string("http(s) URL or about:blank"),
                  "headless": _boolean("run without a visible window", False),
                  "purpose": {"type": "string", "enum": ["target", "identity"],
                              "default": "target"},
                  "mission_id": _string("mission id"),
                  "scope": _array("explicit in-scope entries")},
                 ["profile"]), "browser_open", open_world=True),
    Tool("browser_status", "Browser status",
         "Show whether a profile is running, its URL, title, and process id.",
         "low", "browser",
         _schema({"profile": _string("profile name")}, ["profile"]),
         "browser_status", read_only=True),
    Tool("browser_list", "List browser profiles",
         "List known browser profiles and their live state.",
         "low", "browser", _schema({}), "browser_list", read_only=True),
    Tool("browser_goto", "Navigate browser",
         "Navigate an existing profile to a scoped URL.",
         "medium", "browser",
         _schema({"profile": _string("profile name"),
                  "url": _string("http(s) URL"),
                  "timeout": _integer("navigation timeout in ms", 1000, 120000, 20000),
                  "purpose": {"type": "string", "enum": ["target", "identity"],
                              "default": "target"},
                  "mission_id": _string("mission id"),
                  "scope": _array("explicit in-scope entries")},
                 ["profile", "url"]), "browser_goto", open_world=True),
    Tool("browser_snapshot", "Snapshot page",
         "Return the visible page text plus interactive elements with stable refs. "
         "Password values are never returned.",
         "low", "browser",
         _schema({"profile": _string("profile name"),
                  "include_text": _boolean("include visible page text", True)},
                 ["profile"]), "browser_snapshot", read_only=True),
    Tool("browser_click", "Click element",
         "Click an element by snapshot ref or CSS selector.",
         "medium", "browser",
         _schema({"profile": _string("profile name"),
                  "ref": _string("snapshot ref, e.g. e12"),
                  "selector": _string("CSS selector"),
                  "button": {"type": "string", "enum": ["left", "right", "middle"],
                             "default": "left"},
                  "timeout": _integer("timeout in ms", 500, 120000, 10000)},
                 ["profile"]), "browser_click"),
    Tool("browser_type", "Type into element",
         "Fill an input or editable element by ref or selector. The typed text is "
         "redacted from the audit trail. Use submit=true to press Enter.",
         "medium", "browser",
         _schema({"profile": _string("profile name"),
                  "text": _string("text to type"),
                  "ref": _string("snapshot ref"),
                  "selector": _string("CSS selector"),
                  "submit": _boolean("press Enter after typing", False),
                  "clear": _boolean("clear the field first", True),
                  "timeout": _integer("timeout in ms", 500, 120000, 10000)},
                 ["profile", "text"]), "browser_type"),
    Tool("browser_press", "Press key",
         "Press a keyboard key on an element or the page body.",
         "medium", "browser",
         _schema({"profile": _string("profile name"),
                  "key": _string("key name, e.g. Enter or Escape"),
                  "ref": _string("snapshot ref"),
                  "selector": _string("CSS selector")},
                 ["profile", "key"]), "browser_press"),
    Tool("browser_wait", "Wait for page",
         "Wait for a human or a page condition: time, url substring, text, selector, "
         "or navigation away from the current URL. Use navigation after asking a "
         "human to finish a login.",
         "low", "browser",
         _schema({"profile": _string("profile name"),
                  "until": {"type": "string",
                            "enum": ["time", "url", "text", "selector", "navigation"],
                            "default": "time"},
                  "value": _string("substring or selector"),
                  "timeout": _integer("timeout in ms", 1000, 900000, 30000)},
                 ["profile"]), "browser_wait", read_only=True),
    Tool("browser_screenshot", "Screenshot browser",
         "Capture the visible page to a PNG under the NetCast3r data directory.",
         "low", "browser",
         _schema({"profile": _string("profile name"),
                  "full_page": _boolean("capture the full scrollable page", False)},
                 ["profile"]), "browser_screenshot", read_only=True),
    Tool("browser_capture", "Capture browser session",
         "Copy the live cookie jar into a named auth profile for http_request. "
         "Cookie values are stored sealed and are never returned.",
         "medium", "browser",
         _schema({"profile": _string("browser profile"),
                  "name": _string("auth profile name"),
                  "domain": _string("optional cookie domain filter"),
                  "storage_key": _string("localStorage key holding the token"),
                  "header": _string("header for the token, default Authorization")},
                 ["profile", "name"]), "browser_capture"),
    Tool("browser_eval", "Evaluate JavaScript",
         "Evaluate one JavaScript expression in the page and return its JSON value. "
         "High risk: it can read page secrets. Supervised mode needs an approval.",
         "high", "browser",
         _schema({"profile": _string("profile name"),
                  "expression": _string("JavaScript expression")},
                 ["profile", "expression"]), "browser_eval",
         open_world=True),
    Tool("browser_close", "Close browser",
         "Terminate the Chromium process for a profile. Unsaved page state is lost.",
         "medium", "browser",
         _schema({"profile": _string("profile name")}, ["profile"]),
         "browser_close", destructive=True),
    Tool("tool_calls_list", "List tool calls",
         "Read the MCP audit trail: tool, risk, status, actor, mission, run, and timing.",
         "low", "governance",
         _schema({"tool": _string("tool name"), "status": _string("audit status"),
                  "mission_id": _string("mission id"), "run_id": _string("run id"),
                  "limit": _integer("page size", 1, 200, 50),
                  "page": _integer("page number", 1)}), "tool_calls_list", read_only=True),
)

_TOOL_MAP = {tool.name: tool for tool in TOOLS}


def catalog() -> list[dict]:
    """Metadata-only view for the UI and ``tools/list``."""
    return [{
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "risk": tool.risk,
        "category": tool.category,
        "read_only": tool.read_only,
        "destructive": tool.destructive,
        "open_world": tool.open_world,
        "operator_only": tool.operator_only,
        "input_schema": tool.input_schema,
    } for tool in TOOLS]


def mcp_tools() -> list[dict]:
    return [{
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "annotations": tool.annotations(),
    } for tool in TOOLS]


class ToolRegistry:
    def __init__(self, ctx: ToolContext):
        if ctx.policy not in POLICIES:
            raise ValueError(f"unknown MCP policy: {ctx.policy}")
        ctx.tool_count = len(TOOLS)
        self.ctx = ctx

    def _policy_check(self, tool: Tool, args: dict) -> str:
        """Return '' or raise; returns the approval id spent, if any."""
        risk = RISK_LEVELS.get(tool.risk, 99)
        if self.ctx.policy == "readonly" and risk > RISK_LEVELS["low"]:
            raise ToolError("policy_denied",
                            f"{tool.name} is {tool.risk} risk; readonly policy allows low only")
        if tool.operator_only and self.ctx.policy != "full":
            raise ToolError("policy_denied",
                            "approval decisions are operator-only; use the UI or set the "
                            "MCP policy to full for an explicitly trusted operator")
        if risk < RISK_LEVELS["high"]:
            return ""
        if self.ctx.policy == "supervised":
            approval_id = str(args.get("approval_id") or "").strip()
            if not approval_id:
                raise ToolError("approval_required",
                                f"{tool.name} needs an approved approval_id",
                                "request one with approval_request, then retry the same "
                                "arguments plus approval_id")
            self._consume_approval(tool, args, approval_id)
            return approval_id
        if not args.get("confirm"):
            raise ToolError("confirm_required",
                            f"{tool.name} is high risk; pass confirm=true to execute")
        return str(args.get("approval_id") or "")

    def _consume_approval(self, tool: Tool, args: dict, approval_id: str) -> None:
        try:
            approval = _call(self.ctx, "GET", f"/api/v1/approvals/{approval_id}")
        except ToolError as exc:
            if exc.code == "not_found":
                raise ToolError("approval_required", "approval not found")
            raise
        if approval.get("status") != "approved":
            raise ToolError("approval_required",
                            f"approval is {approval.get('status')}, not approved")
        if approval.get("used_at"):
            raise ToolError("approval_required", "approval has already been used")
        mission_id = str(args.get("mission_id") or "")
        if mission_id and approval.get("mission_id") != mission_id:
            raise ToolError("approval_required", "approval belongs to a different mission")
        payload = approval.get("payload") or {}
        approved_tool = str(payload.get("tool") or "").strip()
        if approved_tool and approved_tool != tool.name:
            raise ToolError("approval_required",
                            f"approval is for {approved_tool}, not {tool.name}")
        expected = str(payload.get("args_digest") or "")
        if expected and expected != args_digest(tool.name, args):
            raise ToolError("approval_required",
                            "approval was granted for different arguments")
        try:
            _call(self.ctx, "POST", f"/api/v1/approvals/{approval_id}/consume")
        except ToolError as exc:
            raise ToolError("approval_required", f"approval could not be spent: {exc.message}")

    @staticmethod
    def _bucket(tool: Tool) -> str:
        if tool.name in {"scan_start", "mission_start_run", "runs_resume"}:
            return "scan"
        if tool.name == "http_probe":
            return "probe"
        if tool.name == "http_request":
            return "request"
        if tool.name == "inbox_wait":
            return "wait"
        if tool.risk == "high" or not tool.read_only:
            return "mutation"
        return "default"

    def call(self, name: str, arguments: dict | None, actor: str = "") -> tuple[dict, bool]:
        tool = _TOOL_MAP.get(name)
        if tool is None:
            raise ToolError("unknown_tool", f"unknown tool: {name}")
        args = dict(arguments or {})
        actor = actor or self.ctx.actor
        started = time.monotonic()
        approval_id = ""
        status = "ok"
        try:
            _validate(args, tool.input_schema)
            self.ctx.limiter.check(self._bucket(tool))
            approval_id = self._policy_check(tool, args)
            result = _HANDLERS[tool.handler_name](self.ctx, args)
            payload = result if isinstance(result, dict) else {"result": result}
            payload.setdefault("ok", True)
            payload.setdefault("tool", tool.name)
            return payload, False
        except ToolError as exc:
            status = {
                "approval_required": "approval_required",
                "confirm_required": "confirm_required",
                "policy_denied": "denied",
                "scope_denied": "denied",
                "rate_limited": "denied",
            }.get(exc.code, "error")
            payload = exc.payload()
            payload.update({"ok": False, "tool": tool.name, "status": status})
            return payload, True
        finally:
            duration = int((time.monotonic() - started) * 1000)
            mission_id = str(args.get("mission_id") or self.ctx.mission_id or "")
            run_id = str(args.get("run_id") or "")
            result_value = locals().get("payload", {"ok": status == "ok"})
            try:
                self.ctx.plane.request("POST", "/api/v1/tool-calls", body={
                    "tool": tool.name,
                    "risk": tool.risk,
                    "status": status,
                    "actor": actor,
                    "mission_id": mission_id,
                    "run_id": run_id,
                    "approval_id": approval_id,
                    "args": audit_args(tool.name, args),
                    "result": redact_payload(result_value),
                    "error": "" if status == "ok" else str(
                        result_value.get("error", {}).get("message", "")),
                    "duration_ms": duration,
                })
            except Exception:  # noqa: BLE001 - audit failure must not hide the result
                pass
