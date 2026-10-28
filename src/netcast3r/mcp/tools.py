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

import hashlib
import json
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ..scope import ScopeManager

POLICIES = ("readonly", "supervised", "full")
RISK_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}
DEFAULT_POLICY = "supervised"

REDACT_KEYS = {"api_key", "apikey", "authorization", "cookie", "password",
               "secret", "token", "private_key", "session"}

METADATA_HOSTS = {"metadata.google.internal", "metadata.goog"}
METADATA_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}


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
             "allow_manual", "restart") if key in args}
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
                    "args": redact_payload(args),
                    "result": redact_payload(result_value),
                    "error": "" if status == "ok" else str(
                        result_value.get("error", {}).get("message", "")),
                    "duration_ms": duration,
                })
            except Exception:  # noqa: BLE001 - audit failure must not hide the result
                pass
