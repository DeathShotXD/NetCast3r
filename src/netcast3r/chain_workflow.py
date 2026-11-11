"""Typed exploit-chain execution.

A confirmed finding is not the end of an engagement. This module runs a
bounded, ordered chain of typed steps:

    extract -> auth_profile -> http -> assert -> exploit_run -> token_pivot

Every step goes through the same MCP tool registry as the rest of NetCast3r,
so mission scope, risk tiers, approvals, and the audit trail still apply. A
chain never creates a finding; it produces observations and candidates for the
operator to validate.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from . import authstore, toolshed
from .server.keys import mask

MAX_STEPS = 40
MAX_SECONDS = 900.0
MAX_RESULT = 12000

_VAR = re.compile(r"\{\{\s*([A-Za-z0-9_.\[\]-]+)\s*\}\}")
_SECRET_KEYS = ("token", "secret", "password", "passwd", "cookie",
                "authorization", "key", "credential", "session")

TEMPLATES: dict[str, dict] = {
    "git-to-source-audit": {
        "description": "Recover an exposed .git repo, then run codeaudit and REA on it.",
        "steps": [
            {"kind": "tool", "tool": "git_dump",
             "args": {"target": "{{target}}", "mission_id": "{{mission_id}}"}},
            {"kind": "tool", "tool": "codeaudit_scan",
             "args": {"path": "{{last.dest}}", "max_files": 5000}},
            {"kind": "tool", "tool": "reveng_analyze",
             "args": {"kind": "source", "path": "{{last.path}}",
                      "max_files": 5000}},
        ],
    },
    "token-to-auth-profile": {
        "description": "Store a recovered token/cookie, replay it, and check where it pivots.",
        "steps": [
            {"kind": "auth_profile", "name": "{{profile}}",
             "headers": {"Authorization": "{{token}}"},
             "note": "captured by chain_execute"},
            {"kind": "http", "args": {"target": "{{target}}", "method": "GET",
                                      "auth_profile": "{{profile}}",
                                      "follow_redirects": False}},
            {"kind": "assert", "status": 200, "required": True},
            {"kind": "pivot", "hosts": "{{hosts}}", "header": "Authorization",
             "token": "{{token}}", "path": "{{path}}"},
        ],
    },
    "jwt-forge-to-auth-profile": {
        "description": "Forge an HS256 token from a recovered key, store it, and replay it.",
        "steps": [
            {"kind": "tool", "tool": "jwt_forge",
             "args": {"key": "{{key}}", "claims": "{{claims}}",
                      "algorithm": "HS256"}},
            {"kind": "auth_profile", "name": "{{profile}}",
             "headers": {"Authorization": "{{last.token}}"},
             "note": "forged token from recovered key"},
            {"kind": "http", "args": {"target": "{{target}}", "method": "GET",
                                      "auth_profile": "{{profile}}",
                                      "follow_redirects": False}},
            {"kind": "assert", "status": 200, "required": False},
        ],
    },
    "sqli-union-to-data": {
        "description": "Send one UNION payload and assert that the response carries it.",
        "steps": [
            {"kind": "http", "args": {"target": "{{target}}", "method": "POST",
                                      "form": "{{form}}",
                                      "follow_redirects": False}},
            {"kind": "assert", "body_contains": "{{marker}}", "required": True},
            {"kind": "extract", "from": "last.body", "regex": "{{regex}}",
             "name": "evidence", "required": True},
        ],
    },
}


class ChainError(RuntimeError):
    """A step failed or the chain input is invalid."""


def list_templates() -> list[dict]:
    return [{"name": name, "description": item["description"],
             "steps": len(item["steps"])}
            for name, item in sorted(TEMPLATES.items())]


def _get_path(value, path: str):
    current = value
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", str(path or "")):
        if part.startswith("[") and part.endswith("]"):
            index = int(part[1:-1])
            if not isinstance(current, (list, tuple)) or index >= len(current):
                raise KeyError(path)
            current = current[index]
            continue
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        raise KeyError(path)
    return current


def _lookup(path: str, variables: dict, last):
    if path.startswith("last."):
        return _get_path(last, path[5:])
    if path == "last":
        return last
    if path.startswith("vars."):
        return _get_path(variables, path[5:])
    if path == "vars":
        return variables
    if path in variables:
        return variables[path]
    return _get_path(variables, path)


def _bind(value, variables: dict, last):
    if isinstance(value, str):
        exact = _VAR.fullmatch(value.strip())
        if exact:
            return _lookup(exact.group(1), variables, last)
        def replace(match):
            try:
                return str(_lookup(match.group(1), variables, last))
            except KeyError:
                return match.group(0)
        return _VAR.sub(replace, value)
    if isinstance(value, dict):
        return {str(k): _bind(v, variables, last) for k, v in value.items()}
    if isinstance(value, list):
        return [_bind(item, variables, last) for item in value]
    return value


def _clip(value):
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    if len(text) <= MAX_RESULT:
        return value
    return {"truncated": True, "preview": text[:MAX_RESULT]}


def _public_vars(variables: dict) -> dict:
    out = {}
    for name, value in variables.items():
        if any(secret in name.lower() for secret in _SECRET_KEYS):
            out[name] = mask(str(value))
        else:
            out[name] = value if isinstance(value, (int, float, bool)) else str(value)[:300]
    return out


def _with_mission(tool: str, args: dict, mission_id: str) -> dict:
    """Add mission_id only when the tool's schema accepts it."""
    if not mission_id or not isinstance(args, dict):
        return args
    from .mcp.tools import _TOOL_MAP

    spec = _TOOL_MAP.get(tool)
    properties = (getattr(spec, "input_schema", {}) or {}).get("properties", {})
    if "mission_id" in properties and not args.get("mission_id"):
        args = {**args, "mission_id": mission_id}
    return args


def _registry(server, mission_id: str, policy: str):
    from .mcp.tools import ToolContext, ToolRegistry
    from .server.agent_runtime import LocalPlane

    mission = server.index.get_mission(mission_id) or {}
    authorized = (str(mission.get("status") or "") == "active"
                  and str(mission.get("autonomy") or "") == "autonomous")
    ctx = ToolContext(plane=LocalPlane(server), policy=str(policy or "full"),
                      base=getattr(server, "base", None), actor="agent:chain",
                      mission_id=mission_id, authorized=authorized)
    return ToolRegistry(ctx)


def execute(server, mission_id: str, steps: list[dict],
            policy: str = "full", dry_run: bool = False,
            variables: dict | None = None) -> dict:
    """Execute one chain. Returns a step log and masked variables."""
    mission_id = str(mission_id or "").strip()
    mission = server.index.get_mission(mission_id) if mission_id else None
    if not mission:
        raise ChainError("mission not found")
    if str(mission.get("status") or "") != "active":
        raise ChainError("mission is not active")
    if not isinstance(steps, list) or not steps:
        raise ChainError("steps must be a non-empty list")
    if len(steps) > MAX_STEPS:
        raise ChainError(f"at most {MAX_STEPS} steps")
    policy = str(policy or "full").lower()
    if policy not in {"readonly", "supervised", "full"}:
        raise ChainError("policy must be readonly, supervised, or full")
    registry = _registry(server, mission_id, policy)
    variables: dict = {"mission_id": mission_id,
                       **(variables if isinstance(variables, dict) else {})}
    last = None
    log: list[dict] = []
    started = time.monotonic()
    status = "ok"
    for index, step in enumerate(steps):
        if time.monotonic() - started > MAX_SECONDS:
            status = "stopped"
            log.append({"index": index, "kind": "timeout",
                        "ok": False, "error": "chain time budget exceeded"})
            break
        if not isinstance(step, dict):
            raise ChainError(f"step {index} is not an object")
        kind = str(step.get("kind") or "").strip().lower()
        required = bool(step.get("required", True))
        try:
            args = _bind(step.get("args") or {}, variables, last)
            if dry_run:
                log.append({"index": index, "kind": kind, "ok": True,
                            "planned": _clip(args)})
                continue
            if kind == "http":
                args = _with_mission("http_request", args, mission_id)
                payload, is_error = registry.call("http_request", args,
                                                  actor="agent:chain")
            elif kind == "tool":
                tool = str(step.get("tool") or "").strip()
                if not tool:
                    raise ChainError("tool step needs tool")
                args = _with_mission(tool, args, mission_id)
                payload, is_error = registry.call(tool, args, actor="agent:chain")
            elif kind == "script":
                name = str(step.get("name") or "").strip()
                if not name:
                    raise ChainError("script step needs name")
                script_args = step.get("args") or []
                script_args = [str(item) for item in script_args] \
                    if isinstance(script_args, list) else []
                payload = toolshed.run_script(
                    server.index, getattr(server, "base", None), name,
                    args=script_args, timeout=int(step.get("timeout") or 60),
                    mission_id=mission_id)
                is_error = payload.get("status") != "ok"
            elif kind == "auth_profile":
                name = str(step.get("name") or "").strip()
                if not name:
                    raise ChainError("auth_profile step needs name")
                payload = authstore.set_profile(
                    name,
                    headers=_bind(step.get("headers") or {}, variables, last),
                    cookies=_bind(step.get("cookies") or {}, variables, last),
                    note=str(step.get("note") or "chain_execute"),
                    base=getattr(server, "base", None))
                is_error = False
            elif kind == "extract":
                from_path = str(step.get("from") or "last")
                if "{{" in from_path:
                    source = _bind(from_path, variables, last)
                else:
                    source = _lookup(from_path, variables, last)
                value = None
                if step.get("json_path"):
                    value = _get_path(source, str(step["json_path"]))
                elif step.get("regex"):
                    text = source if isinstance(source, str) else json.dumps(
                        source, default=str)
                    match = re.search(str(step["regex"]), text)
                    if match:
                        value = match.group(int(step.get("group") or 1))
                if value is None:
                    raise ChainError("extract found no value")
                name = str(step.get("name") or "value").strip()
                variables[name] = value
                payload = {"name": name,
                           "value": mask(str(value))
                           if step.get("secret") else str(value)[:500]}
                is_error = False
            elif kind == "assert":
                payload = {"passed": True}
                is_error = False
                current = last or {}
                if step.get("status") is not None:
                    actual = current.get("status")
                    if actual is None and isinstance(current.get("result"), dict):
                        actual = current["result"].get("status")
                    if int(actual or 0) != int(step["status"]):
                        raise ChainError(
                            f"assert status {step['status']} != {actual}")
                if step.get("body_contains"):
                    needle = str(_bind(step["body_contains"], variables, last))
                    haystack = json.dumps(current, default=str)
                    if isinstance(current, dict):
                        body = current.get("body")
                        if isinstance(body, str):
                            haystack += "\n" + body
                        nested = current.get("result")
                        if isinstance(nested, dict) and isinstance(nested.get("body"), str):
                            haystack += "\n" + nested["body"]
                    if needle not in haystack:
                        raise ChainError("assert body marker missing")
                if step.get("var"):
                    name = str(step["var"])
                    if name not in variables:
                        raise ChainError(f"assert variable missing: {name}")
                    if "equals" in step and variables[name] != step["equals"]:
                        raise ChainError(f"assert variable {name} mismatch")
                if step.get("not_empty"):
                    if not current:
                        raise ChainError("assert empty result")
            elif kind == "pivot":
                hosts = _bind(step.get("hosts") or [], variables, last)
                token = str(_bind(step.get("token") or "", variables, last))
                if isinstance(hosts, str):
                    hosts = [hosts]
                payload, is_error = registry.call("token_pivot", {
                    "hosts": hosts,
                    "header": str(step.get("header") or "Authorization"),
                    "token_value": token,
                    "path": str(step.get("path") or "/"),
                    "mission_id": mission_id,
                }, actor="agent:chain")
            else:
                raise ChainError(f"unknown step kind: {kind}")
            last = payload
            log.append({"index": index, "kind": kind, "ok": not is_error,
                        "result": _clip(payload)})
            if is_error and required:
                status = "failed"
                break
        except Exception as exc:  # noqa: BLE001 - a chain step must not crash the API
            log.append({"index": index, "kind": kind, "ok": False,
                        "error": f"{type(exc).__name__}: {exc}"})
            if required:
                status = "failed"
                break
    return {
        "mission_id": mission_id,
        "status": status,
        "steps": log,
        "vars": _public_vars(variables),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "note": ("A chain produces observations and candidates, never findings. "
                 "Scope, risk, and approval gates still apply to every step."),
    }
