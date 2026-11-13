"""Deterministic plan compiler.

A goal and a set of observed signals become an ordered, typed step graph over
the real tool catalog. Every step names a tool that exists, the arguments known
from the target, the arguments still missing, and a verification assertion the
deterministic verifier must satisfy before the step counts.

The compiler is model-independent on purpose: with no provider it still emits a
plan and a fallback. A model may only reorder the candidates, never invent a
step or relax a gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_STEPS = 12


@dataclass
class Plan:
    id: str
    title: str
    goal: str
    impact: str
    signals: tuple
    steps: tuple
    followups: tuple = ()
    fallback: str = ""


# Each step carries a ``verify`` assertion in the verifier's vocabulary. The
# checks reference real payload keys, so a passing gate is evidence, not a vibe.
PLANS = (
    Plan(
        id="idor-two-identity",
        title="Prove an object-level authorization gap with two identities",
        goal="Show that one object answers the same for a non-owner identity",
        impact="high",
        signals=("idor", "bola", "object", "authorization", "account",
                 "tenant", "user id", "cross-account", "ownership"),
        steps=(
            {"tool": "access_control_compare",
             "args": {"target": "{target}", "auth_profile": "{profile}"},
             "verify": [{"path": "distinct_responses", "gte": 2}],
             "expected": "the same request answers differently for two identities"},
            {"tool": "idor_sequence_probe",
             "args": {"target": "{target}", "ids": "{ids}"},
             "verify": [{"path": "distinct_shapes", "gte": 2}],
             "expected": "a controlled id shift returns a different object"},
        ),
        followups=("Which other objects share the missing check?",
                   "Does the same gap reach a write endpoint?"),
    ),
    Plan(
        id="sqli-differential",
        title="Detect a SQL injection differential, then extract",
        goal="Turn a syntax-character differential into a value read",
        impact="high",
        signals=("sql", "sqli", "sql injection", "union", "mysql", "database",
                 "error-based", "parameter"),
        steps=(
            {"tool": "injection_differential_probe",
             "args": {"target": "{target}", "parameter": "{parameter}"},
             "verify": [{"path": "differentials", "gte": 1}],
             "expected": "a syntax character changes the response shape or status"},
            {"tool": "oracle_extract",
             "args": {"target": "{target}", "query": "{query}",
                      "true_when": "{true_when}"},
             "verify": [{"path": "length", "gte": 1}],
             "expected": "the oracle returns a non-empty value"},
        ),
        followups=("Is the same parameter injectable in a POST body?",
                   "Can an error-based payload replace the blind oracle?"),
    ),
    Plan(
        id="ssrf-oob",
        title="Prove server-side request forgery with a callback",
        goal="Force a server-side fetch to a controlled endpoint",
        impact="high",
        signals=("ssrf", "server-side request", "callback", "out-of-band",
                 "oob", "169.254.169.254", "url parameter", "link preview"),
        steps=(
            {"tool": "oast_create",
             "args": {"label": "{label}"},
             "verify": [{"path": "session", "present": True}],
             "expected": "a callback endpoint exists to aim the fetch at"},
            {"tool": "http_request",
             "args": {"target": "{target}", "follow_redirects": False},
             "verify": [{"path": "status", "gte": 200, "lte": 599}],
             "expected": "the fetcher accepted the request carrying the callback"},
        ),
        followups=("Did the callback fire, and from which egress address?",
                   "Can the fetch reach cloud metadata?"),
    ),
    Plan(
        id="open-redirect",
        title="Confirm an open redirect to a controlled host",
        goal="Make the server redirect to an attacker-controlled location",
        impact="medium",
        signals=("redirect", "open redirect", "return url", "next parameter",
                 "continue", "destination"),
        steps=(
            {"tool": "http_request",
             "args": {"target": "{target}", "follow_redirects": False},
             "verify": [{"path": "status", "in": [301, 302, 303, 307, 308]},
                        {"path": "headers.location", "present": True}],
             "expected": "a 3xx whose Location names the external host"},
        ),
        followups=("Does the redirect chain into an OAuth callback?",
                   "Is the same parameter present in a POST body?"),
    ),
    Plan(
        id="file-read",
        title="Read application source through a confirmed file read",
        goal="Turn a file-read template into disclosed source or config",
        impact="high",
        signals=("lfi", "local file", "file read", "traversal", "path parameter",
                 "source disclosure"),
        steps=(
            {"tool": "source_disclosure_scan",
             "args": {"read_url": "{read_url}"},
             "verify": [{"path": "files_scanned", "gte": 1}],
             "expected": "at least one source or config file is returned"},
        ),
        followups=("Do the disclosed files carry a credential?",
                   "Can the same template read application code with a sink?"),
    ),
    Plan(
        id="takeover",
        title="Confirm a dangling-CNAME takeover",
        goal="Show a scoped name still delegates to an unclaimed service",
        impact="high",
        signals=("takeover", "dangling cname", "unclaimed", "subdomain",
                 "cname"),
        steps=(
            {"tool": "takeover_scan",
             "args": {"target": "{target}"},
             "verify": [{"path": "counts.vulnerable", "gte": 1}],
             "expected": "a name resolves to a provider that no longer owns it"},
        ),
        followups=("Is the provider serving attacker content for the name?",),
    ),
    Plan(
        id="cache-poison",
        title="Confirm a cache poisoning of an unkeyed header",
        goal="Make one response cache a value the origin reflected",
        impact="high",
        signals=("cache", "cache poisoning", "x-forwarded-host", "unkeyed",
                 "cache deception"),
        steps=(
            {"tool": "cache_audit",
             "args": {"target": "{target}", "mode": "poisoning"},
             "verify": [{"path": "poisoning.counts.poisoned", "gte": 1}],
             "expected": "a canary survives a replay without the header"},
        ),
        followups=("Does the poisoned key reach a logged-in user?",),
    ),
    Plan(
        id="graphql-authz",
        title="Exercise GraphQL field-level authorization",
        goal="Reach a field or object one identity should not see",
        impact="high",
        signals=("graphql", "introspection", "resolver", "mutation", "node",
                 "batching"),
        steps=(
            {"tool": "graphql_probe",
             "args": {"target": "{target}"},
             "verify": [{"path": "findings.0.id", "present": True}],
             "expected": "the endpoint exposes schema or batching surface"},
            {"tool": "access_control_compare",
             "args": {"target": "{target}", "auth_profile": "{profile}"},
             "verify": [{"path": "distinct_responses", "gte": 2}],
             "expected": "two identities receive different data for one query"},
        ),
        followups=("Can a batched query bypass the rate limit?",
                   "Does a node() lookup cross tenants?"),
    ),
    Plan(
        id="websocket-cswsh",
        title="Confirm cross-site WebSocket hijacking",
        goal="Open the socket from a hostile origin with the victim's cookies",
        impact="high",
        signals=("websocket", "cswsh", "ws", "wss", "socket"),
        steps=(
            {"tool": "ws_audit",
             "args": {"target": "{target}"},
             "verify": [{"path": "verdict", "eq": "cswsh"}],
             "expected": "the server completes a cross-origin upgrade"},
        ),
        followups=("Which frame triggers a privileged action?",),
    ),
    Plan(
        id="jwt-forge",
        title="Forge a token from a recovered key and replay it",
        goal="Show a recovered secret forges an accepted token",
        impact="critical",
        signals=("jwt", "json web token", "alg", "kid", "signing key",
                 "hmac secret"),
        steps=(
            {"tool": "jwt_forge",
             "args": {"key": "{key}", "claims": "{claims}",
                      "algorithm": "HS256"},
             "verify": [{"path": "token", "present": True}],
             "expected": "a token is produced from the recovered key"},
        ),
        followups=("Does the forged token open a protected endpoint?",),
    ),
    Plan(
        id="generic-recon",
        title="Fingerprint and inventory the surface",
        goal="Establish a baseline before any exploit attempt",
        impact="medium",
        signals=(),
        steps=(
            {"tool": "http_probe",
             "args": {"target": "{target}"},
             "verify": [{"path": "status", "gte": 200, "lte": 599}],
             "expected": "the target answers with a status and a title"},
        ),
        followups=("Which routes and parameters are reachable?",),
        fallback="If the probe is refused, confirm scope and reachability first.",
    ),
)

_IMPACT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def library(query: str = "", limit: int = 50) -> dict:
    """Browse the plan library."""
    q = (query or "").strip().lower()
    items = []
    for plan in PLANS:
        text = " ".join([plan.id, plan.title, plan.goal, *plan.signals]).lower()
        if q and q not in text:
            continue
        items.append({
            "id": plan.id, "title": plan.title, "goal": plan.goal,
            "impact": plan.impact, "signals": list(plan.signals),
            "steps": [step["tool"] for step in plan.steps],
            "followups": list(plan.followups),
        })
    return {"items": items[:max(1, min(int(limit or 50), 100))],
            "total": len(items),
            "note": "A plan is a hypothesis with gates; each step must pass to count."}


def _tokens(text: str) -> set:
    return {token for token in re.split(r"[^a-z0-9.+#-]+", str(text).lower())
            if token}


def rank(goal: str = "", signals=None, limit: int = 3) -> list:
    """Rank library plans by signal overlap. Deterministic, ties by impact."""
    context = " ".join([goal or "", *(str(v) for v in (signals or []))]).lower()
    tokens = _tokens(context)
    scored = []
    for plan in PLANS:
        hits = []
        for signal in plan.signals:
            text = signal.lower()
            if (" " in text or "-" in text):
                if text in context:
                    hits.append(signal)
            elif text in tokens:
                hits.append(signal)
        score = 3 * len(hits)
        if not context and plan.id == "generic-recon":
            score = 1
        if score or (not context and plan.impact == "medium"):
            scored.append((score, _IMPACT.get(plan.impact, 0), plan, hits))
    if not scored:
        only = next((p for p in PLANS if p.id == "generic-recon"), None)
        return [{"plan": only, "score": 0, "why": []}] if only else []
    scored.sort(key=lambda row: (row[0], row[1]), reverse=True)
    return [{"plan": plan, "score": score, "why": hits}
            for score, _impact, plan, hits in scored[:max(1, int(limit))]]


def _fill(value, variables: dict):
    if isinstance(value, str):
        for key, replacement in variables.items():
            value = value.replace("{%s}" % key, str(replacement))
        return value
    if isinstance(value, dict):
        return {key: _fill(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [_fill(item, variables) for item in value]
    return value


def _tool_schema(tool: str) -> dict:
    try:
        from .mcp.tools import _TOOL_MAP
        definition = _TOOL_MAP.get(tool)
        return getattr(definition, "input_schema", {}) or {}
    except Exception:  # noqa: BLE001 - a missing catalog must not crash the planner
        return {}


def compile_plan(goal: str = "", target: str = "", signals=None,
                 mission_id: str = "", profile: str = "", extra=None,
                 candidates: bool = True) -> dict:
    """Compile the best-matching plan into a typed, gated step graph."""
    variables = {"target": target, "mission_id": mission_id, "profile": profile,
                 "label": mission_id or "plan"}
    variables.update({str(k): v for k, v in (extra or {}).items() if v})
    ranked = rank(goal, signals, limit=3)
    if not ranked:
        return {"ok": False, "reason": "no plan matches", "candidates": []}

    compiled = []
    for row in ranked:
        plan = row["plan"]
        steps = []
        ready_all = True
        for number, step in enumerate(list(plan.steps)[:MAX_STEPS], start=1):
            tool = step["tool"]
            schema = _tool_schema(tool)
            if not schema:
                steps.append({"n": number, "tool": tool, "known": False,
                              "missing_arguments": [],
                              "reason": "tool is not in the catalog"})
                ready_all = False
                continue
            args = _fill(step["args"], variables)
            if mission_id and "mission_id" in (schema.get("properties") or {}):
                args.setdefault("mission_id", mission_id)
            missing: list = []
            for name, value in args.items():
                if isinstance(value, str) and "{" in value:
                    missing.append(name)
            for name in (schema.get("required") or []):
                if name not in missing and (
                        name not in args or args[name] in ("", None, [])
                        or (isinstance(args[name], str) and "{" in args[name])):
                    missing.append(name)
            ready = not missing
            ready_all = ready_all and ready
            steps.append({
                "n": number, "tool": tool, "known": True,
                "risk": getattr(next((t for t in _catalog() if t.name == tool), None),
                                "risk", "") or "",
                "args": args, "verify": step.get("verify") or [],
                "expected": step.get("expected", ""),
                "read_only": bool(getattr(
                    next((t for t in _catalog() if t.name == tool), None),
                    "read_only", False)),
                "missing_arguments": missing, "ready": ready,
            })
        compiled.append({
            "id": plan.id, "title": plan.title, "impact": plan.impact,
            "why": row["why"], "score": row["score"], "steps": steps,
            "followups": list(plan.followups), "fallback": plan.fallback,
            "ready": ready_all and bool(steps),
        })

    best = compiled[0]
    result = {
        "goal": goal, "target": target, "mission_id": mission_id,
        "chosen": best["id"], "title": best["title"], "impact": best["impact"],
        "why": best["why"], "steps": best["steps"],
        "followups": best["followups"], "fallback": best["fallback"],
        "ready": best["ready"],
        "missing_arguments": sorted({name for step in best["steps"]
                                     for name in step.get("missing_arguments", [])}),
        "note": ("A step counts only when the verifier passes its assertion. "
                 "Supply the missing arguments to make the plan ready."),
    }
    if candidates:
        result["candidates"] = [{"id": row["id"], "title": row["title"],
                                 "score": row["score"], "impact": row["impact"],
                                 "ready": row["ready"]} for row in compiled]
    return result


def _catalog():
    try:
        from .mcp.tools import TOOLS
        return TOOLS
    except Exception:  # noqa: BLE001
        return []


def summary() -> dict:
    return {
        "plans": [plan.id for plan in PLANS],
        "count": len(PLANS),
        "note": "Compiled plans are hypotheses with deterministic gates.",
    }
