"""Deterministic learning from real tool calls and runs.

NetCast3r does not let a model invent experience. A lesson is written only
from a record the control plane already stored: a tool call, a task, or a run.
The reflection is heuristic, so it is reproducible and cheap. A model may be
used later to rewrite the lesson, but the evidence stays the stored record.

The goal is compounding operational memory:

* a policy denial teaches the next plan to request the right approval;
* a scope denial teaches it to check the scope first;
* a timeout teaches it to back off or shrink the request;
* a success names the technique, target class, and evidence that worked.

Skills are longer markdown documents (a technique, a checklist, a write-up
digest) that an agent can load before planning.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from . import research, selfmodel

SCOPE_HINTS = ("scope", "out of scope", "scope_denied", "target is outside")
APPROVAL_HINTS = ("approval", "confirm", "policy_denied", "readonly")
TIMEOUT_HINTS = ("timeout", "timed out", "rate limit", "429", "too many requests")
CONNECT_HINTS = (
    "connecterror", "connecttimeout", "readtimeout", "remoteprotocolerror",
    "remotedisconnected", "connection refused", "connection reset",
    "network is unreachable", "host is unreachable", "unreachable",
    "name or service not known", "nodename nor servname", "temporary failure in name resolution",
    "no address associated with hostname", "probe failed", "request failed",
)
TLS_HINTS = (
    "ssl", "tls", "certificate", "cert", "handshake",
    "certificate_verify_failed", "unable to get local issuer",
)
DEAD_LESSON_HINTS = CONNECT_HINTS + TLS_HINTS + (
    "timeout", "timed out", "dead", "down", "offline", "dns",
    "http_probe", "http_request", "reliability",
)
AUTH_HINTS = ("401", "403", "unauthorized", "forbidden", "insufficient_scope")
NOTFOUND_HINTS = ("404", "not found", "not_found")
INPUT_HINTS = ("invalid", "required", "must be", "unknown argument", "validation")
_ERROR_CLASS_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Timeout))\b")


def _host(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        if "://" in raw:
            return (urlsplit(raw).hostname or "").lower().rstrip(".")
        return raw.split("/", 1)[0].split(":", 1)[0].lower().rstrip(".")
    except ValueError:
        return ""


def _target(args: dict) -> str:
    for key in ("target", "url", "host", "domain", "endpoint"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return _host(value.strip())
    return ""


def classify_error(error: str, status: str = "") -> str:
    """Return a stable error_class token for failure lessons."""
    raw = str(error or "").strip()
    text = raw.lower()
    if "connecterror" in text:
        return "ConnectError"
    if any(hint in text for hint in TLS_HINTS):
        return "TLSError"
    if any(hint in text for hint in ("connecttimeout", "readtimeout", "timeout", "timed out")):
        return "TimeoutError"
    if any(hint in text for hint in CONNECT_HINTS):
        return "ConnectError"
    match = _ERROR_CLASS_RE.search(raw)
    if match:
        return match.group(1)
    if status in {"denied"}:
        return "policy_denied"
    if status in {"approval_required", "confirm_required"}:
        return status
    if any(hint in text for hint in SCOPE_HINTS):
        return "scope_denied"
    if any(hint in text for hint in APPROVAL_HINTS):
        return "policy_denied"
    if any(hint in text for hint in AUTH_HINTS):
        return "auth_error"
    if any(hint in text for hint in NOTFOUND_HINTS):
        return "not_found"
    if any(hint in text for hint in INPUT_HINTS):
        return "input_error"
    return "tool_error"


def is_host_unreachable_text(text: str) -> bool:
    """True when text describes a connectivity, TLS, timeout, or host-dead failure."""
    low = str(text or "").lower()
    return any(hint in low for hint in DEAD_LESSON_HINTS)


def _classify(error: str, status: str) -> tuple[str, str, str]:
    text = (error or "").lower()
    if status in {"denied"}:
        return ("blocked", "policy", "Request the matching approval or switch to a read-only step.")
    if status in {"approval_required", "confirm_required"}:
        return ("blocked", "approval",
                "Create an approval bound to the exact arguments, then retry once.")
    if any(hint in text for hint in SCOPE_HINTS):
        return ("failure", "scope",
                "Check the mission scope before the next active request.")
    if any(hint in text for hint in APPROVAL_HINTS):
        return ("blocked", "policy",
                "Use an allowed tool or request a single-use approval.")
    if any(hint in text for hint in TLS_HINTS) or "connecterror" in text:
        return ("failure", "reliability",
                "Retry with TLS fallback (verify_tls=false) or alternate path before parking the host.")
    if any(hint in text for hint in TIMEOUT_HINTS) or any(hint in text for hint in CONNECT_HINTS):
        return ("failure", "reliability",
                "Reduce the request, lower concurrency, and add a backoff before retrying.")
    if any(hint in text for hint in AUTH_HINTS):
        return ("partial", "auth",
                "Capture or refresh the auth profile, then confirm the session before retrying.")
    if any(hint in text for hint in NOTFOUND_HINTS):
        return ("failure", "routing",
                "Confirm the path or object id; try the documented route before fuzzing.")
    if any(hint in text for hint in INPUT_HINTS):
        return ("failure", "input",
                "Read the schema and send the smallest valid request.")
    return ("failure", "tooling",
            "Read the last output, fix the smallest cause, and retry once.")


def reflect_tool_call(record: dict) -> dict:
    """Turn one stored tool call into a lesson draft."""
    tool = str(record.get("tool") or "unknown")
    status = str(record.get("status") or "ok")
    error = str(record.get("error") or "")
    args = record.get("args") if isinstance(record.get("args"), dict) else {}
    result = record.get("result") if isinstance(record.get("result"), dict) else {}
    target = _target(args) or _host(str(record.get("target") or record.get("context") or ""))
    error_class = ""
    provisional = False
    if status == "ok":
        outcome, technique, next_step = "success", tool, "Repeat the same shape on the next in-scope object."
        lesson = f"{tool} succeeded" + (f" against {target}" if target else "") + "."
        if isinstance(result.get("status"), int):
            lesson += f" Observed HTTP {result['status']}."
        tags = ["success", tool]
    else:
        outcome, category, next_step = _classify(error, status)
        error_class = classify_error(error, status)
        provisional = True
        technique = tool
        lesson = f"{tool} returned {status or 'an error'}" + (f": {error[:240]}" if error else ".")
        tags = [outcome, category, tool, error_class, f"error_class:{error_class}", "provisional=true"]
        if any(hint in error.lower() for hint in TLS_HINTS):
            tags.append("tls")
    if target:
        tags.append(target)
        if status != "ok":
            tags.append(f"host:{target}")
    draft = {
        "title": f"{tool}: {outcome}",
        "lesson": lesson,
        "technique": technique,
        "context": target,
        "outcome": outcome,
        "next_step": next_step,
        "tags": sorted(set(tags)),
        "source": f"tool_call:{record.get('id', '')}",
        "confidence": 0.8 if outcome in {"success", "failure"} else 0.6,
        "mission_id": str(record.get("mission_id") or ""),
        "run_id": str(record.get("run_id") or ""),
        "host": target,
        "error_class": error_class,
        "provisional": provisional,
    }
    if error_class:
        draft["lesson"] = (
            f"{draft['lesson']} error_class={error_class}"
            + (" provisional=true" if provisional else "")
        ).strip()
    return draft


def reflect_run(index, run_id: str, limit: int = 200) -> dict:
    """Summarize a run's tool failures and successes into one lesson."""
    run = index.get_run(run_id)
    if not run:
        raise ValueError("run not found")
    calls, _ = index.list_tool_calls(run_id=run_id, limit=limit)
    if not calls:
        events = index.list_events(run_id, limit=limit)
        errors = [event for event in events if event.get("level") in {"error", "warn"}]
        outcomes = {"success": 0, "failure": 0, "partial": 0, "blocked": 0}
        lesson = f"Run {run_id} produced no tool calls; {len(errors)} warning/error events."
        return {
            "title": "run without tool calls",
            "lesson": lesson, "technique": "", "context": str(run.get("target") or ""),
            "outcome": "partial" if errors else "success",
            "next_step": "Check the runner logs before retrying." if errors else
                         "Start with a scope check and one probe.",
            "tags": ["run", "events"], "source": f"run:{run_id}",
            "confidence": 0.5, "mission_id": str(run.get("mission_id") or ""),
            "run_id": run_id,
        }
    failures = [call for call in calls if call.get("status") != "ok"]
    successes = [call for call in calls if call.get("status") == "ok"]
    if failures:
        first = failures[0]
        draft = reflect_tool_call(first)
        draft.update({
            "title": f"run {run_id}: {len(failures)} failed tool call(s)",
            "lesson": (f"{len(failures)} of {len(calls)} tool calls failed; the first was "
                       f"{first.get('tool')}: {str(first.get('error') or '')[:240]}"),
            "outcome": "partial" if successes else "failure",
            "next_step": draft["next_step"],
            "source": f"run:{run_id}",
            "run_id": run_id,
            "tags": sorted(set(draft["tags"] + ["run"])),
        })
        return draft
    return {
        "title": f"run {run_id}: all tool calls succeeded",
        "lesson": f"{len(calls)} tool calls succeeded against {run.get('target') or 'the target'}.",
        "technique": successes[-1].get("tool", ""),
        "context": str(run.get("target") or ""),
        "outcome": "success",
        "next_step": "Deepen the same surface with an authenticated request or a path differential.",
        "tags": ["run", "success"],
        "source": f"run:{run_id}",
        "confidence": 0.7,
        "mission_id": str(run.get("mission_id") or ""),
        "run_id": run_id,
    }


def suggest_next(index, mission_id: str, limit: int = 8) -> dict:
    """Rank concrete next actions from the mission, findings, and lessons."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    target = str(mission.get("target") or "")
    host = _host(target)
    slug = host.split(".")[0] if host else ""
    findings, _ = index.list_findings(q=host, limit=20)
    lessons, _ = index.list_lessons(mission_id=mission_id, limit=20)
    matched, _ = index.list_lessons(q=host, limit=20)
    seen = {item["id"] for item in lessons}
    lessons.extend(item for item in matched if item["id"] not in seen)
    if slug:
        tagged, _ = index.list_lessons(tag=slug, limit=20)
        seen = {item["id"] for item in lessons}
        lessons.extend(item for item in tagged if item["id"] not in seen)
    calls, _ = index.list_tool_calls(mission_id=mission_id, limit=50)
    expertise = index.list_expertise(limit=10)
    signal_tokens: set[str] = set()
    if host:
        signal_tokens.add(host)
        if slug:
            signal_tokens.add(slug)
    for item in expertise[:5]:
        signal_tokens.add(str(item.get("tech") or "").lower())
    for lesson in lessons[:8]:
        if not lesson_is_active(lesson):
            continue
        for tag in (lesson.get("tags") or []):
            low = str(tag).lower()
            if low and low not in {"success", "failure", "partial", "blocked", "run"}:
                signal_tokens.add(low)
    verified_skills, _ = index.list_skills(tag="verified-ttp", status="active", limit=40)
    ranked_verified = sorted(
        verified_skills,
        key=lambda row: _skill_signal_overlap(row, signal_tokens),
        reverse=True,
    )
    actions: list[dict] = []

    def add(title: str, why: str, tool: str, args: dict, risk: str = "low") -> None:
        if len(actions) < limit:
            actions.append({"title": title, "why": why, "tool": tool,
                            "args": args, "risk": risk})

    for skill in ranked_verified:
        overlap = _skill_signal_overlap(skill, signal_tokens)
        if overlap <= 0:
            continue
        add(
            f"Load verified playbook: {skill.get('title') or skill.get('name')}",
            f"verified-ttp skill matches {overlap} mission signal(s)",
            "skills_get",
            {"name": skill.get("name") or skill.get("id")},
            "low",
        )
        if len(actions) >= min(3, limit):
            break

    if not calls:
        add("Confirm scope and fingerprint the target",
            "no tool calls are recorded for this mission yet",
            "http_probe", {"target": target, "mission_id": mission_id}, "medium")
    if any(call.get("status") == "denied" for call in calls):
        add("Request the approval for the denied step",
            "a previous call was blocked by policy",
            "approval_request", {"mission_id": mission_id,
                                 "tool": next(c["tool"] for c in calls
                                              if c.get("status") == "denied")}, "medium")
    if findings:
        untriaged = [f for f in findings if f.get("triage_status") in {"new", "in_progress"}]
        if untriaged:
            add("Finish the evidence for the open finding",
                f"{len(untriaged)} finding(s) still need proof or triage",
                "finding_artifact_add",
                {"finding_id": untriaged[0]["id"], "name": "evidence.txt",
                 "content": "replace with the captured request/response"}, "medium")
    try:
        open_hypotheses, _ = index.list_hypotheses(
            mission_id=mission_id, status="open", limit=5)
        supported, _ = index.list_hypotheses(
            mission_id=mission_id, status="supported", limit=5)
    except (ValueError, AttributeError):
        open_hypotheses, supported = [], []
    for hypothesis in supported[:2]:
        add(f"Promote the supported hypothesis: {hypothesis['title']}",
            "its assertion-based test passed but it is not a finding yet",
            "hypothesis_promote",
            {"hypothesis_id": hypothesis["id"], "title": hypothesis["title"],
             "severity": "medium", "impact": "replace with the demonstrated impact"},
            "medium")
    for hypothesis in open_hypotheses[:2]:
        add(f"Test the open hypothesis: {hypothesis['title']}",
            f"recorded for {hypothesis.get('target')} and not resolved yet",
            "hypothesis_test",
            {"hypothesis_id": hypothesis["id"], "steps": []}, "medium")
    for lesson in lessons[:3]:
        if not lesson_is_active(lesson):
            continue
        if lesson.get("next_step"):
            add(lesson["next_step"], f"lesson: {lesson.get('title')}",
                "lessons_get", {"lesson_id": lesson["id"]}, "low")
    if not findings:
        add("Test the authenticated surface with the saved profile",
            "no finding exists yet; the highest-value next step is an authenticated object check",
            "http_request", {"target": target, "mission_id": mission_id,
                             "method": "GET", "auth_profile": ""}, "medium")
        add("Compare path encodings on the main API route",
            "authorization layers often disagree with the router about encoding",
            "http_path_diff", {"target": target, "mission_id": mission_id,
                               "max_variants": 12}, "medium")
    tech_actions = {
        "wordpress": ("Enumerate WordPress plugins, themes, and REST users",
                      "this instance has WordPress exposure in its lessons",
                      "recon_passive", {"tool": "whatweb", "target": target,
                                        "mission_id": mission_id}),
        "graphql": ("Test GraphQL introspection and field-level authorization",
                    "this instance has GraphQL exposure in its lessons",
                    "http_request", {"target": target, "mission_id": mission_id,
                                     "method": "POST", "json": {"query": "{__typename}"}}),
        "oauth": ("Test OAuth redirect_uri, state, and audience handling",
                  "this instance has OAuth exposure in its lessons",
                  "http_request", {"target": target, "mission_id": mission_id,
                                   "method": "GET"}),
        "saml": ("Test SAML signature wrapping and audience validation",
                 "this instance has SAML exposure in its lessons",
                 "http_request", {"target": target, "mission_id": mission_id,
                                  "method": "GET"}),
        "php": ("Check for exposed backups, .env, phpinfo, and debug pages",
                "this instance has PHP exposure in its lessons",
                "http_request", {"target": target, "mission_id": mission_id,
                                 "method": "GET"}),
        "api": ("Run the two-account object matrix on the documented API",
                "this instance has API exposure in its lessons",
                "http_request", {"target": target, "mission_id": mission_id,
                                 "method": "GET"}),
    }
    for item in expertise[:3]:
        action = tech_actions.get(item["tech"])
        if action and item["exposures"] >= 2:
            add(action[0], f"{action[1]} ({item['exposures']} exposures, "
                           f"{item['confidence']:.0%} success)",
                action[2], action[3], "medium")
    capability = {}
    try:
        capability = selfmodel.gaps(index, limit=3)
        for gap in capability.get("items", [])[:2]:
            add(gap["action"], f"capability gap: {gap['label']} ({gap['gap']})",
                gap["tool"], gap["args"], "low")
    except Exception:  # noqa: BLE001 - a gap read must not break planning
        capability = {}
    try:
        plan = research.plan(index, target=target, tech=slug, limit=2)
        for item in plan.get("items", [])[:1]:
            why = ", ".join(item.get("why") or []) or item["class"]
            add(f"Test the technique: {item['title']}",
                f"research match ({why}); proof: {item['proof'][:120]}",
                "technique_plan",
                {"target": target, "tech": slug, "limit": 3}, "low")
    except Exception:  # noqa: BLE001 - research ranking must not break planning
        plan = {}
    if not actions:
        add("Re-read the latest run output and pick one unexplained response",
            "the obvious paths are covered; deepen the evidence instead of widening",
            "runs_events", {"run_id": mission.get("last_run_id") or ""}, "low")
    return {"mission_id": mission_id, "target": target,
            "findings": len(findings), "lessons": len(lessons),
            "expertise": expertise[:5],
            "capability": {"overall": capability.get("overall", 0),
                           "gaps": len(capability.get("items", []))},
            "research": {"catalogue": plan.get("catalogue", 0),
                         "matched": len(plan.get("items", []))},
            "actions": actions[:limit],
            "note": ("Suggestions are deterministic and based on stored records; they are "
                     "not a model's guess. Confirm scope before running one.")}


def _slug_token(value: str, limit: int = 64) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return (token or "technique")[:limit]


def reproduction_checklist(hypothesis: dict) -> str:
    """Short markdown checklist from a supported lead (no payloads)."""
    title = str(hypothesis.get("title") or "Supported hypothesis").strip()
    target = str(hypothesis.get("target") or "").strip()
    technique = str(hypothesis.get("technique") or "").strip()
    rationale = str(hypothesis.get("rationale") or "").strip()
    expected = str(hypothesis.get("expected") or "").strip()
    hyp_id = str(hypothesis.get("id") or "").strip()
    lines = [f"# Verified: {title}", ""]
    if target:
        lines.extend([f"Target: {target}", ""])
    if technique:
        lines.extend([f"Technique: {technique}", ""])
    if rationale:
        lines.extend(["## Rationale", rationale, ""])
    if expected:
        lines.extend(["## Expected observation", expected, ""])
    lines.extend([
        "## Reproduction checklist",
        "1. Confirm scope and baseline the target origin.",
        "2. Re-run the same preconditions used when this lead was supported.",
        "3. Compare the live response to the expected observation above.",
        "4. Capture raw request/response evidence before promotion.",
        "5. Revert any state change created during the test.",
    ])
    if hyp_id:
        lines.extend(["", f"Hypothesis: {hyp_id}"])
    return "\n".join(lines).strip()


def upsert_verified_skill(index, hypothesis: dict) -> dict | None:
    """Turn a supported hypothesis into a reusable verified-ttp skill."""
    if str(hypothesis.get("status") or "") != "supported":
        return None
    result = hypothesis.get("result") if isinstance(hypothesis.get("result"), dict) else {}
    if result and not result.get("ok"):
        return None
    expected = str(hypothesis.get("expected") or "").strip()
    if not expected and not result.get("ok"):
        return None
    technique = str(hypothesis.get("technique") or "").strip().lower()
    title = str(hypothesis.get("title") or "").strip()
    rationale = str(hypothesis.get("rationale") or "").strip()
    slug = _slug_token(technique or title or "lead")
    name = f"verified-{slug}"[:120]
    body = reproduction_checklist(hypothesis)
    tags = ["verified-ttp"]
    if technique:
        tags.append(technique)
    host = _host(str(hypothesis.get("target") or ""))
    if host:
        tags.append(host)
    hyp_id = str(hypothesis.get("id") or "").strip()
    if hyp_id:
        tags.append(f"hypothesis:{hyp_id}")
    try:
        return index.upsert_skill(
            name=name,
            body=body,
            title=f"Verified: {title or slug.replace('-', ' ').title()}",
            description=(expected or rationale or title)[:240],
            tags=sorted(set(tags)),
            source=f"hypothesis:{hyp_id}" if hyp_id else "netcast3r:verified-ttp",
        )
    except ValueError:
        return None


def compound_supported_hypothesis(index, hypothesis_id: str) -> dict | None:
    """Learning hook after a hypothesis becomes supported."""
    hypothesis = index.get_hypothesis(hypothesis_id)
    if not hypothesis:
        return None
    return upsert_verified_skill(index, hypothesis)


def _skill_signal_overlap(skill: dict, signals: set[str]) -> int:
    if not signals:
        return 0
    blob = " ".join(
        [str(skill.get("name") or ""), str(skill.get("title") or ""),
         str(skill.get("description") or ""), str(skill.get("body") or "")]
        + [str(tag) for tag in (skill.get("tags") or [])]
    ).lower()
    score = 0
    for token in signals:
        if not token or len(token) < 2:
            continue
        if token in blob:
            score += 2 if token in {str(t).lower() for t in (skill.get("tags") or [])} else 1
    return score


def summarize_skill(body: str, limit: int = 400) -> str:
    """First meaningful paragraph of a skill body, for list views."""
    for block in re.split(r"\n\s*\n", body or ""):
        block = re.sub(r"^#+\s*", "", block.strip())
        if block and not block.startswith("```"):
            return block[:limit]
    return (body or "").strip()[:limit]


BUILTIN_SKILLS = [
    {
        "name": "path-encoding-scope-differential",
        "title": "Path-encoding scope differential",
        "description": "Find authorization checks that run before the router decodes the path.",
        "tags": ["authz", "encoding", "api"],
        "body": """# Path-encoding scope differential

When a token has a narrower scope than an endpoint, compare the literal path with
encoded variants. A `403` on the literal path that becomes `400` on an encoded
path means the authorization check missed the route and the handler still ran.

1. Baseline the literal path with the low-scope credential.
2. Encode the first character, the last character, and the whole final segment.
3. Compare status and body; a validation error is a handler reach, not proof of impact.
4. Confirm the downstream entitlement or object check before recording a finding.
5. Do not replay state-changing methods without an explicit opt-in.

Use `http_path_diff` with the low-scope auth profile and inspect `check_skipped`.
""",
    },
    {
        "name": "login-method-2fa-matrix",
        "title": "Login-method x 2FA matrix",
        "description": "Every login path must enforce the second factor, not just the password path.",
        "tags": ["auth", "2fa", "matrix"],
        "body": """# Login-method x 2FA matrix

Enumerate every way a session can be created, then test each one with 2FA on:

- password
- email code
- SMS/phone code
- OAuth/OIDC
- device ticket or QR login
- password reset

For each: does it set a session cookie before the TOTP challenge? Does the new
session report a verified state? Can it read the TOTP secret or enroll a device?
The expected result is the same `tfaKey` challenge on every path.

Record the exact cookie names, the challenge response, and the first sensitive
API that succeeds without a TOTP.
""",
    },
    {
        "name": "account-rebind-ato",
        "title": "Account rebind takeover",
        "description": "Check whether changing the account identifier needs only mailbox access.",
        "tags": ["ato", "email", "account"],
        "body": """# Account rebind takeover

A password reset should not move the account away from the victim. Test the
email-change flow separately:

1. Verify the current address.
2. Add a new address you control.
3. Look for a password, TOTP, or recovery-code requirement.
4. Sign in with the new address and compare the account id.
5. Check whether the old address can still recover the account.

A flow that accepts only old/new email codes converts temporary mailbox access
into permanent ownership. Revert the change after capturing evidence.
""",
    },
    {
        "name": "two-account-object-matrix",
        "title": "Two-account object matrix",
        "description": "Use two owned accounts to test object-level authorization honestly.",
        "tags": ["idor", "authz", "matrix"],
        "body": """# Two-account object matrix

Create two accounts you own. For every object route, request the object from the
owner, then from the other account, then anonymously. Record status and body
length. A different body with the same status is still a lead.

Keep a table of: object type, id shape, owner-only fields, and the response for
each of the three callers. Only test ids that belong to your two accounts; never
enumerate a third party's data.

Finish with a read-only proof and a cleanup note for every object you created.
""",
    },
]


SKILL_PACKS_PATH = Path(__file__).with_name("data") / "skill_packs.json"


def bundled_skill_packs() -> list[dict]:
    """The bundled advanced playbooks, loaded from data/skill_packs.json."""
    try:
        raw = json.loads(SKILL_PACKS_PATH.read_text())
    except (OSError, ValueError):
        return []
    items = []
    for pack in raw.get("packs", []):
        if not isinstance(pack, dict):
            continue
        name = str(pack.get("name") or "").strip()
        body = str(pack.get("body") or "").strip()
        if not name or not body:
            continue
        items.append({
            "name": name,
            "title": str(pack.get("title") or name.replace("-", " ").title()),
            "description": str(pack.get("description") or ""),
            "tags": [str(tag) for tag in (pack.get("tags") or [])],
            "body": body,
        })
    return items


_UNREACHABLE_RE = re.compile(
    r"unreachable|connect\s*error|connecterror|probe[_\s-]?failed|"
    r"request[_\s-]?failed|connecttimeout|readtimeout|timed?\s*out|"
    r"connection refused|connection reset|name or service not known|"
    r"network unreachable|certificate verify failed|handshake|"
    r"ssl:|\btls\b.*(?:fail|error|dead)|host\s+(?:is\s+)?(?:dead|down)|"
    r"error_class:(?:connecterror|tlserror|timeouterror)|"
    r"no valid http",
    re.I)
_DEAD_NOTE_RE = re.compile(r"dead[\s-]?end|host.*dead|dead host", re.I)
_SUPERSEDED_TAGS = frozenset({"superseded", "contradicted"})


def lesson_is_active(lesson: dict) -> bool:
    """False when a lesson was superseded by later evidence."""
    if str(lesson.get("outcome") or "").lower() == "contradicted":
        return False
    tags = {str(tag).lower() for tag in (lesson.get("tags") or [])}
    if tags & _SUPERSEDED_TAGS:
        return False
    text = str(lesson.get("lesson") or "")
    return "[superseded:" not in text.lower()


def _mentions_unreachable(text: str) -> bool:
    return bool(_UNREACHABLE_RE.search(text or ""))


def _host_matches(host: str, lesson: dict) -> bool:
    host = host.strip().lower()
    if not host:
        return False
    blob = " ".join(
        str(lesson.get(key) or "")
        for key in ("title", "lesson", "context", "next_step", "technique")
    ).lower()
    tags = {str(tag).lower() for tag in (lesson.get("tags") or [])}
    if host in blob or host in tags or f"host:{host}" in tags:
        return True
    # A short first label like "api" or "www" is too generic to clear a lesson
    # for every host that happens to carry it as a tag.
    slug = host.split(".")[0]
    return bool(slug and len(slug) >= 7 and slug in tags)


def _note_matches_unreachable(host: str, note: dict) -> bool:
    if not _host_matches(host, {"title": note.get("title"), "lesson": note.get("body"),
                                "context": "", "next_step": "", "technique": "",
                                "tags": []}):
        return False
    blob = f"{note.get('title') or ''} {note.get('body') or ''}"
    kind = str(note.get("kind") or "").lower()
    if "[superseded:" in blob.lower():
        return False
    return (_mentions_unreachable(blob) or "dead" in kind
            or bool(_DEAD_NOTE_RE.search(blob)))


def contradict_host_unreachable_lessons(index, host: str, mission_id: str = "",
                                      evidence: str = "", *,
                                      lesson_id: str = "") -> dict:
    """Mark stale unreachable lessons/notes contradicted after HTTP success."""
    raw_host = str(host or "").strip()
    if raw_host.startswith("lsn_") and not lesson_id:
        lesson_id = raw_host
        raw_host = ""
    host = (_host(raw_host) or raw_host).lower()
    stamp = (evidence or "HTTP success on this host").strip()[:240]
    out = {"host": host, "mission_id": mission_id, "lessons": 0, "notes": 0,
           "kb": 0, "total": 0, "contradicted": 0, "contradicted_ids": [],
           "items": [], "evidence": stamp}

    candidates: list[dict] = []
    seen: set[str] = set()
    if lesson_id:
        single = index.get_lesson(lesson_id)
        if single:
            seen.add(single["id"])
            candidates.append(single)
            if not host:
                host = _host(str(single.get("host") or single.get("context") or "")).lower()
                out["host"] = host
            if not mission_id:
                mission_id = str(single.get("mission_id") or "")
                out["mission_id"] = mission_id

    if not host and not candidates:
        return out

    for query in ({host, host.split(".")[0]} if host else set()):
        if not query:
            continue
        rows, _ = index.list_lessons(q=query, limit=80)
        for row in rows:
            if row["id"] not in seen:
                seen.add(row["id"])
                candidates.append(row)
    if mission_id:
        rows, _ = index.list_lessons(mission_id=mission_id, limit=120)
        for row in rows:
            if row["id"] not in seen:
                seen.add(row["id"])
                candidates.append(row)

    for lesson in candidates:
        if not lesson_is_active(lesson):
            continue
        is_explicit = bool(lesson_id and lesson.get("id") == lesson_id)
        if not is_explicit:
            if not _host_matches(host, lesson):
                continue
            blob = " ".join(
                [str(lesson.get(key) or "")
                 for key in ("title", "lesson", "context", "next_step")]
                + [str(t) for t in (lesson.get("tags") or [])]
            )
            if not _mentions_unreachable(blob):
                continue
        suffix = f" [superseded: {stamp}]"
        body = str(lesson.get("lesson") or "")
        if suffix.lower() not in body.lower():
            body = (body + suffix).strip()[:4000]
        base_tags = {
            str(tag) for tag in (lesson.get("tags") or [])
            if str(tag).strip() and str(tag).lower() not in {"provisional=true", "provisional"}
        }
        add_tags = {"superseded", "contradicted", "provisional=false"}
        if host:
            add_tags.update({host, f"host:{host}"})
        tags = sorted(base_tags | add_tags)
        try:
            patched_row = index.patch_lesson(
                lesson["id"],
                lesson=body,
                outcome="observation",
                next_step="Host answered over HTTP; retry active probes on this host.",
                tags=tags,
                confidence=min(float(lesson.get("confidence") or 0.5), 0.35),
            )
        except ValueError:
            continue
        out["lessons"] += 1
        out["contradicted_ids"].append(lesson["id"])
        if patched_row:
            out["items"].append(patched_row)

    if mission_id and host:
        for note in index.list_agent_notes(mission_id, limit=120):
            if not _note_matches_unreachable(host, note):
                continue
            body = str(note.get("body") or "")
            suffix = f" [superseded: {stamp}]"
            if suffix.lower() not in body.lower():
                body = (body + suffix).strip()[:4000]
            title = str(note.get("title") or "")
            if title.lower().startswith("superseded:"):
                patched_title = title
            else:
                patched_title = f"superseded: {title}"[:500]
            try:
                index.patch_agent_note(
                    note["id"],
                    kind="observation",
                    title=patched_title,
                    body=body,
                )
            except (TypeError, ValueError, AttributeError):
                continue
            out["notes"] += 1

    from . import kb as kb_module

    scopes = ["global"]
    if mission_id:
        scopes.append(mission_id)
    if host:
        for scope in scopes:
            for row in index.list_kb_entries(scope=scope, kind="dead-end", q=host, limit=40):
                body = str(row.get("body") or "")
                if "[superseded:" in body.lower():
                    continue
                if host not in body.lower() and host not in str(row.get("key") or "").lower():
                    continue
                if not (_mentions_unreachable(body) or "refuted" in body.lower()):
                    continue
                patched = (body + f" [superseded: {stamp}]").strip()[:4000]
                try:
                    kb_module.record(
                        index, scope, "dead-end", str(row.get("key") or host),
                        title=str(row.get("title") or host),
                        body=patched,
                        confidence="hypothesis",
                        source={"superseded_by": stamp, "host": host},
                        data=row.get("data") or {},
                    )
                except ValueError:
                    continue
                out["kb"] += 1

    out["total"] = out["lessons"] + out["notes"] + out["kb"]
    out["contradicted"] = out["total"]
    if out["lessons"]:
        try:
            index.add_director_log(
                "lesson.contradict",
                f"superseded {out['lessons']} unreachable lesson(s) for {host or 'target'}",
                mission_id=mission_id or None,
                data={"host": host, "lessons": out["lessons"], "notes": out["notes"],
                      "kb": out["kb"], "evidence": stamp})
        except Exception:  # noqa: BLE001
            pass
    return out


def supersede_host_lesson(index, host: str = "", mission_id: str = "",
                          evidence: str = "", *, lesson_id: str = "",
                          status_code: int = 200, tool: str = "http_probe",
                          tls_insecure: bool = False) -> dict:
    """Alias/wrapper to contradict stale host-dead lessons on probe success."""
    if not evidence:
        evidence = f"HTTP {int(status_code or 200)} via {tool}"
        if tls_insecure:
            evidence += " (tls_insecure)"
    return contradict_host_unreachable_lessons(
        index, host, mission_id=mission_id, evidence=evidence,
        lesson_id=lesson_id)


contradict_lesson = supersede_host_lesson


def note_host_reachable(index, target: str, status: int, mission_id: str = "",
                        tls_insecure: bool = False) -> dict:
    """Hook for successful HTTP tools: clear poisoned dead-host memory."""
    if int(status or 0) <= 0 or index is None:
        return {"host": "", "contradicted": 0, "total": 0}
    host = _host(target) or ""
    evidence = f"HTTP {int(status)}" + (" (tls_insecure)" if tls_insecure else "")
    return contradict_host_unreachable_lessons(
        index, host, mission_id=mission_id, evidence=evidence)


def on_http_tool_success(index, call: dict) -> dict | None:
    """Learning hook after a stored http_probe/http_request success."""
    if str(call.get("tool") or "") not in {"http_probe", "http_request"}:
        return None
    if str(call.get("status") or "") != "ok":
        return None
    result = call.get("result") if isinstance(call.get("result"), dict) else {}
    status = result.get("status")
    if not isinstance(status, int) or status <= 0:
        return None
    args = call.get("args") if isinstance(call.get("args"), dict) else {}
    host = _target(args) or _host(str(result.get("url") or ""))
    if not host:
        return None
    evidence = f"HTTP {status} via {call.get('tool')}"
    return contradict_host_unreachable_lessons(
        index, host, mission_id=str(call.get("mission_id") or ""), evidence=evidence)


def seed_builtin_skills(index) -> int:
    """Install the built-in and packaged skill sets once. Return how many were added."""
    added = 0
    for skill in BUILTIN_SKILLS:
        if index.get_skill(skill["name"]):
            continue
        try:
            index.upsert_skill(
                name=skill["name"], body=skill["body"], title=skill["title"],
                description=skill["description"], tags=skill["tags"],
                source="netcast3r:builtin")
            added += 1
        except ValueError:
            continue
    for pack in bundled_skill_packs():
        if index.get_skill(pack["name"]):
            continue
        try:
            index.upsert_skill(
                name=pack["name"], body=pack["body"], title=pack["title"],
                description=pack["description"], tags=pack["tags"],
                source="netcast3r:pack")
            added += 1
        except ValueError:
            continue
    return added
