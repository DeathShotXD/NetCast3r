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

import re
from urllib.parse import urlsplit

SCOPE_HINTS = ("scope", "out of scope", "scope_denied", "target is outside")
APPROVAL_HINTS = ("approval", "confirm", "policy_denied", "readonly")
TIMEOUT_HINTS = ("timeout", "timed out", "rate limit", "429", "too many requests")
AUTH_HINTS = ("401", "403", "unauthorized", "forbidden", "insufficient_scope")
NOTFOUND_HINTS = ("404", "not found", "not_found")
INPUT_HINTS = ("invalid", "required", "must be", "unknown argument", "validation")


def _host(value: str) -> str:
    try:
        if "://" in value:
            return urlsplit(value).hostname or ""
        return value.split("/", 1)[0]
    except ValueError:
        return ""


def _target(args: dict) -> str:
    for key in ("target", "url", "host", "domain", "endpoint"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return _host(value.strip())
    return ""


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
    if any(hint in text for hint in TIMEOUT_HINTS):
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
    target = _target(args)
    if status == "ok":
        outcome, technique, next_step = "success", tool, "Repeat the same shape on the next in-scope object."
        lesson = f"{tool} succeeded" + (f" against {target}" if target else "") + "."
        if isinstance(result.get("status"), int):
            lesson += f" Observed HTTP {result['status']}."
        tags = ["success", tool]
    else:
        outcome, category, next_step = _classify(error, status)
        technique = tool
        lesson = f"{tool} returned {status or 'an error'}" + (f": {error[:240]}" if error else ".")
        tags = [outcome, category, tool]
    if target:
        tags.append(target)
    return {
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
    }


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
    lessons, _ = index.list_lessons(q=host, limit=20)
    if slug:
        tagged, _ = index.list_lessons(tag=slug, limit=20)
        seen = {item["id"] for item in lessons}
        lessons.extend(item for item in tagged if item["id"] not in seen)
    calls, _ = index.list_tool_calls(mission_id=mission_id, limit=50)
    expertise = index.list_expertise(limit=10)
    actions: list[dict] = []

    def add(title: str, why: str, tool: str, args: dict, risk: str = "low") -> None:
        if len(actions) < limit:
            actions.append({"title": title, "why": why, "tool": tool,
                            "args": args, "risk": risk})

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
    for lesson in lessons[:3]:
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
    if not actions:
        add("Re-read the latest run output and pick one unexplained response",
            "the obvious paths are covered; deepen the evidence instead of widening",
            "runs_events", {"run_id": mission.get("last_run_id") or ""}, "low")
    return {"mission_id": mission_id, "target": target,
            "findings": len(findings), "lessons": len(lessons),
            "expertise": expertise[:5],
            "actions": actions[:limit],
            "note": ("Suggestions are deterministic and based on stored records; they are "
                     "not a model's guess. Confirm scope before running one.")}


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


def seed_builtin_skills(index) -> int:
    """Install the small built-in skill set once. Return how many were added."""
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
    return added
