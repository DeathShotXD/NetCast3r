"""Reproduction: turn a candidate's recorded evidence into a minimal proof.

Builds the smallest honest reproduction from what a module step actually
recorded - a curl and a Python snippet - so a reviewer can re-run the
observation themselves. It reproduces the request that was made; it does not
invent an exploit.

``verify_poc`` replays those recorded steps against the authorised target and
scores them against the recorded expectations. A pass is evidence; a fail is a
refutation. Neither path creates a finding.
"""

from __future__ import annotations

import json
import re
from typing import Callable
from urllib.parse import urlsplit


Transport = Callable[[dict], dict]


def _sh(value: str) -> str:
    text = str(value)
    if text and all(ch.isalnum() or ch in "-_./:@=%?&" for ch in text):
        return text
    return "'" + text.replace("'", "'\\''") + "'"


def _steps(candidate: dict) -> list[dict]:
    evidence = candidate.get("evidence") or {}
    raw = evidence.get("steps") or []
    out: list[dict] = []
    for step in raw:
        if not isinstance(step, dict):
            continue
        target = str(step.get("target") or "").strip()
        if not target:
            continue
        observation = step.get("observation") if isinstance(
            step.get("observation"), dict) else {}
        method = str(observation.get("method") or step.get("method")
                     or "GET").upper() or "GET"
        headers = observation.get("headers") if isinstance(
            observation.get("headers"), dict) else {}
        if not headers and isinstance(step.get("headers"), dict):
            headers = step.get("headers") or {}
        body = observation.get("body")
        if body is None:
            body = step.get("body")
        expected_status = (observation.get("status")
                           or observation.get("expected_status")
                           or step.get("expected_status"))
        marker = (observation.get("marker") or observation.get("match")
                  or step.get("marker") or "")
        out.append({
            "tool": str(step.get("tool") or ""),
            "target": target,
            "method": method,
            "headers": {str(k): str(v) for k, v in list(headers.items())[:12]},
            "body": body if isinstance(body, (str, bytes, dict, list)) else None,
            "expected_status": int(expected_status) if str(
                expected_status or "").isdigit() else None,
            "marker": str(marker or "").strip(),
        })
    return out


def _ttp_for(candidate: dict) -> dict | None:
    """Attach a matching research technique when the module or title hints one."""
    try:
        from . import research
    except Exception:  # noqa: BLE001 - research is optional for PoC build
        return None
    module = str(candidate.get("module_id") or "").strip().lower()
    title = str(candidate.get("title") or "").strip().lower()
    query = " ".join(part for part in (module.replace("-", " "),
                                       module.replace("_", " "), title) if part)
    if not query.strip():
        return None
    try:
        hits = research.search(query=query, limit=3).get("items") or []
    except Exception:  # noqa: BLE001
        return None
    if not hits:
        # Fall back to a class keyword from the module id.
        for token in re.split(r"[^a-z0-9]+", module):
            if len(token) < 4:
                continue
            try:
                hits = research.search(query=token, limit=1).get("items") or []
            except Exception:  # noqa: BLE001
                hits = []
            if hits:
                break
    if not hits:
        return None
    item = hits[0]
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "class": item.get("class"),
        "steps": list(item.get("steps") or [])[:6],
        "tools": list(item.get("tools") or [])[:8],
        "sources": list(item.get("sources") or [])[:4],
    }


def build_poc(candidate: dict, mission: dict | None = None) -> dict:
    mission = mission or {}
    evidence = candidate.get("evidence") or {}
    steps = _steps(candidate)
    curl_lines: list[str] = []
    python_lines = ["import requests", ""]
    assertions: list[dict] = []
    for step in steps:
        target = step["target"]
        method = step["method"]
        headers = step["headers"]
        curl = ["curl", "-sS", "-i", "-X", method]
        for name, value in headers.items():
            if str(name).lower() in {"content-length", "date", "connection"}:
                continue
            curl += ["-H", f"{name}: {value}"]
        body = step.get("body")
        data_arg = None
        if isinstance(body, (dict, list)):
            data_arg = json.dumps(body)
            curl += ["-H", "content-type: application/json", "--data-binary",
                     data_arg]
        elif isinstance(body, str) and body:
            data_arg = body
            curl += ["--data-binary", body]
        elif isinstance(body, bytes) and body:
            data_arg = body.decode("utf-8", "ignore")
            curl += ["--data-binary", data_arg]
        curl.append(target)
        curl_lines.append(" ".join(_sh(part) for part in curl))
        py_headers = {k: v for k, v in headers.items()
                      if str(k).lower() not in {"content-length", "date", "connection"}}
        python_lines.append(
            f"response = requests.request({method!r}, {target!r}, "
            f"headers={py_headers!r}"
            + (f", data={data_arg!r}" if data_arg is not None else "")
            + ")")
        assertion = {"target": target, "method": method}
        if step.get("expected_status") is not None:
            assertion["expected_status"] = step["expected_status"]
            python_lines.append(
                f"assert response.status_code == {step['expected_status']}")
        if step.get("marker"):
            assertion["marker"] = step["marker"]
            python_lines.append(f"assert {step['marker']!r} in response.text")
        python_lines.append("print(response.status_code)")
        python_lines.append("print(response.text[:400])")
        python_lines.append("")
        assertions.append(assertion)
    curl_text = " \\\n  && ".join(curl_lines) if curl_lines else "# no request step recorded"
    python_text = "\n".join(python_lines).strip()
    ttp = _ttp_for(candidate)
    ttp_block = []
    if ttp:
        ttp_block = [
            "",
            "## Technique",
            f"- `{ttp.get('id')}` {ttp.get('title')}",
            f"- Class: `{ttp.get('class')}`",
            "- Procedure:",
            *[f"  - {step}" for step in (ttp.get("steps") or [])],
        ]
    expected = evidence.get("expected") or "a reproducible difference"
    markdown = "\n".join([
        f"# Reproduction: {candidate.get('title', 'candidate')}",
        "",
        f"- Module: `{candidate.get('module_id') or 'n/a'}`",
        f"- Target: `{mission.get('target', '')}`",
        f"- Expected: {expected}",
        *ttp_block,
        "",
        "## curl",
        "```bash",
        curl_text,
        "```",
        "",
        "## python",
        "```python",
        python_text,
        "```",
        "",
        "A candidate is not a finding. Run this against the authorised target,",
        "confirm the difference, then promote it.",
    ])
    ready = len(steps) >= 1
    return {
        "candidate_id": candidate.get("id", ""),
        "title": candidate.get("title", ""),
        "module_id": candidate.get("module_id", ""),
        "target": mission.get("target", ""),
        "reproduced_steps": len(steps),
        "ready": ready,
        "assertions": assertions,
        "ttp": ttp,
        "curl": curl_text,
        "python": python_text,
        "markdown": markdown,
        "findings": 0,
        "note": ("Replayable PoC built from recorded evidence."
                 if ready else
                 "No request step recorded; refuse promotion unless an operator forces it."),
    }


def _default_transport(step: dict, timeout: float = 20.0) -> dict:
    import httpx

    headers = dict(step.get("headers") or {})
    body = step.get("body")
    kwargs: dict = {"headers": headers, "follow_redirects": False, "timeout": timeout}
    if isinstance(body, (dict, list)):
        kwargs["json"] = body
    elif isinstance(body, (str, bytes)) and body:
        kwargs["content"] = body if isinstance(body, bytes) else body.encode()
    with httpx.Client(timeout=timeout, trust_env=False) as client:
        response = client.request(step["method"], step["target"], **kwargs)
    return {
        "status": response.status_code,
        "headers": {k: v for k, v in response.headers.items()},
        "body": response.text[:4000],
        "url": str(response.url),
    }


def _in_scope(url: str, mission: dict) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    scope = mission.get("scope") or []
    if isinstance(scope, str):
        try:
            scope = json.loads(scope)
        except json.JSONDecodeError:
            scope = [scope]
    allowed = []
    for item in scope:
        text = str(item or "").strip().lower()
        if not text:
            continue
        if "://" in text:
            text = urlsplit(text).hostname or text
        allowed.append(text.lstrip("."))
    target = str(mission.get("target") or "").strip().lower()
    if target:
        th = urlsplit(target if "://" in target else f"https://{target}").hostname
        if th:
            allowed.append(th.lower())
    if not allowed:
        return False
    return any(host == item or host.endswith("." + item) for item in allowed)


def verify_poc(candidate: dict, mission: dict | None = None,
               transport: Transport | None = None,
               timeout: float = 20.0) -> dict:
    """Replay recorded PoC steps and score them against expectations.

    Scope is enforced here so a verify call cannot leave the mission's
    authorised hosts. The transport is injectable for tests.
    """
    mission = mission or {}
    built = build_poc(candidate, mission)
    steps = _steps(candidate)
    if not steps:
        return {
            **built,
            "verified": False,
            "passed": 0,
            "failed": 0,
            "results": [],
            "error": "no request step recorded",
        }
    runner = transport or (lambda step: _default_transport(step, timeout=timeout))
    results: list[dict] = []
    passed = 0
    failed = 0
    for step in steps:
        if not _in_scope(step["target"], mission):
            results.append({
                "target": step["target"], "method": step["method"],
                "ok": False, "error": "target is outside mission scope",
            })
            failed += 1
            continue
        try:
            response = runner(step)
        except Exception as exc:  # noqa: BLE001 - record and keep scoring
            results.append({
                "target": step["target"], "method": step["method"],
                "ok": False, "error": f"{type(exc).__name__}: {exc}"[:200],
            })
            failed += 1
            continue
        status = int(response.get("status") or 0)
        body = str(response.get("body") or "")
        checks: list[dict] = []
        ok = True
        expected_status = step.get("expected_status")
        if expected_status is not None:
            hit = status == int(expected_status)
            checks.append({"kind": "status", "expected": expected_status,
                           "got": status, "ok": hit})
            ok = ok and hit
        marker = step.get("marker") or ""
        if marker:
            hit = marker in body
            checks.append({"kind": "marker", "expected": marker,
                           "ok": hit})
            ok = ok and hit
        if expected_status is None and not marker:
            # Reachability alone is not a pass; require a recorded expectation.
            checks.append({"kind": "expectation", "ok": False,
                           "error": "no expected status or marker recorded"})
            ok = False
        results.append({
            "target": step["target"],
            "method": step["method"],
            "status": status,
            "url": response.get("url") or step["target"],
            "checks": checks,
            "ok": ok,
            "body_preview": body[:240],
        })
        if ok:
            passed += 1
        else:
            failed += 1
    verified = passed > 0 and failed == 0
    return {
        **built,
        "verified": verified,
        "passed": passed,
        "failed": failed,
        "results": results,
        "error": "" if verified else (
            "one or more assertions failed" if results else "nothing to verify"),
    }


def promotion_gate(candidate: dict, mission: dict | None = None, *,
                   force: bool = False, notes: str = "",
                   require_verify: bool = False,
                   transport: Transport | None = None) -> dict:
    """Decide whether a candidate may become a finding.

    Rules:
    - a replayable PoC with at least one recorded request step is required;
    - ``force=true`` with an operator note overrides a missing PoC;
    - ``require_verify=true`` demands a live assertion pass.
    """
    built = build_poc(candidate, mission)
    evidence = candidate.get("evidence") or {}
    raw_evidence = ""
    if isinstance(evidence, dict):
        raw_evidence = str(evidence.get("raw") or evidence.get("proof")
                           or evidence.get("expected") or "")
    if not isinstance(raw_evidence, str):
        raw_evidence = str(raw_evidence)
    verified = None
    if require_verify:
        verified = verify_poc(candidate, mission, transport=transport)
        if not verified.get("verified"):
            return {
                "allowed": False,
                "reason": "PoC verification failed",
                "poc": built,
                "verification": verified,
            }
    if built.get("ready"):
        pack = built["markdown"]
        if verified and verified.get("verified"):
            pack = pack + "\n\n## Verification\n\n" + json.dumps({
                "passed": verified.get("passed"),
                "failed": verified.get("failed"),
                "results": verified.get("results"),
            }, indent=2)[:4000]
        return {
            "allowed": True,
            "reason": "replayable PoC ready",
            "poc": built,
            "verification": verified,
            "evidence": pack[:8000],
        }
    if force and str(notes or "").strip():
        pack = (
            f"Operator-forced promotion without recorded request steps.\n"
            f"Notes: {notes.strip()}\n\n"
            f"{built.get('markdown') or ''}"
        )
        if len(raw_evidence.strip()) >= 32:
            pack = raw_evidence.strip() + "\n\n" + pack
        return {
            "allowed": True,
            "reason": "operator force with notes",
            "poc": built,
            "verification": verified,
            "evidence": pack[:8000],
        }
    return {
        "allowed": False,
        "reason": ("candidate has no recorded request step; build evidence "
                   "first, or pass force=true with notes"),
        "poc": built,
        "verification": verified,
    }
