"""Deterministic verification gates.

A tool call is an observation, never a conclusion. This module judges one
observation against an explicit assertion without a model, so a weak or missing
provider cannot turn a 200 into a finding. Every check is data:

    {"path": "counts.vulnerable", "gte": 1}
    {"path": "status", "eq": 200}
    {"path": "headers.location", "contains": "nc3r-canary.invalid"}
    {"path": "body", "regex": "SQL syntax.*MySQL"}
    {"path": "body_sha256", "changed": true}   # compared to a baseline

A verdict is one of:

- ``pass``   every check matched;
- ``fail``   a check was evaluated and did not match;
- ``repeat`` the observation was a transport refusal or lacked the field, so
  the step should be retried rather than trusted or discarded.

``repeat`` is what keeps a transient timeout from being scored as a definitive
negative, and a missing field from being read as a pass.
"""

from __future__ import annotations

import re
from typing import Any

VERDICTS = ("pass", "fail", "repeat")

_MISSING = object()


def _get(data: Any, path: str):
    """Resolve a dotted path with optional ``[index]`` against a payload."""
    if not path:
        return data
    current = data
    for token in _split(path):
        if current is _MISSING:
            return _MISSING
        if isinstance(current, (list, tuple)) and isinstance(token, str) and token.isdigit():
            token = int(token)
        if isinstance(token, int):
            if isinstance(current, (list, tuple)) and -len(current) <= token < len(current):
                current = current[token]
            else:
                return _MISSING
        elif isinstance(current, dict):
            if token in current:
                current = current[token]
            else:
                return _MISSING
        else:
            return _MISSING
    return current


def _split(path: str) -> list:
    tokens: list = []
    for part in str(path).split("."):
        match = re.match(r"^([^\[]*)((?:\[\d+\])*)$", part or "")
        if not match:
            tokens.append(part)
            continue
        name, indices = match.group(1), match.group(2)
        if name:
            tokens.append(name)
        for index in re.findall(r"\[(\d+)\]", indices):
            tokens.append(int(index))
    return tokens


def _matches(value, spec: dict) -> tuple[bool, str]:
    if "eq" in spec and value != spec["eq"]:
        return False, f"{value!r} != {spec['eq']!r}"
    if "ne" in spec and value == spec["ne"]:
        return False, f"{value!r} == {spec['ne']!r}"
    for op, ok in (("gte", lambda a, b: a >= b), ("lte", lambda a, b: a <= b),
                   ("gt", lambda a, b: a > b), ("lt", lambda a, b: a < b)):
        if op in spec:
            try:
                if not ok(value, spec[op]):
                    return False, f"{value!r} not {op} {spec[op]!r}"
            except TypeError:
                return False, f"{value!r} is not comparable to {spec[op]!r}"
    if "contains" in spec and str(spec["contains"]).lower() not in str(value).lower():
        return False, f"{spec['contains']!r} not in value"
    if "not_contains" in spec and str(spec["not_contains"]).lower() in str(value).lower():
        return False, f"{spec['not_contains']!r} present in value"
    if "regex" in spec and not re.search(str(spec["regex"]), str(value)):
        return False, "regex did not match"
    if "in" in spec and value not in (spec["in"] or []):
        return False, f"{value!r} not in the allowed set"
    if spec.get("present") is False and value is not _MISSING:
        return False, "value present but expected absent"
    return True, ""


def _observation_failed(observation) -> bool:
    if isinstance(observation, dict):
        error = observation.get("error")
        if error and not any(key in observation for key in
                             ("status", "body", "results", "value", "verdict")):
            return True
    return False


def verify(assertion, observation, baseline=None) -> dict:
    """Judge one observation against one assertion. Never raises."""
    if observation is None:
        return {"verdict": "repeat", "reason": "no observation was recorded",
                "checks": []}
    if _observation_failed(observation):
        message = observation.get("error")
        if isinstance(message, dict):
            message = message.get("message") or message
        return {"verdict": "repeat",
                "reason": f"transport refusal: {str(message)[:200]}", "checks": []}

    if isinstance(assertion, dict) and "all" in assertion:
        checks = list(assertion["all"] or [])
    elif isinstance(assertion, (dict, list)):
        checks = assertion if isinstance(assertion, list) else [assertion]
    else:
        return {"verdict": "repeat", "reason": "no assertion to verify against",
                "checks": []}
    if not checks:
        return {"verdict": "repeat", "reason": "empty assertion", "checks": []}

    outcome: list = []
    for check in checks:
        path = str(check.get("path") or "")
        value = _get(observation, path) if path else observation
        if value is _MISSING:
            if "present" in check:
                ok = not check["present"]
                outcome.append({"path": path, "ok": ok,
                                "detail": "absent" if ok
                                else "value is absent but expected present"})
                continue
            outcome.append({"path": path, "ok": None,
                            "detail": "field not present in the observation"})
            continue
        if check.get("changed"):
            base = _get(baseline, path) if path else baseline
            if base is _MISSING:
                outcome.append({"path": path, "ok": None,
                                "detail": "no baseline to compare against"})
                continue
            if value == base:
                outcome.append({"path": path, "ok": False,
                                "detail": "value did not change from the baseline"})
                continue
            outcome.append({"path": path, "ok": True, "detail": "changed from baseline"})
            continue
        ok, detail = _matches(value, check)
        outcome.append({"path": path, "ok": ok, "detail": detail})

    if any(row["ok"] is None for row in outcome):
        first = next(row for row in outcome if row["ok"] is None)
        return {"verdict": "repeat",
                "reason": f"cannot evaluate {first['path']}: {first['detail']}",
                "checks": outcome}
    if all(row["ok"] for row in outcome):
        return {"verdict": "pass", "reason": "every check matched",
                "checks": outcome}
    failed = [row for row in outcome if not row["ok"]]
    return {"verdict": "fail",
            "reason": "; ".join(f"{row['path']}: {row['detail']}" for row in failed),
            "checks": outcome}


def verify_plan(plan: dict, observations: list, baseline=None) -> dict:
    """Verify each step of a compiled plan against its recorded observation."""
    steps = (plan or {}).get("steps") or []
    rows = []
    passed = failed = repeat = 0
    for step in steps:
        number = int(step.get("n") or len(rows) + 1)
        recorded = next((item for item in (observations or [])
                         if int(item.get("n") or 0) == number), None)
        if recorded is None:
            rows.append({"n": number, "tool": step.get("tool", ""),
                         "verdict": "repeat", "reason": "step not yet run"})
            repeat += 1
            continue
        result = verify(step.get("verify"), recorded.get("observation"),
                        recorded.get("baseline") if baseline is None else baseline)
        rows.append({"n": number, "tool": step.get("tool", ""), **result})
        if result["verdict"] == "pass":
            passed += 1
        elif result["verdict"] == "fail":
            failed += 1
        else:
            repeat += 1
    state = ("verified" if steps and passed == len(steps) else
             "refuted" if failed and not passed else
             "blocked" if repeat == len(steps) and steps else
             "partial" if passed else "inconclusive")
    return {"state": state, "passed": passed, "failed": failed, "repeat": repeat,
            "steps": rows,
            "note": "A step passes only when its assertion is satisfied."}


def summary() -> dict:
    return {
        "checks": ["eq", "ne", "gte", "lte", "gt", "lt", "contains",
                   "not_contains", "regex", "in", "present", "changed"],
        "verdicts": list(VERDICTS),
        "note": "Deterministic: no model is consulted, so a missing provider cannot fake a pass.",
    }
