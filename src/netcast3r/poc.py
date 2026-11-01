"""Reproduction: turn a candidate's recorded evidence into a minimal proof.

Strix ships a "working PoC" per finding. This builds the smallest honest
reproduction from what a module step actually recorded - a curl and a Python
snippet - so a reviewer can re-run the observation themselves. It reproduces
the request that was made; it does not invent an exploit.
"""

from __future__ import annotations


def _sh(value: str) -> str:
    text = str(value)
    if text and all(ch.isalnum() or ch in "-_./:@=%?&" for ch in text):
        return text
    return "'" + text.replace("'", "'\\''") + "'"


def build_poc(candidate: dict, mission: dict | None = None) -> dict:
    mission = mission or {}
    evidence = candidate.get("evidence") or {}
    steps = evidence.get("steps") or []
    curl_lines: list[str] = []
    python_lines = ["import requests", ""]
    reproduced = 0
    for step in steps:
        if not isinstance(step, dict):
            continue
        target = str(step.get("target") or "").strip()
        if not target:
            continue
        observation = step.get("observation") if isinstance(
            step.get("observation"), dict) else {}
        method = str(observation.get("method") or "GET").upper()
        headers = observation.get("headers") if isinstance(
            observation.get("headers"), dict) else {}
        curl = ["curl", "-sS", "-i", "-X", method]
        for name, value in list(headers.items())[:6]:
            if str(name).lower() in {"content-length", "date", "connection"}:
                continue
            curl += ["-H", f"{name}: {value}"]
        curl.append(target)
        curl_lines.append(" ".join(_sh(part) for part in curl))
        python_lines.append(f"response = requests.{method.lower()}({target!r})")
        python_lines.append("print(response.status_code)")
        python_lines.append("print(response.text[:400])")
        python_lines.append("")
        reproduced += 1
    curl_text = " \\\n  && ".join(curl_lines) if curl_lines else "# no request step recorded"
    python_text = "\n".join(python_lines).strip()
    markdown = "\n".join([
        f"# Reproduction: {candidate.get('title', 'candidate')}",
        "",
        f"- Module: `{candidate.get('module_id') or 'n/a'}`",
        f"- Target: `{mission.get('target', '')}`",
        f"- Expected: {evidence.get('expected') or 'a reproducible difference'}",
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
    return {"candidate_id": candidate.get("id", ""),
            "title": candidate.get("title", ""),
            "module_id": candidate.get("module_id", ""),
            "target": mission.get("target", ""),
            "reproduced_steps": reproduced,
            "curl": curl_text,
            "python": python_text,
            "markdown": markdown,
            "findings": 0}
