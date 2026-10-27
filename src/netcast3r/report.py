"""Report writer.

Turns a run into a submission-ready markdown report. Secrets are redacted, and
each finding carries its impact, proof, reproduction, and remediation so it can
go straight into a program.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path


def redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    if len(value) <= 12:
        return value[:2] + "*" * max(len(value) - 2, 0)
    return f"{value[:6]}...{value[-4:]}"


def _scrub(text, value: str) -> str:
    """Remove the raw secret from any field so the proof cannot leak it."""
    text = str(text)
    if value and value in text:
        text = text.replace(value, redact(value))
    return text


def _inline(text, value: str = "") -> str:
    """One-line, secret-free field, so a value cannot inject a new markdown block."""
    return _scrub(text, value).replace("\r", " ").replace("\n", " ").strip()


def _fence(body, value: str = "") -> list[str]:
    """Wrap content in a fence longer than any backtick run inside it."""
    body = _scrub(body, value)
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", body)), default=0)
    ticks = "`" * (longest + 1)
    return [ticks, body.strip(), ticks]


def _scrub_tree(value, secrets: list[str]):
    """Recursively scrub every string in a finding, including nested evidence."""
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = _scrub(value, secret)
        return value
    if isinstance(value, dict):
        return {key: _scrub_tree(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_tree(item, secrets) for item in value]
    return value


def public_finding(finding: dict) -> dict:
    """A copy of a finding safe to write to a shared artifact: no raw secret.

    Both halves of a credential pair are redacted, and the scrub walks nested
    evidence (corroboration verdicts, reproduction steps) so a model quoting
    the secret cannot smuggle it past the top-level fields.
    """
    out = dict(finding)
    value = str(out.get("value") or "")
    pair = str(out.get("pair_value") or "")
    secrets = sorted({secret for secret in (value, pair) if secret},
                     key=len, reverse=True)
    out = _scrub_tree(out, secrets)
    if value:
        out["value"] = redact(value)
    if pair:
        out["pair_value"] = redact(pair)
    return out


def render(target: str, summary: dict, findings: list[dict],
           out_of_scope: list[str] | None = None,
           unverified: list[dict] | None = None,
           review: dict | None = None) -> str:
    lines: list[str] = []
    lines.append("# NetCast3r report")
    lines.append("")
    lines.append(f"- target: {target}")
    lines.append(f"- generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    for key, value in summary.items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Confirmed findings")
    lines.append("")
    if not findings:
        lines.append("No live credentials were confirmed in this run.")
        lines.append("")
    for index, finding in enumerate(findings, start=1):
        value = str(finding.get("value", ""))
        lines.append(f"### {index}. {_inline(finding.get('title', 'finding'))}")
        lines.append("")
        lines.append(f"- severity: {_inline(finding.get('severity', 'unknown'))}")
        lines.append(f"- type: {_inline(finding.get('secret_type', ''))}")
        lines.append(f"- value: {redact(value)}")
        lines.append(f"- source: {_inline(finding.get('source', ''), value)}")
        lines.append(f"- status: {_inline(finding.get('status', ''))}")
        if finding.get("confidence"):
            lines.append(f"- confidence: {finding.get('confidence')}")
        corroboration = finding.get("corroboration") or {}
        verdicts = corroboration.get("verdicts") or []
        if verdicts:
            lines.append("- corroboration: "
                         f"{corroboration.get('live', 0)}/{corroboration.get('total', 0)} "
                         f"models across different providers agree the credential is live")
            for verdict in verdicts:
                who = f"{verdict.get('provider', '?')}/{verdict.get('model', '?')}"
                said = "live" if verdict.get("live") else "not convinced"
                reason = str(verdict.get("reason") or "").strip()
                line = f"  - {_inline(who)}: {said}"
                if reason:
                    line += f" ({_inline(reason, finding.get('value', ''))})"
                lines.append(line)
        lines.append("")
        lines.append("Impact")
        lines.append("")
        lines.append(_scrub(finding.get("impact", ""), value))
        lines.append("")
        lines.append("Proof")
        lines.append("")
        lines.extend(_fence(finding.get("proof", ""), value))
        lines.append("")
        lines.append("Reproduction")
        lines.append("")
        steps = "\n".join(_scrub(step, value) for step in finding.get("reproduction", []))
        lines.extend(_fence(steps, value))
        lines.append("")
        model_notes: list[str] = []
        if finding.get("model_severity"):
            model_notes.append(f"- model severity (unconfirmed): {_inline(finding['model_severity'])}")
        if finding.get("model_impact"):
            model_notes.append(f"- {_inline(finding['model_impact'], value)}")
        for step in finding.get("model_steps", []) or []:
            model_notes.append(f"- {_inline(step, value)}")
        if finding.get("narrative"):
            model_notes.append(_scrub(finding["narrative"], value))
        if model_notes:
            lines.append("Analyst narrative (model generated, not independently verified)")
            lines.append("")
            lines.extend(model_notes)
            lines.append("")
        lines.append("Remediation")
        lines.append("")
        lines.append("Rotate the credential, remove it from client code, and move "
                     "the value behind a server-side configuration path.")
        lines.append("")
    if unverified:
        lines.append("## High and critical candidates (not confirmed)")
        lines.append("")
        lines.append("These values look like live credentials but the automated check "
                     "did not confirm them. Work each one by hand before ruling it out.")
        lines.append("")
        for index, item in enumerate(unverified, start=1):
            value = str(item.get("value", ""))
            lines.append(f"### C{index}. {_inline(item.get('type', 'candidate'))}")
            lines.append("")
            lines.append(f"- severity (by type): {_inline(item.get('severity', ''))}")
            lines.append(f"- type: {_inline(item.get('type', ''))}")
            lines.append(f"- value: {redact(value)}")
            lines.append(f"- source: {_inline(item.get('source', ''), value)}")
            lines.append(f"- why it was not confirmed: {_inline(item.get('detail', ''), value)}")
            lines.append("")
            lines.append("Manual reproduction")
            lines.append("")
            steps = "\n".join(_scrub(step, value) for step in item.get("steps", []) or [])
            lines.extend(_fence(steps, value))
            lines.append("")
    code_endpoints = (review or {}).get("endpoints") or []
    code_loopholes = (review or {}).get("loopholes") or []
    known_values = [str(f.get("value", "")) for f in findings if f.get("value")]
    known_values += [str(u.get("value", "")) for u in (unverified or []) if u.get("value")]

    def wash(text) -> str:
        text = _inline(text)
        for value in known_values:
            text = _scrub(text, value)
        return text

    if code_endpoints or code_loopholes:
        lines.append("## Code review (from the JavaScript and source pass)")
        lines.append("")
        if code_loopholes:
            lines.append("### Weak points")
            lines.append("")
            for item in code_loopholes[:100]:
                sev = str(item.get("severity", "")).strip()
                head = f"- {wash(item.get('detail', ''))}".rstrip()
                if sev:
                    head += f"  (severity: {_inline(sev)})"
                lines.append(head)
                if item.get("evidence"):
                    lines.append(f"  - evidence: {wash(item['evidence'])}")
                if item.get("source"):
                    lines.append(f"  - source: {wash(item['source'])}")
            lines.append("")
        if code_endpoints:
            lines.append("### Endpoints")
            lines.append("")
            for item in code_endpoints[:200]:
                method = str(item.get("method", "")).upper()
                note = str(item.get("note", "")).strip()
                line = f"- {_inline(method)} {wash(item.get('path', ''))}".rstrip()
                if note:
                    line += f" - {wash(note)}"
                lines.append(line)
                if item.get("source"):
                    lines.append(f"  - source: {wash(item['source'])}")
            lines.append("")
    if out_of_scope:
        lines.append("## Out of scope skipped")
        lines.append("")
        for url in out_of_scope[:50]:
            lines.append(f"- {url}")
        lines.append("")
    text = "\n".join(lines)
    # Some findings carry a second credential half (a database password, a
    # paired token). Scrub it from the whole report as well as the primary
    # value, since a model-written proof may quote either one. Longest first,
    # so a short value that is a substring of the pair cannot split it.
    secrets = set()
    for item in list(findings or []) + list(unverified or []):
        for key in ("value", "pair_value"):
            secret = str(item.get(key) or "")
            if secret:
                secrets.add(secret)
    for secret in sorted(secrets, key=len, reverse=True):
        text = _scrub(text, secret)
    return text


def save(target: str, summary: dict, findings: list[dict],
         out_dir: str | Path, out_of_scope: list[str] | None = None,
         unverified: list[dict] | None = None, review: dict | None = None) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.md"
    path.write_text(render(target, summary, findings, out_of_scope,
                           unverified=unverified, review=review))
    return path


def save_json(out_dir: str | Path, summary: dict, findings: list[dict]) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "results.json"
    public = [public_finding(f) for f in findings]
    path.write_text(json.dumps({"summary": summary, "findings": public}, indent=2, default=str))
    return path


def save_jsonl(out_dir: str | Path, findings: list[dict]) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "results.jsonl"
    with open(path, "w") as handle:
        for finding in findings:
            handle.write(json.dumps(public_finding(finding), default=str) + "\n")
    return path


LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def save_sarif(out_dir: str | Path, findings: list[dict]) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "results.sarif"
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in findings:
        secret_type = finding.get("secret_type", "secret")
        value = str(finding.get("value", ""))
        pair = str(finding.get("pair_value") or "")

        def scrub(text):
            return _scrub(_scrub(text, value), pair)

        rules.setdefault(secret_type, {
            "id": secret_type,
            "name": secret_type,
            "shortDescription": {"text": f"Exposed {secret_type} credential"},
            "helpUri": "https://github.com/DeathShotXD/NetCast3r",
        })
        results.append({
            "ruleId": secret_type,
            "level": LEVELS.get(str(finding.get("severity", "")).lower(), "warning"),
            "message": {"text": scrub(finding.get("title", "exposed credential"))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": scrub(finding.get("source", ""))}
                }
            }],
        })
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "NetCast3r",
                "informationUri": "https://github.com/DeathShotXD/NetCast3r",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    path.write_text(json.dumps(document, indent=2, default=str))
    return path
