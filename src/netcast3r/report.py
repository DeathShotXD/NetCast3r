"""Report writer.

Turns a run into a submission-ready markdown report. Secrets are redacted, and
each finding carries its impact, proof, reproduction, and remediation so it can
go straight into a program.
"""

from __future__ import annotations

import json
import time
from pathlib import Path


def redact(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "*" * max(len(value) - 2, 0)
    return f"{value[:6]}...{value[-4:]}"


def render(target: str, summary: dict, findings: list[dict],
           out_of_scope: list[str] | None = None) -> str:
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
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No live credentials were confirmed in this run.")
        lines.append("")
    for index, finding in enumerate(findings, start=1):
        lines.append(f"### {index}. {finding.get('title', 'finding')}")
        lines.append("")
        lines.append(f"- severity: {finding.get('severity', 'unknown')}")
        lines.append(f"- type: {finding.get('secret_type', '')}")
        lines.append(f"- value: {redact(str(finding.get('value', '')))}")
        lines.append(f"- source: {finding.get('source', '')}")
        lines.append(f"- status: {finding.get('status', '')}")
        if finding.get("confidence"):
            lines.append(f"- confidence: {finding.get('confidence')}")
        lines.append("")
        if finding.get("narrative"):
            lines.append(str(finding["narrative"]).strip())
            lines.append("")
        lines.append("Impact")
        lines.append("")
        lines.append(f"{finding.get('impact', '')}")
        lines.append("")
        lines.append("Proof")
        lines.append("")
        lines.append("```")
        lines.append(str(finding.get("proof", "")).strip())
        lines.append("```")
        lines.append("")
        lines.append("Reproduction")
        lines.append("")
        lines.append("```")
        for step in finding.get("reproduction", []):
            lines.append(step)
        lines.append("```")
        lines.append("")
        lines.append("Remediation")
        lines.append("")
        lines.append("Rotate the credential, remove it from client code, and move "
                     "the value behind a server-side configuration path.")
        lines.append("")
    if out_of_scope:
        lines.append("## Out of scope skipped")
        lines.append("")
        for url in out_of_scope[:50]:
            lines.append(f"- {url}")
        lines.append("")
    return "\n".join(lines)


def save(target: str, summary: dict, findings: list[dict],
         out_dir: str | Path, out_of_scope: list[str] | None = None) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.md"
    path.write_text(render(target, summary, findings, out_of_scope))
    return path


def save_json(out_dir: str | Path, summary: dict, findings: list[dict]) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "results.json"
    path.write_text(json.dumps({"summary": summary, "findings": findings}, indent=2, default=str))
    return path


def save_jsonl(out_dir: str | Path, findings: list[dict]) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "results.jsonl"
    with open(path, "w") as handle:
        for finding in findings:
            handle.write(json.dumps(finding, default=str) + "\n")
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
        rules.setdefault(secret_type, {
            "id": secret_type,
            "name": secret_type,
            "shortDescription": {"text": f"Exposed {secret_type} credential"},
            "helpUri": "https://github.com/DeathShotXD/NetCast3r",
        })
        results.append({
            "ruleId": secret_type,
            "level": LEVELS.get(str(finding.get("severity", "")).lower(), "warning"),
            "message": {"text": finding.get("title", "exposed credential")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("source", "")}
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
