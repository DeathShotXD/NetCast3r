"""Report writer.

Turns a run into a submission-ready markdown report. Secrets are redacted, and
each finding carries its impact, proof, reproduction, and remediation so it can
go straight into a program.
"""

from __future__ import annotations

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
