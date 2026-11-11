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


def _block(text, value: str = "") -> str:
    """Secret-free multi-line field: keep the author's markdown structure."""
    return (_scrub(text, value).replace("\r\n", "\n").replace("\r", "\n")
            .strip("\n"))


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


def _req_rank(req: dict, evidence: str = "") -> int:
    """Lower is a stronger demonstration of the issue."""
    target = str(req.get("target") or "").lower()
    traversal = ("../", "..%2f", "..%5c", "..%252f", "..\\", "%2e%2e", "/etc/")
    injection = ("<script", "union+select", "union%20select", "{{", "${", "';",
                 "\" or ", "sleep(", "waitfor")
    rank = 3
    if any(marker in target for marker in traversal):
        rank = 0
    elif any(marker in target for marker in injection):
        rank = 1
    else:
        status = req.get("status")
        if isinstance(status, int) and status >= 500:
            rank = 2
    # A request whose query value (or file name) is named in the write-up is the
    # exact one that was proven, so it outranks its neighbours. Only traversal
    # requests are eligible, so a baseline "file=web.config" never wins.
    if rank == 0 and evidence and "file=" in target:
        raw = target.split("file=", 1)[-1]
        if raw in evidence:
            return -2
        decoded = raw
        for escape in ("%2f", "%5c", "%252f"):
            decoded = decoded.replace(escape, "/")
        name = decoded.rstrip("/").rsplit("/", 1)[-1]
        if len(name) > 3 and name in evidence:
            return -1
    return rank


def _poc_chain_requests(finding: dict) -> list[dict]:
    """The HTTP requests worth replaying, pulled from the finding's evidence.

    Only recorded observations qualify: a request that actually reached the
    target. Planning calls, notes, and artifacts are not reproduction steps.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for item in finding.get("evidence_chain") or []:
        if not isinstance(item, dict) or item.get("kind") != "tool_call":
            continue
        if str(item.get("tool") or "") not in {"http_request", "http_probe", "http"}:
            continue
        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        target = str(request.get("target") or "").strip()
        if not target:
            continue
        method = str(request.get("method") or "GET").upper() or "GET"
        key = (method, target)
        if key in seen:
            continue
        seen.add(key)
        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        out.append({
            "at": str(item.get("at") or ""),
            "method": method,
            "target": target,
            "status": response.get("status"),
            "bytes": response.get("bytes"),
        })
    return out


def _shell(value: str) -> str:
    """Quote for a shell only when the value would not survive word-splitting."""
    text = str(value)
    safe = set("-_./:@=%?&+,~")
    if text and all(ch.isalnum() or ch in safe for ch in text):
        return text
    return "'" + text.replace("'", "'\\''") + "'"


def _poc_curl(req: dict) -> str:
    method = req.get("method") or "GET"
    parts = ["curl", "-sS", "-i", "-X", method]
    for name, value in (req.get("headers") or {}).items():
        if str(name).lower() in {"content-length", "date", "connection"}:
            continue
        parts += ["-H", f"{name}: {value}"]
    parts.append(req["target"])
    return " ".join(_shell(part) for part in parts)


def _poc_evidence_curl(evidence: str) -> str:
    """Use a curl block already written in the evidence when no call was logged.

    Manual findings often carry their reproduction command inside the evidence
    markdown. Prefer a fenced block that starts with curl so the generated PoC
    stays runnable instead of replacing it with a placeholder.
    """
    for match in re.finditer(r"```[A-Za-z0-9_-]*\s*\n(.*?)```", evidence or "",
                             re.S):
        body = match.group(1).strip()
        if body.lower().startswith("curl "):
            return body
    return ""


def _demote_headings(text: str, levels: int = 2) -> str:
    """Nest headings from embedded evidence below the section that carries them.

    Evidence is written as a standalone markdown document, so it starts at h1
    and uses h2 for its own sections. Inserting it verbatim under ``## Proof``
    would collide with the generated document's headings. Demote every ATX
    heading by ``levels`` (never past h6) and leave fenced code untouched.
    """
    out: list[str] = []
    fence = ""
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not fence:
                fence = marker
            elif fence == marker:
                fence = ""
            out.append(line)
            continue
        if fence:
            out.append(line)
            continue
        match = re.match(r"^(#{1,6})(\s+.*)$", line)
        if match:
            hashes = "#" * min(6, len(match.group(1)) + levels)
            out.append(hashes + match.group(2))
        else:
            out.append(line)
    return "\n".join(out)


def _interesting(req: dict) -> bool:
    """Rank the exploit request above the reconnaissance ones."""
    target = str(req.get("target") or "")
    markers = ("../", "..%2f", "%2e%2e", "file=", "?id=", "?url=", "?path=",
               "<script", "union+select", "union%20select", "{{", "${")
    if any(marker in target.lower() for marker in markers):
        return True
    status = req.get("status")
    return isinstance(status, int) and status >= 500


def render_finding_poc(finding: dict, mission: dict | None = None,
                       submission: dict | None = None) -> str:
    """A humanized, submission-ready proof of concept for one finding.

    Assembles the finding's own words and the requests that were actually
    recorded into a document a reviewer can follow by hand: a plain-language
    summary, numbered reproduction steps, copy-paste curl and Python, the
    evidence on file, and remediation. Secrets are redacted exactly as in the
    run report, so the PoC never leaks the raw value it proves.
    """
    mission = mission or {}
    submission = submission or {}
    finding = public_finding(finding)

    title = _inline(finding.get("title", "finding")) or "finding"
    severity = _inline(finding.get("severity", "unknown")) or "unknown"
    kind = _inline(finding.get("secret_type", "") or finding.get("type", "")) or "n/a"
    target = _inline(mission.get("target", "") or submission.get("target", "")
                     or finding.get("target", "")) or "(not recorded)"
    status = _inline(finding.get("triage_status", "") or finding.get("status", "")) or "untriaged"
    confidence = finding.get("confidence")
    created = _inline(finding.get("created_at", ""))

    impact = _inline(finding.get("impact", ""))
    evidence = _block(finding.get("evidence", ""))
    source = _inline(finding.get("source", ""))
    notes = _block(finding.get("notes", ""))

    requests = _poc_chain_requests(finding)
    key_request = None
    if requests:
        hint = f"{evidence} {impact}".lower()
        key_request = min(requests, key=lambda r: (_req_rank(r, hint), str(r.get("at") or "")))
    total_requests = len(requests)
    requests = requests[:10]

    summary_lines: list[str] = []
    if impact:
        summary_lines.append(impact)
    if not summary_lines:
        summary_lines.append(
            "This finding was recorded without a written impact statement. "
            "Reproduce the request below and describe the difference you observe.")

    asset = ""
    if key_request:
        asset = str(key_request["target"])
    elif requests:
        asset = str(requests[0]["target"])
    if not asset:
        asset = target or source

    step_lines: list[str] = []
    for index, req in enumerate(requests, start=1):
        note = ""
        if isinstance(req.get("status"), int):
            note = f" Observe the response status ({req['status']})."
        if key_request and req["target"] == key_request["target"] and req["method"] == key_request["method"]:
            note += " This is the request that demonstrates the issue."
        step_lines.append(f"{index}. Send `{req['method']} {req['target']}`.{note}")

    curl_blocks: list[str] = []
    python_lines = ["import requests", ""]
    for req in requests:
        curl_blocks.append(_poc_curl(req))
        python_lines.append(
            f"response = requests.request({req['method']!r}, {req['target']!r})")
        if isinstance(req.get("status"), int):
            python_lines.append(f"assert response.status_code == {req['status']}")
        python_lines.append("print(response.status_code)")
        python_lines.append("print(response.text[:400])")
        python_lines.append("")
    evidence_curl = _poc_evidence_curl(evidence)
    curl_text = ("\n\n".join(curl_blocks) or evidence_curl
                 or "# no structured request was recorded; use the proof below")
    python_text = "\n".join(python_lines).strip()

    lines: list[str] = [f"# {title}", ""]
    lines.append(f"- **Severity:** {severity}")
    lines.append(f"- **Type:** {kind}")
    lines.append(f"- **Target:** {target}")
    if mission.get("title"):
        lines.append(f"- **Mission:** {_inline(mission['title'])}")
    if created:
        lines.append(f"- **Recorded:** {created}")
    lines.append(f"- **Status:** {status}")
    if isinstance(confidence, (int, float)) and confidence:
        lines.append(f"- **Confidence:** {confidence}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.extend(summary_lines)
    lines.append("")

    if asset:
        lines.append("## Affected asset")
        lines.append("")
        lines.append(f"`{asset}`")
        lines.append("")

    lines.append("## Steps to reproduce")
    lines.append("")
    if step_lines:
        lines.extend(step_lines)
        extra = total_requests - len(requests)
        if extra > 0:
            lines.append(f"{len(requests) + 1}. {extra} further probe(s) were recorded; "
                         "the full request log is in the evidence on file.")
    else:
        lines.append("1. No structured request step was recorded on this finding. "
                     "Use the manual verification or the proof below to replay it.")
    lines.append("")

    lines.append("## Manual verification")
    lines.append("")
    lines.append("### curl")
    lines.append("")
    lines.append("```bash")
    lines.append(curl_text)
    lines.append("```")
    lines.append("")
    if requests:
        lines.append("### python")
        lines.append("")
        lines.append("```python")
        lines.append(python_text)
        lines.append("```")
        lines.append("")

    if evidence:
        lines.append("## Proof")
        lines.append("")
        lines.append(_demote_headings(evidence))
        lines.append("")

    artifacts = [a for a in (finding.get("artifacts") or []) if isinstance(a, dict)]
    if artifacts:
        lines.append("## Evidence on file")
        lines.append("")
        for artifact in artifacts[:20]:
            name = _inline(artifact.get("name", "artifact"))
            digest = _inline(artifact.get("sha256", ""))
            size = artifact.get("bytes") or 0
            line = f"- `{name}` ({size} bytes"
            if digest:
                line += f", sha256 {digest[:16]}"
            line += ")"
            lines.append(line)
        lines.append("")

    lines.append("## Impact")
    lines.append("")
    lines.append(impact or "Not yet written. Describe the concrete impact before "
                 "filing this report.")
    lines.append("")

    lines.append("## Remediation")
    lines.append("")
    if kind == "path-traversal" or "traversal" in kind:
        lines.append("Resolve the requested file against a fixed allow-list instead "
                     "of the application root, reject any name that escapes it, and "
                     "rotate every credential the readable file exposed.")
    elif "credential" in kind or "secret" in kind or "key" in kind or "token" in kind:
        lines.append("Rotate the exposed credential, remove it from any reachable "
                     "artifact, and move it behind server-side configuration.")
    else:
        lines.append("Fix the underlying weakness, then re-run the steps above to "
                     "confirm the difference is gone.")
    lines.append("")

    if notes:
        lines.append("## Notes")
        lines.append("")
        lines.append(notes)
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"_Auto-generated from finding `{_inline(finding.get('id', ''))}` by "
                 "NetCast3r. Reproduce only against the authorised target._")
    return "\n".join(lines)


def finding_poc_filename(finding: dict, submission: dict | None = None) -> str:
    """A stable, filesystem-safe name for a finding's PoC report."""
    basis = str((submission or {}).get("id") or finding.get("id") or "finding")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", basis).strip("-") or "finding"
    return f"{safe}-poc.md"


def _pdf_escape(text: str) -> str:
    return (str(text or "").replace("\\", "\\\\").replace("(", "\\(")
            .replace(")", "\\)"))


def markdown_to_pdf_bytes(markdown: str, title: str = "NetCast3r report") -> bytes:
    """Minimal text PDF from markdown. No external PDF library required.

    Headings and bullets become plain Helvetica lines. This is a delivery
    artifact for operators who need a PDF companion to the Markdown report,
    not a typeset layout engine. Secrets must already be redacted in the
    markdown.
    """
    lines: list[str] = []
    for raw in str(markdown or "").splitlines():
        text = raw.rstrip()
        if text.startswith("# "):
            lines.append(text[2:].strip())
            lines.append("")
        elif text.startswith("## "):
            lines.append(text[3:].strip())
            lines.append("")
        elif text.startswith("### "):
            lines.append(text[4:].strip())
        elif text.startswith("- "):
            lines.append("* " + text[2:].strip())
        elif text.startswith("```"):
            continue
        else:
            lines.append(text)
        if len(lines) >= 900:
            lines.append("... truncated ...")
            break
    if not lines:
        lines = [title, "", "No content."]

    content_lines = ["BT", "/F1 11 Tf", "50 780 Td", "14 TL"]
    first = True
    y_budget = 0
    for line in lines:
        chunk = _pdf_escape(line[:110])
        if first:
            content_lines.append(f"({chunk}) Tj")
            first = False
        else:
            content_lines.append("T*")
            content_lines.append(f"({chunk}) Tj")
        y_budget += 1
        if y_budget >= 52:
            # Soft page break: continue stream; viewers still show one page of
            # dense text which is enough for a submission companion.
            break
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", "replace")

    objects: list[bytes] = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n")
    objects.append(
        f"4 0 obj<< /Length {len(stream)} >>stream\n".encode()
        + stream + b"\nendstream\nendobj\n")
    objects.append(
        b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)
    xref = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode())
    out.extend(
        f"trailer<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n".encode())
    return bytes(out)


def save_pdf(out_dir: str | Path, markdown: str,
             name: str = "report.pdf") -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(markdown_to_pdf_bytes(markdown))
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


LEVELS = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note", "informational": "note"}


def _sarif_rule_id(finding: dict) -> str:
    """A stable rule id for any finding, not only a secret type."""
    raw = str(finding.get("rule_id") or finding.get("secret_type")
              or finding.get("category") or finding.get("cwe")
              or "netcast3r.finding")
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-")
    return clean[:100] or "netcast3r.finding"


def save_sarif(out_dir: str | Path, findings: list[dict]) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "results.sarif"
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in findings:
        rule_id = _sarif_rule_id(finding)
        secret_type = str(finding.get("secret_type") or "")
        value = str(finding.get("value", ""))
        pair = str(finding.get("pair_value") or "")
        title = str(finding.get("title") or finding.get("summary")
                    or "finding")[:500]

        def scrub(text):
            text = _scrub(text, value)
            return _scrub(text, pair)

        description = str(finding.get("description") or finding.get("impact")
                          or finding.get("proof") or title)[:2000]
        source = str(finding.get("source") or finding.get("target")
                     or finding.get("url") or "")
        line = finding.get("line") or finding.get("start_line")
        severity = str(finding.get("severity", "")).lower()
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {
                "text": (f"Exposed {secret_type} credential" if secret_type
                         else title[:200])},
            "fullDescription": {"text": scrub(description)},
            "helpUri": "https://github.com/DeathShotXD/NetCast3r",
            "properties": {"tags": ["security"]},
        })
        physical = {"artifactLocation": {"uri": scrub(source)}}
        try:
            start = int(line)
        except (TypeError, ValueError):
            start = 0
        if start > 0:
            physical["region"] = {"startLine": start}
        result = {
            "ruleId": rule_id,
            "level": LEVELS.get(severity, "warning"),
            "message": {"text": scrub(title)},
            "locations": [{"physicalLocation": physical}],
            "properties": {},
        }
        for key in ("confidence", "status", "cwe", "cvss", "module_id",
                    "technique", "source_kind"):
            if finding.get(key) not in (None, "", []):
                result["properties"][key] = finding[key]
        if not result["properties"]:
            result.pop("properties")
        results.append(result)
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
