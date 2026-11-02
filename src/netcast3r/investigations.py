"""Hypothesis evidence.

A lead in NetCast3r is a hypothesis, not a finding. This module answers the
question a human actually asks: *what happened to this lead?* It collects the
recorded tests, notes, tool calls, graph nodes, and runs that mention the
hypothesis, and it says plainly whether the lead is untested, supported,
refuted, inconclusive, promoted, or archived.

Matching is keyword-based and conservative. A false connection is labeled as a
possible match; it is never presented as proof.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

STOPWORDS = {
    "test", "testing", "the", "and", "for", "with", "from", "this", "that",
    "into", "onto", "main", "domain", "exists", "exist", "identity", "cloud",
    "return", "returns", "response", "request", "using", "show", "role",
    "token", "read", "only", "call", "one", "can", "use", "you", "your",
    "have", "has", "are", "was", "were", "not", "but", "all", "any",
    "name", "role", "read-only", "expected", "proof",
}
PLANNING_TOOLS = {
    "hunt_brief", "technique_plan", "chain_plan", "skill_packs",
    "lessons_list", "agent_notes_list", "kb_digest", "campaign_status",
    "target_profile", "directions_list", "tool_calls_list", "missions_get",
    "agent_notes_write", "hypothesis_create", "technique_search",
    "hypothesis_list", "hypothesis_get",
}
PLANNING_NOTE_KINDS = {"brief", "plan", "director.plan"}
LEAD_NOTE_KINDS = {"swarm.observation"}
MAX_EVIDENCE = 200
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
REQUEST_RE = re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+(/[^\s\"'<>]+)",
                        re.I)
NEGATIVE_HINTS = ("no ", "not ", "absent", "failed", "blocked", "inconclusive",
                  "refuted", "dead-end", "dead end", "404", "403", "error")
PLANNING_TITLE_HINTS = ("planning", "strategy", "chain", "brief", "round",
                        "summary")

TECHNIQUE_HINTS = (
    (("ssrf", "server-side request", "metadata"), "ssrf",
     "An OAST callback from the server, then a metadata response only where "
     "the programme permits it."),
    (("open redirect", "redirect parameter", "redirect uri"), "open-redirect",
     "The exact request and Location header to an external host, plus the "
     "security-relevant flow it enables."),
    (("idor", "bola", "object authorization", "object-level"), "idor",
     "Two identities you own; the second reads or changes the first one's "
     "object without permission."),
    (("xss", "cross-site scripting", "html sink"), "xss",
     "The payload executes in a real browser; show the sink, the context, and "
     "the executed request."),
    (("cache", "poison", "deception"), "cache",
     "The poison request, the clean read, and the cache header that proves the "
     "response was shared."),
    (("jwt", "token", "session", "mfa", "2fa"), "auth",
     "A token or session that crosses an authorization boundary, with the "
     "baseline and the bypass response."),
    (("traversal", "lfi", "path"), "path-traversal",
     "The request and the file or path reached outside the intended root."),
)


def _infer(title: str, body: str) -> tuple[str, str]:
    text = f"{title} {body}".lower()
    for words, technique, expected in TECHNIQUE_HINTS:
        if any(word in text for word in words):
            return technique, expected
    return "observation", ("A reproducible difference that proves the claim, "
                           "not just reachability.")


def _url_in(text: str) -> str:
    match = URL_RE.search(str(text or ""))
    return match.group(0).rstrip(".,;") if match else ""


def _path_hint(hypothesis: dict) -> str:
    target = str(hypothesis.get("target") or "")
    try:
        parts = urlsplit(target if "://" in target else f"https://{target}")
    except ValueError:
        return ""
    path = (parts.path or "").strip("/")
    if len(path) < 3:
        return ""
    return path.lower()


def _target_for(title: str, body: str, mission_target: str) -> str:
    """Prefer the in-scope request endpoint, never the attacker URL."""
    request = REQUEST_RE.search(body) or REQUEST_RE.search(title)
    target = str(mission_target or "").strip()
    parts = urlsplit(target if "://" in target else f"https://{target}")
    origin = f"{parts.scheme}://{parts.netloc}" if parts.netloc else target
    if request:
        path = request.group(1).rstrip(".,;")
        return f"{origin.rstrip('/')}{path}"
    candidate = _url_in(body) or _url_in(title)
    if candidate:
        try:
            host = (urlsplit(candidate).hostname or "").lower()
            mission_host = (parts.hostname or "").lower()
            if mission_host and (host == mission_host
                                 or host.endswith("." + mission_host)):
                return candidate
        except ValueError:
            pass
    return target


def _norm_title(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def sync_from_notes(index, mission_id: str, limit: int = 3) -> dict:
    """Turn recorded positive observations into visible hypotheses.

    This is not a scanner and it does not invent a lead. It only reads notes
    the swarm already wrote, requires a concrete title, and creates a
    hypothesis with the note id in its rationale. Dead ends, briefs, plans,
    and generic round summaries are ignored.
    """
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    existing, _ = index.list_hypotheses(mission_id=mission_id, limit=1000)
    titles = {_norm_title(item.get("title")) for item in existing}
    rationales = " ".join(str(item.get("rationale") or "") for item in existing)
    created = []
    skipped = []
    limit = max(1, min(int(limit or 3), 20))
    notes = index.list_agent_notes(mission_id, limit=500)
    for note in reversed(notes):
        if str(note.get("kind") or "") not in LEAD_NOTE_KINDS:
            continue
        title = str(note.get("title") or "").strip()
        body = str(note.get("body") or "").strip()
        if len(title) < 8 or len(body) < 20:
            continue
        lower = title.lower()
        body_lower = body.lower()
        if any(word in lower for word in PLANNING_TITLE_HINTS):
            skipped.append({"note_id": note.get("id"), "title": title,
                            "reason": "planning note"})
            continue
        if any(word in f"{lower} {body_lower}" for word in NEGATIVE_HINTS):
            skipped.append({"note_id": note.get("id"), "title": title,
                            "reason": "negative or inconclusive observation"})
            continue
        technique, expected = _infer(title, body)
        # Only a named technique earns a lead. This keeps an ordinary
        # "endpoint exists" note from becoming a hypothesis.
        target = _target_for(title, body, str(mission.get("target") or ""))
        if technique == "observation":
            # An ordinary 301, an endpoint that exists, or a scope check is a
            # fact, not an actionable lead. Only a named technique earns a
            # hypothesis from a note.
            skipped.append({"note_id": note.get("id"), "title": title,
                            "reason": "no named technique"})
            continue
        if _norm_title(title) in titles or str(note.get("id")) in rationales:
            skipped.append({"note_id": note.get("id"), "title": title,
                            "reason": "lead already exists"})
            continue
        if len(created) >= limit:
            break
        rationale = (f"Derived from recorded note {note.get('id')} "
                     f"({note.get('created_at')}): {body[:1200]}")
        try:
            hypothesis = index.create_hypothesis(
                title=title[:200], target=target, mission_id=mission_id,
                technique=technique, rationale=rationale,
                expected=expected)
        except ValueError as exc:
            skipped.append({"note_id": note.get("id"), "title": title,
                            "reason": str(exc)})
            continue
        created.append(hypothesis)
        titles.add(_norm_title(title))
        rationales += " " + rationale
    return {
        "mission_id": mission_id,
        "created": created,
        "skipped": skipped[-20:],
        "counts": {"created": len(created), "skipped": len(skipped)},
        "note": ("A created lead is a falsifiable hypothesis. It is not a "
                 "finding and it does not change coverage or the ledger."),
    }


def _terms(hypothesis: dict) -> list[str]:
    text = " ".join(str(hypothesis.get(key) or "") for key in
                    ("title", "technique", "rationale", "expected", "target"))
    target = str(hypothesis.get("target") or "").lower()
    target_host = ""
    path_words: list[str] = []
    try:
        parts = urlsplit(target if "://" in target else f"https://{target}")
        target_host = parts.hostname or ""
        path_words = re.findall(r"[a-z0-9][a-z0-9_-]{3,}",
                                f"{parts.path} {parts.query}".lower())
    except ValueError:
        target_host = target
    words = re.findall(r"[a-z0-9][a-z0-9_.:/-]{3,}", text.lower())
    words.extend(path_words)
    terms = []
    for word in words:
        word = word.strip("._:/-")
        if not word or word in STOPWORDS:
            continue
        # The target host appears in almost every call and is not evidence
        # that this particular hypothesis was tested. A path on the target
        # (for example /fetch) still is.
        if target_host and (word in target_host or target_host in word):
            continue
        if word not in terms:
            terms.append(word)
    return terms[:24]


def _accepted(matched: list[str]) -> bool:
    """One distinctive term, or two weak ones, is evidence.

    Words such as ``open``, ``url``, and ``header`` appear in almost every
    redirect probe. They cannot carry a match on their own.
    """
    if not matched:
        return False
    if any(len(re.sub(r"[-_./]", "", term)) >= 8 for term in matched):
        return True
    return len(matched) >= 2


def _match(text: str, terms: list[str]) -> list[str]:
    lowered = str(text or "").lower()
    compact = re.sub(r"[-_./]", "", lowered)
    matched = []
    for term in terms:
        compact_term = re.sub(r"[-_./]", "", term)
        if term in lowered or (compact_term and compact_term in compact):
            matched.append(term)
    return matched


def _call_text(call: dict) -> str:
    try:
        return json.dumps({
            "tool": call.get("tool"),
            "args": call.get("args"),
            "result": call.get("result"),
            "error": call.get("error"),
        }, default=str)
    except TypeError:
        return str(call)


def render_markdown(record: dict) -> str:
    """A readable case file for one lead, built only from recorded evidence."""
    hypothesis = record.get("hypothesis") or {}
    lines = [
        f"# {hypothesis.get('title') or 'Lead'}",
        "",
        f"- Status: **{hypothesis.get('status') or 'open'}**",
        f"- Progress: {record.get('progress') or ''}",
        f"- Technique: {hypothesis.get('technique') or 'none'}",
        f"- Target: {hypothesis.get('target') or 'none'}",
        f"- Mission: {hypothesis.get('mission_id') or ''}",
        f"- Created: {hypothesis.get('created_at') or ''}",
        f"- Finding: {hypothesis.get('finding_id') or 'none'}",
        "",
        "## What would prove it",
        "",
        str(hypothesis.get("expected") or "No proof criterion recorded."),
        "",
        "## Rationale",
        "",
        str(hypothesis.get("rationale") or ""),
        "",
        "## Recorded test",
        "",
        str(hypothesis.get("test") or "No explicit test recorded."),
        "",
        str(hypothesis.get("result") or "No verdict recorded."),
        "",
        "## Tool calls",
        "",
    ]
    calls = record.get("tool_calls") or []
    if calls:
        lines.extend(["| time | tool | status | target |", "| --- | --- | --- | --- |"])
        for call in calls:
            result = call.get("result") if isinstance(call.get("result"), dict) else {}
            status = result.get("status") if result else ""
            target = str((call.get("args") or {}).get("target") or call.get("error") or "")
            lines.append(
                f"| {call.get('created_at') or ''} | {call.get('tool') or ''} | "
                f"{status or call.get('status') or ''} | {target.replace('|', '%7C')} |")
    else:
        lines.append("No matching tool call recorded.")
    lines.extend(["", "## Observations", ""])
    notes = record.get("notes") or []
    if notes:
        for note in notes:
            lines.extend([
                f"### {note.get('title') or 'observation'}",
                "",
                f"{note.get('created_at') or ''} - {note.get('kind') or ''}",
                "",
                str(note.get("body") or ""),
                "",
            ])
    else:
        lines.append("No matching observation recorded.")
    nodes = record.get("graph_nodes") or []
    if nodes:
        lines.extend(["## Graph nodes", ""])
        for node in nodes[:40]:
            lines.append(f"- {node.get('kind') or ''}: "
                         f"{node.get('label') or node.get('key') or node.get('id')}")
        lines.append("")
    lines.extend([
        "## Evidence rule",
        "",
        record.get("note") or (
            "A hypothesis is a lead, not a finding. Open means the proof has "
            "not been recorded. A finding requires reproducible evidence and a "
            "human promotion."),
        "",
    ])
    return "\n".join(lines)


def evidence(index, hypothesis_id: str, limit: int = MAX_EVIDENCE) -> dict:
    hypothesis = index.get_hypothesis(hypothesis_id)
    if not hypothesis:
        raise ValueError("hypothesis not found")
    mission_id = str(hypothesis.get("mission_id") or "")
    terms = _terms(hypothesis)
    path_hint = _path_hint(hypothesis)
    limit = max(1, min(int(limit or MAX_EVIDENCE), 1000))

    notes = []
    for note in index.list_agent_notes(mission_id, limit=1000):
        if str(note.get("kind") or "") in PLANNING_NOTE_KINDS:
            continue
        text = f"{note.get('kind')} {note.get('title')} {note.get('body')}"
        if path_hint and path_hint not in text.lower():
            continue
        matched = _match(text, terms)
        if (path_hint or (matched and _accepted(matched))
                or hypothesis_id in str(note.get("body") or "")):
            notes.append({**note, "matched_terms": matched})
    notes = notes[-limit:]

    calls = []
    runs: dict[str, dict] = {}
    try:
        rows, _ = index.list_tool_calls(mission_id=mission_id, limit=5000)
    except Exception:  # noqa: BLE001 - evidence is best effort
        rows = []
    for call in rows:
        if str(call.get("tool") or "") in PLANNING_TOOLS:
            continue
        text = _call_text(call)
        if path_hint and path_hint not in text.lower():
            continue
        matched = _match(text, terms)
        if (path_hint or (matched and _accepted(matched))
                or hypothesis_id in text):
            calls.append({**call, "matched_terms": matched})
            run_id = str(call.get("run_id") or "")
            if run_id and run_id not in runs:
                run = index.get_run(run_id)
                if run:
                    runs[run_id] = {
                        "id": run_id, "status": run.get("status"),
                        "created_at": run.get("created_at"),
                        "counts": run.get("counts") or {},
                        "options": run.get("options") or {},
                    }
    # list_tool_calls returns newest first; keep the newest evidence.
    calls = calls[:limit]

    graph_nodes = []
    graph_edges = []
    try:
        for node in index.list_graph_nodes(mission_id):
            if node.get("key") == hypothesis_id or node.get("id") == hypothesis_id:
                graph_nodes.append(node)
            else:
                text = (f"{node.get('kind')} {node.get('label')} "
                        f"{node.get('key')} {node.get('data')}")
                if path_hint and path_hint not in text.lower():
                    continue
                matched = _match(text, terms)
                if path_hint or matched:
                    graph_nodes.append({**node, "matched_terms": matched})
        node_ids = {node["id"] for node in graph_nodes}
        for edge in index.list_graph_edges(mission_id):
            if edge.get("src") in node_ids or edge.get("dst") in node_ids:
                graph_edges.append(edge)
    except Exception:  # noqa: BLE001
        graph_nodes, graph_edges = [], []

    status = str(hypothesis.get("status") or "open")
    if status == "open":
        progress = "untested" if not calls else "evidence recorded, no verdict"
    elif status == "supported":
        progress = "supported by recorded evidence; promote only after reproduction"
    elif status == "refuted":
        progress = "refuted by the recorded evidence"
    elif status == "inconclusive":
        progress = "tested, but the evidence does not decide it"
    elif status == "promoted":
        progress = "promoted to a finding"
    else:
        progress = status

    return {
        "hypothesis": hypothesis,
        "progress": progress,
        "terms": terms,
        "path_hint": path_hint,
        "finding": (index.get_finding(str(hypothesis.get("finding_id") or ""))
                    if hypothesis.get("finding_id") else None),
        "counts": {
            "notes": len(notes),
            "tool_calls": len(calls),
            "runs": len(runs),
            "graph_nodes": len(graph_nodes),
            "graph_edges": len(graph_edges),
        },
        "notes": notes,
        "tool_calls": calls,
        "runs": sorted(runs.values(), key=lambda item: item.get("created_at") or ""),
        "graph_nodes": graph_nodes[:limit],
        "graph_edges": graph_edges[:limit],
        "note": ("A hypothesis is a lead, not a finding. 'Open' means the "
                 "proof has not been recorded, even when an agent has already "
                 "reasoned about it. A verdict is not a finding unless a human "
                 "promotes it with reproducible evidence."),
    }