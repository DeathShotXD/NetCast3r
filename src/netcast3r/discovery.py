"""Surface extraction from stored evidence.

Parameters and injectable points are read out of what the mission already
observed - endpoint URLs in the graph, agent notes, and tool-call arguments -
never by firing a scan. A parameter is a real, observed name; whether it is
injectable is a separate test.
"""

from __future__ import annotations

import re

from . import kb

PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.\-]{0,40})=")
JSON_KEY_RE = re.compile(r"[\"']([A-Za-z_][A-Za-z0-9_\-]{0,40})[\"']\s*:")
PATH_RE = re.compile(r"https?://[^\s\"'<>)\]]+")


def _host_of(target: str) -> str:
    from .graph import host_of

    return host_of(target)


def extract_parameters(index, mission_id: str, limit: int = 200) -> dict:
    """Collect observed parameter names and record them as graph nodes and KB."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    seen: dict[str, dict] = {}

    def add(name: str, source: str) -> None:
        name = str(name or "").strip()
        if not name or len(name) > 40:
            return
        entry = seen.setdefault(name, {"name": name, "sources": []})
        if source not in entry["sources"]:
            entry["sources"].append(source)

    for node in index.list_graph_nodes(mission_id, kind="endpoint"):
        for match in PARAM_RE.findall(str(node.get("key") or "")):
            add(match, "endpoint")
    for note in index.list_agent_notes(mission_id, limit=500):
        text = f"{note.get('title', '')} {note.get('body', '')}"
        for match in PARAM_RE.findall(text):
            add(match, "note")
        for match in JSON_KEY_RE.findall(text):
            add(match, "note")
    calls, _ = index.list_tool_calls(mission_id=mission_id, limit=500)
    for call in calls:
        args = call.get("args") or {}
        url = str(args.get("target") or args.get("url") or "")
        for match in PARAM_RE.findall(url):
            add(match, "tool_call")

    host = _host_of(str(mission.get("target") or ""))
    parameters = list(seen.values())[:max(1, int(limit or 200))]
    for row in parameters:
        index.upsert_graph_node(mission_id, "parameter", row["name"],
                                label=row["name"], confidence="observed",
                                data={"sources": row["sources"]})
        kb.record(index, "global", "parameter", row["name"], title=row["name"],
                  body=f"Parameter observed on {host}",
                  source={"mission_id": mission_id})
    # A parameter node satisfies the "injectable_parameter" evidence slot for
    # exploit planning; the module still has to prove injectability.
    return {"mission_id": mission_id, "count": len(seen),
            "parameters": parameters}
