"""The evidence graph and attack paths.

Penligent calls this attack-path management. NetCast3r's version keeps one
rule Penligent's public material does not: every node and every edge is either
derived from a real observation (a run, a tool call, a hypothesis, a finding)
or added explicitly by an agent, and every edge records that provenance and a
confidence. The graph never presents a guess as a fact.

From the graph, `derive_paths` proposes candidate chains toward an impact, and
`verify_path` tests a path step by step through the same scoped, risk-gated
tools every other caller uses. Verification records supports, refutes, or
inconclusive per step. It creates no finding; a promoted finding is still a
separate, human-gated write.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+")

NODE_KINDS = {"target", "host", "ip", "service", "technology", "endpoint",
              "parameter", "identity", "credential", "finding", "hypothesis"}
EDGE_KINDS = {"in_scope", "resolves_to", "exposes", "tests", "tested_by",
              "leads_to", "verified_by"}
PATH_STATES = {"candidate", "verifying", "verified", "partial", "refuted",
               "blocked", "inconclusive"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def host_of(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    try:
        return (urlsplit(text if "://" in text else f"https://{text}").hostname
                or "").lower()
    except ValueError:
        return ""


def _looks_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255
                                   for part in parts)


def _compact(payload, limit: int = 1600) -> dict:
    """Retained for compatibility; the executor owns compaction now."""
    from .steps import compact

    return compact(payload, limit)


def _urls(text: str) -> list[str]:
    found = []
    for match in URL_RE.findall(str(text or "")):
        cleaned = match.rstrip(".,;:")
        if cleaned not in found:
            found.append(cleaned)
    return found[:20]


def _node(index, mission_id: str, kind: str, key: str, label: str = "",
          severity: str = "", confidence: str = "observed", data=None) -> dict:
    return index.upsert_graph_node(mission_id, kind, key, label=label,
                                   severity=severity, confidence=confidence,
                                   data=data)


def _finding_rows(index, mission: dict) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for run in mission.get("runs") or []:
        items, _ = index.list_findings(run_id=run.get("id", ""), limit=200)
        for item in items:
            if item["id"] not in seen:
                seen.add(item["id"])
                rows.append(item)
    return rows


def build_mission_graph(index, mission_id: str) -> dict:
    """Derive nodes and edges for one mission from stored, real evidence."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    target = str(mission.get("target") or "").strip()
    host = host_of(target)
    if not target or not host:
        raise ValueError("mission has no usable target")

    target_node = _node(index, mission_id, "target", target, label=target,
                        data={"url": target, "mission": mission.get("title", "")})
    host_kind = "ip" if _looks_ip(host) else "host"
    host_node = _node(index, mission_id, host_kind, host, label=host)
    index.upsert_graph_edge(mission_id, target_node["id"], host_node["id"],
                            "resolves_to",
                            evidence={"mission_id": mission_id})

    # Scope entries become in-scope nodes; a leading "!" is an exclusion.
    for entry in mission.get("scope") or []:
        text = str(entry or "").strip()
        if not text or text.startswith("!"):
            continue
        scope_host = host_of(text) or text
        kind = "ip" if _looks_ip(scope_host) else "host"
        node = _node(index, mission_id, kind, scope_host, label=scope_host)
        index.upsert_graph_edge(mission_id, target_node["id"], node["id"],
                                "in_scope", evidence={"scope": text})

    endpoints: dict[str, dict] = {}

    def endpoint(url: str, evidence: dict) -> dict:
        node = endpoints.get(url) or _node(index, mission_id, "endpoint", url,
                                           label=url)
        endpoints[url] = node
        index.upsert_graph_edge(mission_id, host_node["id"], node["id"],
                                "exposes", evidence=evidence)
        return node

    # Hypotheses: a falsifiable test is an explicit, low-confidence claim.
    for hyp in index.list_hypotheses(mission_id=mission_id, limit=200)[0]:
        key = str(hyp.get("id") or hyp.get("title") or "")
        node = _node(index, mission_id, "hypothesis", key,
                     label=str(hyp.get("title") or "hypothesis"),
                     confidence="hypothesis",
                     data={"technique": hyp.get("technique", ""),
                           "expected": hyp.get("expected", ""),
                           "status": hyp.get("status", "")})
        index.upsert_graph_edge(mission_id, node["id"], host_node["id"],
                                "tests", evidence={"hypothesis_id": key})
        for url in _urls(hyp.get("target", "")) + _urls(hyp.get("rationale", "")):
            if host_of(url) == host:
                endpoint(url, {"hypothesis_id": key})

    # Findings: observed impact. Severity comes from the finding, not a guess.
    for finding in _finding_rows(index, mission):
        severity = str(finding.get("severity_override")
                       or finding.get("severity") or "info")
        node = _node(index, mission_id, "finding", str(finding.get("id")),
                     label=str(finding.get("title") or "finding"),
                     severity=severity,
                     data={"triage": finding.get("triage_status", ""),
                           "fingerprint": finding.get("fingerprint", "")})
        index.upsert_graph_edge(mission_id, host_node["id"], node["id"],
                                "leads_to",
                                evidence={"finding_id": finding.get("id"),
                                          "run_id": finding.get("run_id", "")})
        for url in _urls(finding.get("value", "")) + _urls(finding.get("source", "")):
            if host_of(url) == host:
                endpoint(url, {"finding_id": finding.get("id")})

    # Agent notes: any URL an agent wrote down is a real, observed endpoint.
    for note in index.list_agent_notes(mission_id, limit=500):
        for url in _urls(f"{note.get('title', '')} {note.get('body', '')}"):
            if host_of(url) == host:
                endpoint(url, {"note_id": note.get("id"),
                               "kind": note.get("kind", "")})

    # Tool calls: the strongest provenance there is. Each call is evidence.
    calls, _ = index.list_tool_calls(mission_id=mission_id, limit=500)
    for call in calls:
        args = call.get("args") or {}
        url = str(args.get("target") or args.get("url") or "")
        if url and host_of(url) == host:
            node = endpoint(url, {"tool_call_id": call.get("id"),
                                  "tool": call.get("tool", "")})
            index.upsert_graph_edge(mission_id, host_node["id"], node["id"],
                                    "tested_by",
                                    evidence={"tool_call_id": call.get("id"),
                                              "tool": call.get("tool", ""),
                                              "status": call.get("status", "")})

    nodes = index.list_graph_nodes(mission_id)
    edges = index.list_graph_edges(mission_id)
    return {"mission_id": mission_id, "nodes": len(nodes), "edges": len(edges),
            "target": target, "host": host,
            "kinds": _counts(nodes, "kind")}


def _counts(rows: list[dict], key: str) -> dict:
    out: dict = {}
    for row in rows:
        value = str(row.get(key) or "")
        out[value] = out.get(value, 0) + 1
    return out


def derive_paths(index, mission_id: str) -> list[dict]:
    """Candidate chains toward an impact, from open leads and the surface."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    host = host_of(mission.get("target", ""))
    nodes = {(node["kind"], node["key"]): node
             for node in index.list_graph_nodes(mission_id)}
    host_node = nodes.get(("host", host)) or nodes.get(("ip", host)) or {}
    finding_by_host: dict[str, dict] = {}
    for node in index.list_graph_nodes(mission_id, kind="finding"):
        finding_by_host.setdefault(host, node)
    endpoints = [node for node in index.list_graph_nodes(mission_id,
                                                         kind="endpoint")
                 if node.get("key")]

    hypotheses = index.list_hypotheses(mission_id=mission_id, status="open",
                                       limit=100)[0]
    paths: list[dict] = []
    for hyp in hypotheses:
        hyp_host = host_of(hyp.get("target", "")) or host
        steps = [{"kind": "test", "hypothesis_id": hyp.get("id", ""),
                  "goal": str(hyp.get("title") or "test the lead"),
                  "target": str(hyp.get("target") or mission.get("target")),
                  "technique": str(hyp.get("technique") or ""),
                  "expected": str(hyp.get("expected") or "")}]
        impact = finding_by_host.get(hyp_host)
        if impact:
            steps.append({"kind": "impact", "finding_id": impact.get("key"),
                          "goal": "Confirm the recorded impact still reproduces",
                          "target": str(mission.get("target"))})
        path = index.upsert_graph_path(
            mission_id, str(hyp.get("title") or "Candidate path"),
            entry_node=host_node.get("id", ""),
            impact_node=(impact or {}).get("id", ""),
            steps=steps, state="candidate")
        paths.append(path)

    if endpoints and not hypotheses:
        steps = [{"kind": "probe", "goal": f"Compare {node['label']} with the baseline",
                  "target": node["key"]} for node in endpoints[:3]]
        path = index.upsert_graph_path(
            mission_id, f"Surface review: {host}", entry_node=host_node.get("id", ""),
            steps=steps, state="candidate")
        paths.append(path)
    return paths


def rebuild(index, mission_id: str) -> dict:
    summary = build_mission_graph(index, mission_id)
    paths = derive_paths(index, mission_id)
    summary["paths"] = len(paths)
    return summary


# -- verification ---------------------------------------------------------
def verify_path(index, mission: dict, path: dict, registry, complete=None,
                on_step=None, should_stop=None) -> dict:
    """Run a path step by step and record what each observation supports."""
    from . import steps as steps_module

    mission_id = str(mission.get("id") or path.get("mission_id") or "")
    host = host_of(mission.get("target", ""))
    result = steps_module.execute_steps(
        path.get("steps") or [], host, mission_id, registry,
        complete=_as_role(complete), on_step=on_step, should_stop=should_stop)
    state = steps_module.state_of(result["supports"], result["refutes"],
                                  result["blocked"], result["ran"],
                                  result["cancelled"])
    summary = "cancelled" if result["cancelled"] else "path verified"
    verdict_summary = {"state": state, "summary": summary,
                       "supports": result["supports"], "refutes": result["refutes"],
                       "blocked": result["blocked"], "steps": result["steps"],
                       "ran": result["ran"], "at": result["at"]}
    index.patch_graph_path(path["id"], state=state, verdict=verdict_summary)
    if on_step:
        on_step("decide", {"agent": "path",
                           "text": f"path {state}: {result['supports']} supported, "
                                   f"{result['refutes']} refuted, "
                                   f"{result['blocked']} blocked"})
    return {"path_id": path["id"], "state": state,
            "supports": result["supports"], "refutes": result["refutes"],
            "blocked": result["blocked"], "steps": result["steps"],
            "findings": 0}


def _as_role(complete):
    """steps.judge calls complete(role, messages); accept a one-arg callable."""
    if complete is None:
        return None
    try:
        if getattr(complete, "__code__", None) and complete.__code__.co_argcount == 1:
            return lambda role, messages: complete(messages)
    except (AttributeError, TypeError):
        pass
    return complete
