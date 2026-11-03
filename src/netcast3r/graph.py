"""The evidence graph and attack paths.

Every node and every edge is either derived from a real observation (a run, a
tool call, a hypothesis, a finding) or added explicitly by an agent, and every
edge records that provenance and a confidence. The graph never presents a guess
as a fact.

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


_SEVERITY_SCORE = {
    "critical": 100, "high": 80, "medium": 55, "low": 30, "info": 10, "": 10,
}

_AUTH_MARKERS = (
    "login", "signin", "signup", "register", "auth", "oauth", "oidc", "saml",
    "sso", "session", "token", "password", "mfa", "2fa", "callback",
)


def _is_auth_surface(node: dict) -> bool:
    text = f"{node.get('key', '')} {node.get('label', '')}".lower()
    return str(node.get("kind") or "") in {"endpoint", "parameter"} and any(
        marker in text for marker in _AUTH_MARKERS)


def _score_node(node: dict, open_lead_ids: set[str]) -> int:
    kind = str(node.get("kind") or "")
    key = str(node.get("key") or "")
    text = f"{key} {node.get('label', '')}".lower()
    severity = str(node.get("severity") or "").lower()
    score = _SEVERITY_SCORE.get(severity, 10)
    if kind == "finding":
        return min(100, score)
    if kind == "hypothesis" and key in open_lead_ids:
        score = max(score, 65 if any(
            token in text for token in
            ("rce", "takeover", "auth", "idor", "ssrf", "sqli")) else 45)
    if _is_auth_surface(node):
        score = max(score, 60)
    elif kind in {"endpoint", "parameter"}:
        score = max(score, 45 if any(
            token in text for token in
            ("api", "graphql", "admin", "admit", "result")) else 25)
    if kind in {"host", "ip", "target"}:
        score = max(score, 20)
    return min(100, score)


def _risk_severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def _threat_type(node: dict, open_lead_ids: set[str]) -> str:
    kind = str(node.get("kind") or "")
    if kind in {"host", "ip", "target"}:
        return "host"
    if kind == "hypothesis" and str(node.get("key") or "") in open_lead_ids:
        return "open_lead"
    if kind == "finding":
        return "finding"
    if _is_auth_surface(node):
        return "auth_surface"
    return "endpoint" if kind in {"endpoint", "parameter"} else kind


def threat_map(index, mission_id: str, limit: int = 80) -> dict:
    """Return an evidence-backed, scored projection of a mission graph."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    limit = max(8, min(int(limit or 80), 200))
    nodes = list(index.list_graph_nodes(mission_id) or [])
    edges = list(index.list_graph_edges(mission_id) or [])
    paths = list(index.list_graph_paths(mission_id) or [])
    leads, _ = index.list_hypotheses(
        mission_id=mission_id, status="open", limit=200)
    findings = _finding_rows(index, mission)
    open_lead_ids = {str(item.get("id") or "") for item in leads}

    host_nodes = [node for node in nodes
                  if node.get("kind") in {"host", "ip", "target"}]
    if not host_nodes:
        host = host_of(mission.get("target", ""))
        host_node = {
            "id": f"th_host_{mission_id}", "kind": "host", "key": host,
            "label": host, "severity": "", "confidence": "observed",
            "data": {"mission_id": mission_id},
        }
        nodes.append(host_node)
        host_nodes.append(host_node)
    anchor_id = str(host_nodes[0].get("id") or "")

    graph_leads = {str(node.get("key") or "") for node in nodes
                   if node.get("kind") == "hypothesis"}
    for lead in leads:
        lead_id = str(lead.get("id") or "")
        if lead_id in graph_leads:
            continue
        node_id = f"th_lead_{lead_id}"
        nodes.append({
            "id": node_id, "kind": "hypothesis", "key": lead_id,
            "label": lead.get("title") or "open lead", "severity": "",
            "confidence": "hypothesis",
            "data": {"status": "open", "technique": lead.get("technique", ""),
                     "expected": lead.get("expected", "")},
        })
        edges.append({
            "id": f"th_edge_{lead_id}", "src": node_id, "dst": anchor_id,
            "kind": "tests", "label": "", "confidence": "hypothesis",
            "evidence": {"hypothesis_id": lead_id},
        })

    graph_findings = {str(node.get("key") or "") for node in nodes
                      if node.get("kind") == "finding"}
    for finding in findings:
        finding_id = str(finding.get("id") or "")
        if finding_id in graph_findings:
            continue
        node_id = f"th_finding_{finding_id}"
        nodes.append({
            "id": node_id, "kind": "finding", "key": finding_id,
            "label": finding.get("title") or "finding",
            "severity": (finding.get("severity_override")
                         or finding.get("severity") or "info"),
            "confidence": "observed",
            "data": {"triage": finding.get("triage_status", "")},
        })
        edges.append({
            "id": f"th_edge_{finding_id}", "src": anchor_id, "dst": node_id,
            "kind": "leads_to", "label": "", "confidence": "observed",
            "evidence": {"finding_id": finding_id,
                         "run_id": finding.get("run_id", "")},
        })

    raw_scores = {
        str(node.get("id") or ""): _score_node(node, open_lead_ids)
        for node in nodes
    }
    # Asset risk inherits the strongest evidenced child risk, with distance
    # decay. This ranks a host because of its graph, not because of its name.
    for _ in range(2):
        for edge in edges:
            src, dst = str(edge.get("src") or ""), str(edge.get("dst") or "")
            if src in raw_scores and dst in raw_scores:
                raw_scores[src] = max(raw_scores[src],
                                      max(0, raw_scores[dst] - 10))
                raw_scores[dst] = max(raw_scores[dst],
                                      max(0, raw_scores[src] - 10))

    projected = []
    for node in nodes:
        node_id = str(node.get("id") or "")
        node_type = _threat_type(node, open_lead_ids)
        if str(node.get("kind") or "") == "hypothesis" and node_type != "open_lead":
            continue
        risk_score = raw_scores[node_id]
        projected.append({
            "id": node.get("id"),
            "type": node_type,
            "kind": node.get("kind"),
            "key": node.get("key"),
            "label": node.get("label") or node.get("key"),
            "severity": node.get("severity") or _risk_severity(risk_score),
            "risk_score": risk_score,
            "confidence": node.get("confidence") or "",
            "status": (node.get("data") or {}).get("status", ""),
            "data": node.get("data") or {},
        })
    projected.sort(key=lambda row: (
        -int(row["risk_score"]), str(row.get("type") or ""),
        str(row.get("label") or "")))
    top = projected[:limit]
    selected = {str(row["id"]) for row in top}
    map_edges = [{
        "id": edge.get("id"),
        "source": edge.get("src"),
        "target": edge.get("dst"),
        "type": edge.get("kind"),
        "label": edge.get("label") or "",
        "risk_score": max(raw_scores.get(str(edge.get("src") or ""), 0),
                          raw_scores.get(str(edge.get("dst") or ""), 0)),
        "confidence": edge.get("confidence") or "",
        "evidence": edge.get("evidence") or {},
    } for edge in edges
        if str(edge.get("src") or "") in selected
        and str(edge.get("dst") or "") in selected]
    counts = _counts(top, "type")
    critical = [row for row in top if int(row["risk_score"]) >= 90][:12]

    return {
        "schema_version": 1,
        "mission_id": mission_id,
        "target": mission.get("target") or "",
        "summary": {
            "nodes": len(top),
            "edges": len(map_edges),
            "paths": len(paths),
            "hosts": counts.get("host", 0),
            "endpoints": counts.get("endpoint", 0),
            "auth_surfaces": counts.get("auth_surface", 0),
            "open_leads": counts.get("open_lead", 0),
            "findings": counts.get("finding", 0),
            "critical_nodes": len(critical),
            "max_risk_score": max(
                (int(row["risk_score"]) for row in top), default=0),
        },
        "critical": critical,
        "nodes": top,
        "edges": map_edges,
        "paths": [{
            "id": path.get("id"), "state": path.get("state"),
            "title": path.get("title") or path.get("id"),
            "entry_node": path.get("entry_node") or "",
            "impact_node": path.get("impact_node") or "",
        } for path in paths[:20]],
        "generated_at": _now(),
    }
