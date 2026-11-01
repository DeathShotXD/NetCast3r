"""Post-exploitation planning.

Once a mission has surface, services, identities, or credentials, the next
question is what to do with them. This reads the graph and the exploit catalog
and proposes ordered post-exploitation objectives - AD, cloud, and lateral
movement - each with its preconditions and the evidence it still needs.

It plans only. Every objective is a gated module; execution goes through the
same scope, risk, and approval gates as everything else, and the identity and
cloud classes are high risk.
"""

from __future__ import annotations

from . import exploits

# Post-exploitation modules worth surfacing, with the evidence each needs.
_POSTEX = (
    ("id-ldap-anon-bind", ("service",), "anonymous or weak LDAP bind"),
    ("id-kerberoast", ("domain_foothold",), "request an SPN ticket and crack it"),
    ("id-asreproast", ("domain_foothold",), "roast a pre-auth-disabled account"),
    ("id-adcs-template", ("domain_foothold",), "abuse a certificate template"),
    ("cloud-s3-public", ("cloud_provider",), "list a public bucket"),
    ("cloud-imds", ("url_parameter", "cloud_provider"), "read instance metadata"),
    ("cloud-k8s-api", ("cloud_provider",), "reach the cluster API anonymously"),
)

_CLOUD_TECH = {"aws", "gcp", "azure", "cloudflare", "s3", "kubernetes", "k8s",
               "docker", "firebase"}


def plan(index, mission_id: str, limit: int = 10) -> dict:
    """Propose post-exploitation objectives from the observed graph."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    nodes = index.list_graph_nodes(mission_id)
    kinds: dict[str, list] = {}
    for node in nodes:
        kinds.setdefault(str(node.get("kind") or ""), []).append(node)

    tech = {str(node.get("key") or node.get("label") or "").lower()
            for node in kinds.get("technology", [])}
    profile = index.get_target_profile(mission_id) or {}
    tech |= {str(name).lower() for name in (profile.get("tech") or [])}

    evidence = {
        "service": bool(kinds.get("service")),
        "identity": bool(kinds.get("identity")),
        "credential": bool(kinds.get("credential")),
        "domain_foothold": bool(kinds.get("identity") or kinds.get("credential")),
        "url_parameter": bool(kinds.get("parameter")),
        "cloud_provider": bool(tech & _CLOUD_TECH),
        "finding": bool(kinds.get("finding")),
        "endpoint": bool(kinds.get("endpoint")),
    }

    services = [str(node.get("label") or node.get("key") or "")
                for node in kinds.get("service", [])][:10]
    objectives = []
    for module_id, needs, why in _POSTEX:
        module = exploits.get_module(module_id)
        if not module:
            continue
        missing = [token for token in needs if not evidence.get(token)]
        ready = not missing
        objectives.append({"module_id": module_id, "name": module["name"],
                           "impact": module["impact"], "risk": module["risk"],
                           "why": why, "ready": ready, "missing": missing})
    objectives.sort(key=lambda item: (not item["ready"], item["risk"]))

    if services:
        objectives.insert(0, {
            "module_id": "", "name": "Enumerate the exposed services",
            "impact": "high", "risk": "medium",
            "why": "open services are the lateral-movement surface: "
                   + ", ".join(services[:6]),
            "ready": True, "missing": []})

    return {"mission_id": mission_id, "evidence": evidence,
            "services": services,
            "objectives": objectives[:max(1, min(int(limit or 10), 40))],
            "note": ("Post-exploitation is planned, not fired. Every objective is a "
                     "gated module; the identity and cloud classes are high risk "
                     "and need an authorized mission or an approval.")}
