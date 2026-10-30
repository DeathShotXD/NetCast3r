"""OffSec framework map and boot2root planning.

The map records what other frameworks do and what NetCast3r actually covers.
It is deliberately candid: a gap is a gap. The plan turns a target's exposed
services into a phased boot2root route with a proof and a cleanup step.
Nothing here executes a command or contacts a host.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

FRAMEWORKS_PATH = Path(__file__).with_name("data") / "offsec_frameworks.json"
COVERAGE_ORDER = {"full": 0, "partial": 1, "gap": 2}


@lru_cache(maxsize=1)
def frameworks() -> tuple[dict, ...]:
    try:
        raw = json.loads(FRAMEWORKS_PATH.read_text())
    except (OSError, ValueError):
        return ()
    items = []
    for item in raw.get("frameworks", []):
        if not isinstance(item, dict) or not item.get("id"):
            continue
        entry = dict(item)
        entry["capabilities"] = [str(value) for value in
                                 entry.get("capabilities") or []]
        items.append(entry)
    return tuple(items)


def search(query: str = "", category: str = "", coverage: str = "",
           limit: int = 50) -> dict:
    q = (query or "").strip().lower()
    category = (category or "").strip().lower()
    coverage = (coverage or "").strip().lower()
    items = list(frameworks())
    if q:
        items = [item for item in items
                 if q in item["name"].lower() or q in item["category"].lower()
                 or q in " ".join(item["capabilities"]).lower()
                 or q in item["note"].lower()]
    if category:
        items = [item for item in items if item["category"] == category]
    if coverage:
        items = [item for item in items if item["coverage"] == coverage]
    items.sort(key=lambda item: (COVERAGE_ORDER.get(item["coverage"], 9),
                                 item["name"].lower()))
    return {"items": items[:max(1, min(int(limit or 50), 200))],
            "total": len(items),
            "note": ("Coverage is a statement about this codebase, not a claim "
                     "about the other framework's quality.")}


def summary() -> dict:
    counts = {"full": 0, "partial": 0, "gap": 0}
    categories: dict[str, int] = {}
    for item in frameworks():
        counts[item["coverage"]] = counts.get(item["coverage"], 0) + 1
        categories[item["category"]] = categories.get(item["category"], 0) + 1
    return {"total": len(frameworks()), "coverage": counts,
            "categories": dict(sorted(categories.items())),
            "note": "A gap is a roadmap item, not an implemented capability."}


def boot2root_plan(os_name: str = "linux", services: list | None = None,
                   goal: str = "") -> dict:
    """Build a phased host route with explicit proof and cleanup."""
    os_name = (os_name or "linux").strip().lower()
    services = [str(value).strip().lower() for value in (services or [])]
    ad = any(name in services for name in ("ldap", "kerberos", "smb", "winrm",
                                           "ad", "active-directory"))
    web = any(name in services for name in ("http", "https", "web", "tomcat",
                                            "jenkins", "wordpress"))
    phases = [
        {"phase": "scope", "goal": "Confirm host, ports, and rules of engagement",
         "checks": ["host is in the mission scope", "allowed ports and hours",
                    "no destructive actions", "cleanup owner"],
         "evidence": "scope entry and target list", "tools": ["scope_check"]},
        {"phase": "enumerate", "goal": "Identify services and versions with minimal noise",
         "checks": ["explicit port list", "banner and TLS certificate",
                    "HTTP title and headers", "SMB signing and dialect",
                    "LDAP rootDSE if directory service"],
         "evidence": "open ports, banners, versions, certificate",
         "tools": ["host_probe", "whatweb", "openssl"]},
    ]
    if web:
        phases.append({
            "phase": "web-access",
            "goal": "Turn the web surface into one reproducible foothold",
            "checks": ["auth and object authorization", "upload and parser sinks",
                       "template, SQL, and command injection", "known CVE only after version proof"],
            "evidence": "request/response pair and the exact command or file read",
            "tools": ["http_request", "http_upload", "oracle_extract", "browser"],
        })
    if ad:
        phases.append({
            "phase": "directory",
            "goal": "Map the domain and one low-privilege identity",
            "checks": ["LDAP rootDSE and naming contexts", "Kerberos realm",
                       "SMB signing and guest access", "SPN and ACL review with an owned account"],
            "evidence": "domain name, reachable DC, one owned identity",
            "tools": ["host_probe", "ldapsearch", "impacket"],
            "gap": ("No AD graph or Kerberos ticket layer is integrated; use an "
                    "isolated lab and an approved external tool until that changes."),
        })
    phases.extend([
        {"phase": "foothold", "goal": "Obtain one stable, authorized session",
         "checks": ["credential validation only with owned accounts",
                    "no password spraying", "record the exact command and output",
                    "prefer a read-only proof over a shell"],
         "evidence": "session or command output with timestamp",
         "tools": ["ssh", "winrm", "http_request"],
         "gap": ("No C2 or implant lifecycle. A shell is a lab-only step and "
                 "must be documented before use.")},
        {"phase": "privilege-escalation",
         "goal": "Move from the foothold identity to the target privilege",
         "checks": (["sudo -l, SUID/SGID, capabilities, cron, PATH, writable services",
                     "kernel and package versions", "credentials in config and history"]
                    if os_name != "windows" else
                    ["whoami /priv, services, unquoted paths, scheduled tasks",
                     "stored credentials, token privileges, AD group membership"]),
         "evidence": "the misconfiguration and the before/after identity",
         "tools": ["linpeas", "winpeas", "seatbelt"],
         "gap": ("NetCast3r does not execute host enumeration scripts. Keep this "
                 "step manual or run it through an approved sandbox.")},
        {"phase": "loot-and-report",
         "goal": "Prove impact with the minimum data and write the chain",
         "checks": ["one sensitive file or identity proof", "redact secrets",
                    "map each link to evidence", "record the lesson"],
         "evidence": "minimal proof, chain diagram, remediation",
         "tools": ["finding_artifact_add", "report_quality", "research_ingest"]},
        {"phase": "cleanup",
         "goal": "Leave the host as found",
         "checks": ["remove uploaded files", "close sessions", "restore config",
                    "record every change"],
         "evidence": "cleanup note in the finding", "tools": []},
    ])
    return {
        "os": os_name,
        "services": services,
        "goal": goal.strip(),
        "ad": ad,
        "web": web,
        "phases": phases,
        "note": ("A boot2root route is a plan, not authorization. Every active "
                 "step still needs scope and, for host-level actions, explicit "
                 "engagement approval."),
    }
