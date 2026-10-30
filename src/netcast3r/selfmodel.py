"""A deterministic self-model and capability-gap analysis.

NetCast3r must know what it can actually do, not what a prompt claims. This
module reads only stored records: training progress, practice lessons, active
skills, expertise counters, findings, missions, and submissions. It produces a
capability snapshot and a ranked gap list.

An upgrade is never applied automatically. A proposal is written to the
database with its evidence, and a human decides whether to implement it. That
keeps "self-upgrading" honest: the framework proposes, the operator disposes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import training

DIMENSIONS = {
    "recon": {
        "label": "Recon and attack surface",
        "categories": ["Information disclosure"],
        "tags": {"recon", "osint", "surface", "fingerprint"},
        "skill": "recon-attack-surface",
    },
    "web": {
        "label": "Web application bugs",
        "categories": ["Cross-site scripting", "Cross-site request forgery (CSRF)",
                       "Clickjacking", "Cross-origin resource sharing (CORS)",
                       "Path traversal", "File upload vulnerabilities"],
        "tags": {"xss", "csrf", "upload", "lfi", "cors"},
        "skill": "xss-context-engine",
    },
    "injection": {
        "label": "Injection and parser bugs",
        "categories": ["SQL injection", "NoSQL injection", "OS command injection",
                       "Server-side template injection",
                       "XML external entity (XXE) injection",
                       "Insecure deserialization"],
        "tags": {"sqli", "rce", "xxe", "ssti", "deserialization", "command-injection"},
        "skill": "sqli-advanced",
    },
    "api": {
        "label": "API and GraphQL",
        "categories": ["API testing", "GraphQL API vulnerabilities", "WebSockets"],
        "tags": {"api", "graphql", "rest", "websocket"},
        "skill": "graphql-deep",
    },
    "auth": {
        "label": "Authentication and authorisation",
        "categories": ["Authentication", "Access control vulnerabilities",
                       "OAuth authentication", "JWT"],
        "tags": {"auth", "oauth", "jwt", "idor", "authz", "saml"},
        "skill": "auth-token-attack",
    },
    "advanced": {
        "label": "Advanced server and logic",
        "categories": ["HTTP request smuggling", "Web cache poisoning",
                       "Web cache deception", "HTTP Host header attacks",
                       "Race conditions", "Business logic vulnerabilities",
                       "Prototype pollution"],
        "tags": {"smuggling", "cache", "race", "logic", "host-header",
                 "prototype-pollution"},
        "skill": "cache-poison-smuggle",
    },
    "cloud": {
        "label": "Cloud and identity",
        "categories": [],
        "tags": {"cloud", "aws", "azure", "gcp", "iam", "ssrf"},
        "skill": "cloud-imds",
    },
    "mobile": {
        "label": "Mobile applications",
        "categories": [],
        "tags": {"mobile", "android", "apk", "frida", "ios"},
        "skill": "mobile-apk-reversing",
    },
    "reversing": {
        "label": "Binary and firmware reversing",
        "categories": [],
        "tags": {"reverse", "binary", "firmware", "ghidra"},
        "skill": "binary-reversing",
    },
    "ai": {
        "label": "LLM and agentic features",
        "categories": ["Web LLM attacks"],
        "tags": {"llm", "ai", "prompt-injection", "agent"},
        "skill": "ai-llm-hunting",
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _matches(values, wanted: set) -> bool:
    for value in values or []:
        text = str(value).strip().lower()
        if text in wanted:
            return True
        if any(token in text for token in wanted):
            return True
    return False


def _level(score: int) -> str:
    if score >= 75:
        return "advanced"
    if score >= 50:
        return "competent"
    if score >= 25:
        return "developing"
    return "nascent"


def snapshot(index) -> dict:
    """Read stored records and return a reproducible capability snapshot."""
    labs = training.catalog()
    progress = {row["lab_slug"]: row for row in index.list_training(limit=1000)}
    skills, _ = index.list_skills(limit=200)
    active_skills = [skill for skill in skills if skill.get("status", "active") == "active"]
    expertise = index.list_expertise(limit=200)
    findings, finding_total = index.list_findings(limit=500)
    missions, mission_total = index.list_missions(limit=200)
    submissions, submission_total = index.list_submissions(limit=200)
    hypotheses, hypothesis_total = index.list_hypotheses(limit=200)

    dimensions = []
    for key, spec in DIMENSIONS.items():
        in_scope = [lab for lab in labs if lab.get("category") in spec["categories"]]
        solved = [lab for lab in in_scope
                  if (progress.get(lab["slug"]) or {}).get("status") == "solved"]
        skill_hits = [skill for skill in active_skills
                      if _matches(skill.get("tags"), spec["tags"])
                      or _matches([skill.get("name")], spec["tags"])]
        expertise_hits = [row for row in expertise
                          if _matches([row.get("tech")], spec["tags"])]
        finding_hits = [item for item in findings
                        if _matches(item.get("tags"), spec["tags"])]
        exposures = sum(int(row.get("exposures") or 0) for row in expertise_hits)
        coverage = len(solved) / len(in_scope) if in_scope else 0.0
        score = (round(coverage * 40)
                 + min(20, len(skill_hits) * 5)
                 + min(20, exposures * 2)
                 + min(20, len(finding_hits) * 5))
        dimensions.append({
            "dimension": key,
            "label": spec["label"],
            "score": min(100, score),
            "level": _level(min(100, score)),
            "training_total": len(in_scope),
            "training_solved": len(solved),
            "coverage": round(coverage, 4),
            "skills": [skill["name"] for skill in skill_hits],
            "expertise": [row["tech"] for row in expertise_hits],
            "exposures": exposures,
            "findings": len(finding_hits),
            "next_lab": next((lab["slug"] for lab in in_scope
                              if (progress.get(lab["slug"]) or {}).get("status")
                              != "solved"), ""),
        })
    dimensions.sort(key=lambda item: (item["score"], item["dimension"]))
    overall = round(sum(item["score"] for item in dimensions) / len(dimensions)) if dimensions else 0
    return {
        "generated_at": _now(),
        "overall": overall,
        "level": _level(overall),
        "counts": {
            "training_total": len(labs),
            "training_solved": sum(1 for row in progress.values()
                                   if row.get("status") == "solved"),
            "skills": len(active_skills),
            "expertise": len(expertise),
            "findings": finding_total,
            "missions": mission_total,
            "submissions": submission_total,
            "hypotheses": hypothesis_total,
        },
        "dimensions": dimensions,
        "note": ("Scores are derived only from stored training, skills, expertise, "
                 "and findings. They measure recorded practice, not unproven ability."),
    }


def gaps(index, limit: int = 6) -> dict:
    """Rank missing capability from the snapshot, with one concrete next step each."""
    state = snapshot(index)
    items = []
    for dim in state["dimensions"]:
        if dim["score"] >= 50:
            continue
        if dim["next_lab"]:
            items.append({
                "dimension": dim["dimension"],
                "label": dim["label"],
                "score": dim["score"],
                "gap": "training coverage",
                "action": f"Solve the next lab: {dim['next_lab']}",
                "tool": "training_plan",
                "args": {"source": "", "category": ""},
            })
        elif dim["training_total"] == 0:
            items.append({
                "dimension": dim["dimension"],
                "label": dim["label"],
                "score": dim["score"],
                "gap": "no bundled exercise",
                "action": f"Load and apply the {DIMENSIONS[dim['dimension']]['skill']} skill pack",
                "tool": "skills_get",
                "args": {"name": DIMENSIONS[dim["dimension"]]["skill"]},
            })
        if not dim["skills"]:
            items.append({
                "dimension": dim["dimension"],
                "label": dim["label"],
                "score": dim["score"],
                "gap": "no active skill",
                "action": f"Install or activate the {DIMENSIONS[dim['dimension']]['skill']} skill",
                "tool": "skills_get",
                "args": {"name": DIMENSIONS[dim["dimension"]]["skill"]},
            })
    if state["counts"]["findings"] and not state["counts"]["submissions"]:
        items.append({
            "dimension": "reporting",
            "label": "Submission pipeline",
            "score": 0,
            "gap": "validated findings are not submitted",
            "action": "Triage one validated finding and prepare a submission for approval",
            "tool": "findings_list",
            "args": {"status": "validated"},
        })
    items.sort(key=lambda item: (item["score"], item["dimension"], item["gap"]))
    return {
        "generated_at": state["generated_at"],
        "overall": state["overall"],
        "items": items[:max(1, min(int(limit or 6), 30))],
        "note": ("Gaps are deterministic. An upgrade proposal still needs a human "
                 "decision; nothing is applied automatically."),
    }


def propose(index, title: str, rationale: str, evidence: str, area: str = "",
            priority: str = "medium") -> dict:
    """Store a human-gated improvement proposal. Never applies it."""
    title = (title or "").strip()
    rationale = (rationale or "").strip()
    evidence = (evidence or "").strip()
    if len(title) < 8:
        raise ValueError("title must be at least 8 characters")
    if len(rationale) < 20:
        raise ValueError("rationale must be at least 20 characters")
    if len(evidence) < 8:
        raise ValueError("evidence is required (a record, path, or observed gap)")
    area = (area or "general").strip().lower()
    if area not in {*DIMENSIONS, "reporting", "general", "reliability"}:
        raise ValueError("unknown improvement area")
    priority = (priority or "medium").strip().lower()
    if priority not in {"low", "medium", "high", "critical"}:
        raise ValueError("priority must be low, medium, high, or critical")
    return index.add_upgrade_proposal(title=title, rationale=rationale,
                                      evidence=evidence, area=area,
                                      priority=priority)
