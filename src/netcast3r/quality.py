"""Report quality and payout intelligence.

Bug bounty payouts follow evidence quality more than scanner volume. This
module scores a finding against the things a triager actually looks for and
returns the missing pieces. It does not predict a bounty and it does not
estimate a payout; it only measures the report you have.

Program ranking uses the submission ledger: real rows, real currencies, no
invented ranges.
"""

from __future__ import annotations

import re

SEVERITIES = {"critical", "high", "medium", "low", "info"}
REQUEST_HINTS = re.compile(
    r"(?i)\b(get|post|put|patch|delete|curl|http/|request|response|reproduc|steps?)\b")
CVE_HINT = re.compile(r"\bCVE-\d{4}-\d{4,7}\b|CVSS:3\.1/", re.I)


def score_finding(index, finding_id: str) -> dict:
    """Score one finding's report completeness from stored fields and artifacts."""
    finding = index.get_finding(finding_id)
    if not finding:
        raise ValueError("finding not found")
    artifacts = index.list_finding_artifacts(finding_id)
    title = str(finding.get("title") or "")
    impact = str(finding.get("impact") or "")
    evidence = str(finding.get("evidence") or "")
    notes = str(finding.get("notes") or "")
    blob = " ".join((title, impact, evidence, notes))
    checks = []

    def check(name: str, points: int, ok: bool, hint: str) -> None:
        checks.append({"name": name, "points": points, "ok": bool(ok),
                       "hint": "" if ok else hint})

    check("specific title", 10, len(title) >= 20, "Make the title name the asset and the flaw.")
    check("impact explains the consequence", 20, len(impact) >= 80,
          "Write what an attacker gains, in two or three sentences.")
    check("evidence is concrete", 15, len(evidence) >= 120,
          "Cite the exact request, response, file, and line.")
    check("evidence file attached", 15, len(artifacts) >= 1,
          "Attach the raw log or screenshot with finding_artifact_add.")
    check("second evidence file", 10, len(artifacts) >= 2,
          "Attach a second artifact: a clean-context run or the restored state.")
    check("reproduction is present", 10, bool(REQUEST_HINTS.search(blob)),
          "Add the minimal request and the observed response.")
    check("severity context", 10, bool(CVE_HINT.search(blob)) or
          finding.get("severity") in SEVERITIES,
          "Add the CVSS vector or the CVE/advisory reference.")
    check("confidence recorded", 10, float(finding.get("confidence") or 0) >= 0.7,
          "Raise confidence only after an independent reproduction.")

    total = sum(item["points"] for item in checks if item["ok"])
    missing = [item["hint"] for item in checks if not item["ok"]]
    grade = ("A" if total >= 90 else "B" if total >= 75 else
             "C" if total >= 55 else "D")
    return {
        "finding_id": finding_id,
        "title": title,
        "severity": finding.get("severity"),
        "score": total,
        "grade": grade,
        "checks": checks,
        "missing": missing,
        "artifacts": len(artifacts),
        "note": ("This is report completeness, not validity. A high score does not "
                 "mean the program will accept it."),
    }


def program_stats(index) -> dict:
    """Aggregate the real submission ledger by program and currency."""
    with index._lock:
        rows = index.conn.execute(
            "SELECT program, platform, currency, COUNT(*) AS total, "
            "SUM(CASE WHEN status IN ('accepted', 'paid') THEN 1 ELSE 0 END) AS accepted, "
            "SUM(CASE WHEN status = 'paid' THEN 1 ELSE 0 END) AS paid, "
            "SUM(CASE WHEN status IN ('accepted', 'paid') THEN bounty_cents ELSE 0 END) "
            "AS bounty_cents FROM submissions GROUP BY program, platform, currency "
            "ORDER BY bounty_cents DESC, accepted DESC"
        ).fetchall()
    items = []
    for row in rows:
        total = int(row["total"] or 0)
        accepted = int(row["accepted"] or 0)
        items.append({
            "program": row["program"] or "(unassigned)",
            "platform": row["platform"] or "other",
            "currency": row["currency"] or "USD",
            "submissions": total,
            "accepted": accepted,
            "paid": int(row["paid"] or 0),
            "bounty_cents": int(row["bounty_cents"] or 0),
            "acceptance_rate": round(accepted / total, 3) if total else 0.0,
            "average_bounty_cents": round(int(row["bounty_cents"] or 0) / max(1, accepted)),
        })
    return {
        "items": items,
        "total": len(items),
        "note": ("Derived only from rows in the submission ledger. Currencies are never "
                 "converted or estimated."),
    }


LAB_HINTS = re.compile(
    r"(?i)\b(juice.?shop|localhost|127\.0\.0\.1|portswigger\.net/web-security|"
    r"local-lab|training lab|dvwa|bodgeit)\b")
ATO_HINTS = re.compile(
    r"(?i)\b(account takeover|ato|auth bypass|2fa bypass|oauth|session|"
    r"email rebind|rce|ssrf.{0,40}metadata|admin jwt|privilege escalation)\b")
IMPACT_HINTS = re.compile(
    r"(?i)\b(attacker|victim|without (password|consent)|permanent|lockout|"
    r"any user|administrator|cloud metadata|exfiltrat)\b")


def bounty_eligibility(index, finding_id: str) -> dict:
    """Gate whether a finding is bounty-shaped (impactful, not a lab hygiene hit).

    This does not claim the program will pay. It answers: is this reportable
    against a real program with demonstrated attacker-attainable harm?
    """
    finding = index.get_finding(finding_id)
    if not finding:
        raise ValueError("finding not found")
    quality = score_finding(index, finding_id)
    title = str(finding.get("title") or "")
    impact = str(finding.get("impact") or "")
    evidence = str(finding.get("evidence") or "")
    tags = [str(t).lower() for t in (finding.get("tags") or [])]
    blob = " ".join((title, impact, evidence, " ".join(tags)))
    gates = []

    def gate(name: str, ok: bool, detail: str) -> None:
        gates.append({"name": name, "ok": bool(ok), "detail": detail})

    is_lab = bool(LAB_HINTS.search(blob) or "local-lab" in tags or "lab" in tags)
    gate("not a local lab or training target", not is_lab,
         "Lab findings train the harness; they do not count toward publishable bounty wins.")
    sev = str(finding.get("severity") or "").lower()
    gate("severity is high or critical", sev in {"high", "critical"},
         "Bounty-eligible publish targets need high/critical attacker impact.")
    gate("impact describes attacker-attainable harm",
         len(impact) >= 80 and bool(IMPACT_HINTS.search(impact) or ATO_HINTS.search(blob)),
         "Write concrete attacker gain (ATO, RCE, data access), not hygiene.")
    gate("evidence is reproducible",
         len(evidence) >= 80 or quality.get("artifacts", 0) >= 1,
         "Attach request/response logs or screenshots that a triager can replay.")
    gate("report completeness at least grade C",
         quality.get("grade") in {"A", "B", "C"},
         "Raise report_quality before counting this toward the publish gate.")
    confirmed = any(t in tags for t in
                    ("confirmed", "reproduced", "chained", "accepted", "paid"))
    gate("marked confirmed or reproduced", confirmed,
         "Tag confirmed/reproduced after an independent PoC replay.")

    ready = all(g["ok"] for g in gates)
    critical_ready = ready and sev == "critical" and not is_lab
    return {
        "finding_id": finding_id,
        "title": title,
        "severity": sev,
        "ready": ready,
        "critical_ready": critical_ready,
        "is_lab": is_lab,
        "quality": {"score": quality.get("score"), "grade": quality.get("grade")},
        "gates": gates,
        "missing": [g["detail"] for g in gates if not g["ok"]],
        "note": ("Publish gate: count only ready, non-lab findings. Prefer "
                 "critical_ready for the five-critical ship criterion."),
    }


def critical_portfolio(index, goal: int = 5) -> dict:
    """Track progress toward N bounty-eligible critical findings."""
    findings, _ = index.list_findings(limit=200)
    scored = []
    for finding in findings:
        try:
            item = bounty_eligibility(index, finding["id"])
        except ValueError:
            continue
        scored.append(item)
    ready = [s for s in scored if s.get("ready")]
    critical_ready = [s for s in scored if s.get("critical_ready")]
    high_ready = [s for s in ready if s.get("severity") == "high"]
    return {
        "goal": int(goal),
        "critical_ready": len(critical_ready),
        "high_ready": len(high_ready),
        "ready_total": len(ready),
        "remaining_critical": max(0, int(goal) - len(critical_ready)),
        "items": critical_ready + high_ready,
        "blocked": [s for s in scored if not s.get("ready")
                    and s.get("severity") in {"high", "critical"}][:20],
        "note": ("Ship criterion: critical_ready >= goal. High ATO findings are "
                 "listed as promotion candidates but do not satisfy the critical count."),
    }
