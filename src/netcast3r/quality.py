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
