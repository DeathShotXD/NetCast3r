"""SAML response analysis.

The SAML bugs that pay are trust-shape bugs: a signature that does not cover
the assertion, a second assertion smuggled alongside a signed one, a NameID
with a comment that splits the value, or an XML entity that expands. This
module reads a SAML response and states those weaknesses.

It is regex-based and never expands entities: a DOCTYPE with an ENTITY is
reported, not parsed, so a hostile document cannot make this tool the victim.
"""

from __future__ import annotations

import base64
import re
import time

MAX_INPUT = 2_000_000
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

ID_RE = re.compile(r'\bID="([^"]+)"')
REF_RE = re.compile(r'Reference\s+URI="#([^"]+)"')
NAMEID_RE = re.compile(r"<(?:\w+:)?NameID\b[^>]*>(.*?)</(?:\w+:)?NameID>",
                       re.IGNORECASE | re.DOTALL)
NOT_ON_OR_AFTER_RE = re.compile(r'NotOnOrAfter="([^"]+)"')


def decode(value: str) -> str:
    """Return XML from a raw or base64-encoded SAML message."""
    text = str(value or "").strip()
    if "<" in text:
        return text
    compact = re.sub(r"\s+", "", text)
    if compact and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            padding = "=" * (-len(compact) % 4)
            return base64.b64decode(compact + padding).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return text
    return text


def _finding(items, ident, severity, title, detail, evidence=""):
    items.append({"id": ident, "severity": severity, "title": title,
                  "detail": detail, "evidence": evidence[:300]})


def _expired(value: str) -> bool:
    try:
        cleaned = value.replace("Z", "+00:00")
        from datetime import datetime
        moment = datetime.fromisoformat(cleaned)
        return moment.timestamp() < time.time()
    except ValueError:
        return False


def analyze(value: str) -> dict:
    """Analyze one SAML response or assertion."""
    text = decode(value)[:MAX_INPUT]
    findings: list = []
    if not text or "<" not in text:
        return {"findings": [], "error": "no XML in the input", "shape": {}}

    if re.search(r"<!DOCTYPE", text, re.IGNORECASE) and \
            re.search(r"<!ENTITY", text, re.IGNORECASE):
        _finding(findings, "xxe_entity", "high", "XML entity defined in the document",
                 "An internal or external entity is declared. A strict parser must "
                 "reject it, not expand it.")

    signatures = len(re.findall(r"<(?:\w+:)?Signature\b", text, re.IGNORECASE))
    assertions = re.findall(r"<(?:\w+:)?Assertion\b[^>]*>", text, re.IGNORECASE)
    assertion_ids = []
    for tag in assertions:
        match = ID_RE.search(tag)
        if match:
            assertion_ids.append(match.group(1))
    signed_ids = REF_RE.findall(text)

    if signatures == 0:
        _finding(findings, "unsigned_response", "high", "No XML signature",
                 "The response carries no Signature element; a consumer that "
                 "accepts it trusts an unsigned assertion.")
    if len(assertions) > 1:
        _finding(findings, "multiple_assertions", "high",
                 "More than one assertion",
                 "Multiple assertions are the shape of an XML signature wrapping "
                 "attack: only one is signed.", f"{len(assertions)} assertions")
    if signatures and assertion_ids and signed_ids and \
            not set(assertion_ids) & set(signed_ids):
        _finding(findings, "signature_not_over_assertion", "high",
                 "Signature does not reference an assertion",
                 "The signed element is not the assertion being consumed, so the "
                 "assertion can be swapped.",
                 f"signed={signed_ids[:3]} assertions={assertion_ids[:3]}")

    for match in NAMEID_RE.finditer(text):
        body = match.group(1)
        if "<!--" in body:
            _finding(findings, "comment_injection", "high",
                     "Comment inside a NameID value",
                     "A comment can split the value so two parsers read different "
                     "identities.", body[:160])

    if "AudienceRestriction" not in text:
        _finding(findings, "missing_audience", "medium", "No audience restriction",
                 "Without an audience, the assertion can be replayed to another "
                 "service provider.")
    deadlines = NOT_ON_OR_AFTER_RE.findall(text)
    if not deadlines:
        _finding(findings, "missing_notonorafter", "medium",
                 "No NotOnOrAfter condition",
                 "An assertion without an expiry can be replayed indefinitely.")
    elif all(_expired(value) for value in deadlines):
        _finding(findings, "expired_assertion", "info",
                 "The assertion is already expired",
                 "Replay outside the validity window should be rejected.",
                 deadlines[0])
    if "Destination=" not in text:
        _finding(findings, "missing_destination", "low", "No Destination attribute",
                 "A missing destination is a hint the response is not bound to one "
                 "endpoint.")
    if "NameIDFormat" not in text:
        _finding(findings, "nameid_format_unspecified", "info",
                 "NameID format not stated",
                 "The consumer will assume a default format.")

    findings.sort(key=lambda row: (SEVERITY_ORDER.get(row["severity"], 9), row["id"]))
    return {
        "findings": findings,
        "shape": {"signatures": signatures, "assertions": len(assertions),
                  "signed_references": signed_ids[:5],
                  "has_audience": "AudienceRestriction" in text,
                  "notonorafter": deadlines[:3]},
        "note": ("A finding here is a misconfiguration to corroborate. The "
                 "signature must be validated against the identity provider's "
                 "certificate for proof."),
    }


def summary() -> dict:
    return {
        "checks": ["signature_presence", "multiple_assertions",
                   "signature_reference", "comment_injection", "audience",
                   "expiry", "destination", "xxe_entity"],
        "note": "Regex analysis; entities are reported, never expanded.",
    }
