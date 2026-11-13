"""DNS and email posture.

Reads the records that describe how a domain sends mail and who may issue for
it, then states the risk in plain terms: SPF that authorises the whole world,
DMARC that only monitors, a missing CAA, or an apex zone that transfers to
anyone who asks. Nothing here sends mail or changes a record; it only reads.

The zone-transfer check is off by default because it is the one query that
leaves a mark on the authoritatives' logs.
"""

from __future__ import annotations

from . import dnsq

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

DEFAULT_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "mail",
    "dkim", "s1", "s2", "smtp", "mandrill", "sendgrid", "amazonses",
    "cm", "protonmail", "zoho", "everlytickey1", "20230601",
)


def parse_spf(record: str) -> dict:
    """Parse one SPF TXT record into its terms and the policy signals we judge."""
    terms = [term for term in str(record or "").split() if term]
    all_term = next((term for term in terms if term.lower().endswith("all")), "")
    qualifier = all_term[:1] if all_term and all_term[0] in "+-~?" else (
        "+" if all_term else "")
    lookups = 0
    for term in terms[1:]:
        lowered = term.lower().lstrip("+-~?")
        # The mechanism name is the token before any ":", "=", or CIDR "/".
        name = lowered.split(":", 1)[0].split("=", 1)[0].split("/", 1)[0]
        if name in ("include", "a", "mx", "ptr", "exists", "redirect"):
            lookups += 1
    return {
        "record": record,
        "terms": terms,
        "all": all_term,
        "all_qualifier": qualifier,
        "allow_all": qualifier in ("+", "") and bool(all_term),
        "hard_fail": qualifier == "-",
        "soft_fail": qualifier == "~",
        "lookups": lookups,
        "lookup_limit_exceeded": lookups > 10,
        "includes": [term.split(":", 1)[1] for term in terms
                     if term.lower().startswith("include:")],
    }


def parse_dmarc(record: str) -> dict:
    """Parse a DMARC record into its tags."""
    tags: dict = {}
    for part in str(record or "").split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    policy = (tags.get("p") or "").lower()
    return {
        "record": record,
        "tags": tags,
        "policy": policy,
        "subdomain_policy": (tags.get("sp") or "").lower(),
        "pct": tags.get("pct", ""),
        "rua": tags.get("rua", ""),
        "enforcing": policy in ("quarantine", "reject"),
        "monitor_only": policy == "none",
    }


def _finding(items: list, ident: str, severity: str, title: str,
             detail: str, evidence: str = "") -> None:
    items.append({"id": ident, "severity": severity, "title": title,
                  "detail": detail, "evidence": evidence})


def posture(domain: str, nameserver: str | None = None, timeout: float = 3.0,
            zone_transfer: bool = False, dkim_selectors=None,
            query=None, axfr_fn=None) -> dict:
    """Read the DNS posture for one apex domain.

    ``query`` and ``axfr_fn`` are injectable so tests never touch the network.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    q = query or (lambda name, rtype: dnsq.query(name, rtype,
                                                 nameserver=nameserver,
                                                 timeout=timeout))
    axfr_fn = axfr_fn or dnsq.axfr

    def read(name: str, rtype: str):
        try:
            message = q(name, rtype)
        except dnsq.DnsError as exc:
            return [], f"dns error: {exc}"
        return message.records(rtype), ("" if message.rcode == 0 else message.rcode_name)

    findings: list = []
    ns_records, ns_error = read(domain, "NS")
    mx_records, mx_error = read(domain, "MX")
    soa_records, soa_error = read(domain, "SOA")
    caa_records, caa_error = read(domain, "CAA")
    txt_records, _ = read(domain, "TXT")

    spf_records = [row.fields.get("text", row.data) for row in txt_records
                   if str(row.fields.get("text", row.data)).lower().startswith("v=spf1")]
    spf = parse_spf(spf_records[0]) if spf_records else {}
    if not spf_records:
        _finding(findings, "spf_missing", "medium", "No SPF record",
                 "The domain publishes no v=spf1 TXT record, so receivers have "
                 "no authorised sender list to check.")
    elif len(spf_records) > 1:
        _finding(findings, "spf_multiple", "medium", "Multiple SPF records",
                 "More than one v=spf1 record causes a permanent SPF error for "
                 "compliant receivers.",
                 " | ".join(spf_records[:3]))
    else:
        if spf.get("allow_all"):
            _finding(findings, "spf_allow_all", "high", "SPF allows every sender",
                     "The +all mechanism authorises any host to send as this "
                     "domain.", spf.get("all", ""))
        elif not spf.get("hard_fail") and not spf.get("soft_fail"):
            _finding(findings, "spf_no_explicit_all", "low",
                     "SPF has no all mechanism",
                     "Without a -all or ~all term, unauthorised senders are "
                     "treated as neutral rather than failed.")
        if spf.get("lookup_limit_exceeded"):
            _finding(findings, "spf_lookup_limit", "medium",
                     "SPF exceeds the 10-lookup limit",
                     "Receivers abort evaluation after 10 DNS lookups, which "
                     "makes the policy a permanent error.",
                     f"lookups={spf.get('lookups')}")

    dmarc_records, dmarc_error = read(f"_dmarc.{domain}", "TXT")
    dmarc_texts = [row.fields.get("text", row.data) for row in dmarc_records
                   if "v=dmarc1" in str(row.fields.get("text", row.data)).lower()]
    dmarc = parse_dmarc(dmarc_texts[0]) if dmarc_texts else {}
    if not dmarc_texts:
        _finding(findings, "dmarc_missing", "medium", "No DMARC record",
                 "The domain publishes no _dmarc policy, so SPF and DKIM "
                 "failures are not acted on at scale.")
    else:
        if dmarc.get("monitor_only"):
            _finding(findings, "dmarc_none", "low", "DMARC only monitors",
                     "p=none records failures but never quarantines or rejects, "
                     "so spoofed mail is still delivered.", "p=none")
        if not dmarc.get("rua"):
            _finding(findings, "dmarc_no_rua", "info", "DMARC has no aggregate report address",
                     "Without rua= the domain receives no visibility into "
                     "authentication failures.")

    caa = [{"flags": row.fields.get("flags"), "tag": row.fields.get("tag"),
            "value": row.fields.get("value")} for row in caa_records]
    if not caa:
        _finding(findings, "caa_missing", "low", "No CAA record",
                 "Any certificate authority may issue for this domain; a CAA "
                 "record restricts issuance to named CAs.")

    selectors = tuple(dkim_selectors or DEFAULT_DKIM_SELECTORS)
    dkim = []
    for selector in selectors[:32]:
        records, _ = read(f"{selector}._domainkey.{domain}", "TXT")
        texts = [row.fields.get("text", row.data) for row in records
                 if "v=dkim1" in str(row.fields.get("text", row.data)).lower()
                 or "p=" in str(row.fields.get("text", row.data)).lower()]
        if texts:
            dkim.append({"selector": selector, "present": True, "record": texts[0][:500]})

    mta_sts_records, _ = read("_mta-sts." + domain, "TXT")
    bimi_records, _ = read(f"default._bimi.{domain}", "TXT")

    zone = {"attempted": bool(zone_transfer), "nameservers": [], "open": False}
    ns_hosts = [row.data.rstrip(".") for row in ns_records]
    if zone_transfer and ns_hosts:
        for host in ns_hosts[:4]:
            try:
                result = axfr_fn(domain, host, timeout=timeout)
            except Exception as exc:  # network failures are data, not crashes
                result = {"nameserver": host, "open": False, "records": [],
                          "error": str(exc)[:160]}
            entry = {"nameserver": host, "open": bool(result.get("open")),
                     "count": int(result.get("count") or len(result.get("records") or [])),
                     "rcode": result.get("rcode"), "error": result.get("error", "")}
            zone["nameservers"].append(entry)
            if entry["open"]:
                zone["open"] = True
        if zone["open"]:
            _finding(findings, "zone_transfer_open", "high",
                     "AXFR zone transfer is open",
                     "A nameserver answered a full zone transfer, exposing every "
                     "record for the domain to anyone who asks.",
                     ", ".join(row["nameserver"] for row in zone["nameservers"]
                               if row["open"]))

    findings.sort(key=lambda row: (SEVERITY_ORDER.get(row["severity"], 9), row["id"]))
    return {
        "domain": domain,
        "nameservers": ns_hosts,
        "mail": {
            "mx": [{"preference": row.fields.get("preference"),
                    "exchange": row.fields.get("exchange")} for row in mx_records],
            "spf": spf,
            "spf_records": spf_records,
            "dmarc": dmarc,
            "dmarc_records": dmarc_texts,
            "dkim": dkim,
            "mta_sts": [row.fields.get("text", row.data) for row in mta_sts_records],
            "bimi": [row.fields.get("text", row.data) for row in bimi_records],
        },
        "caa": caa,
        "soa": ({"mname": soa_records[0].fields.get("mname"),
                 "rname": soa_records[0].fields.get("rname"),
                 "serial": soa_records[0].fields.get("serial")}
                if soa_records else {}),
        "zone_transfer": zone,
        "errors": {key: value for key, value in {
            "ns": ns_error, "mx": mx_error, "soa": soa_error, "caa": caa_error,
            "dmarc": dmarc_error}.items() if value},
        "findings": findings,
        "note": ("DNS posture is read-only. A finding here is a misconfiguration "
                 "to corroborate, not a proven exploit."),
    }


def summary() -> dict:
    return {
        "checks": ["spf", "dmarc", "dkim", "caa", "mx", "ns", "soa",
                   "mta_sts", "bimi", "zone_transfer"],
        "zone_transfer_default": False,
        "note": "AXFR is opt-in because it is visible to the authoritatives.",
    }
