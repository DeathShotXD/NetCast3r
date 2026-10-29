"""Threat intelligence for recent web CVEs and public proof-of-concepts.

The goal is not to run someone else's exploit. It is to answer three questions
quickly and with sources:

1. what is this CVE, how severe is it, and is it being exploited?
2. is there a public PoC or advisory I can read?
3. what is the smallest, safest reproduction that proves impact on an
   authorized target?

Sources are public and read-only: NVD, CISA KEV, GitHub repository/advisory
search, and Sploitus. Every result keeps its source URL. A reproduction plan is
a plan, not an execution: it never runs a command and it flags destructive
payloads for a human decision.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
from pathlib import Path

import httpx

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
GITHUB_API = "https://api.github.com"
SPLOITUS = "https://sploitus.com/"
CACHE_TTL = 6 * 3600
MAX_TEXT = 60_000
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
DESTRUCTIVE = re.compile(
    r"(rm\s+-rf|drop\s+table|truncate\s+table|shutdown|reboot|mkfs|dd\s+if=|"
    r"format\s+[a-z]:|del\s+/f|Invoke-Expression|curl[^\n]*\|\s*(?:ba)?sh)", re.I)


def _now() -> float:
    return time.time()


def _cache_dir(base: str | Path | None = None) -> Path:
    path = Path(base or Path.home() / ".netcast3r") / "threatintel"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _cache_get(key: str, base=None):
    path = _cache_dir(base) / f"{key}.json"
    try:
        payload = json.loads(path.read_text())
        if _now() - float(payload.get("_cached_at", 0)) < CACHE_TTL:
            return payload.get("data")
    except (OSError, ValueError, TypeError):
        return None
    return None


def _cache_put(key: str, data, base=None) -> None:
    path = _cache_dir(base) / f"{key}.json"
    try:
        path.write_text(json.dumps({"_cached_at": _now(), "data": data}, default=str))
    except OSError:
        pass


def _fetch_json(url: str, transport=None, headers=None, timeout=20):
    merged = {"accept": "application/json", "user-agent": "NetCast3r-ThreatIntel/0.1"}
    merged.update(headers or {})
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, trust_env=False,
                          transport=transport) as client:
            response = client.get(url, headers=merged)
            if response.status_code >= 400:
                raise RuntimeError(f"HTTP {response.status_code} from {url}")
            return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(f"source unavailable: {type(exc).__name__}") from exc


def _fetch_text(url: str, transport=None, headers=None, timeout=20) -> str:
    merged = {"accept": "text/html, text/plain, application/json",
              "user-agent": "Mozilla/5.0 (compatible; NetCast3r/0.1)"}
    merged.update(headers or {})
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, trust_env=False,
                          transport=transport) as client:
            response = client.get(url, headers=merged)
            if response.status_code >= 400:
                raise RuntimeError(f"HTTP {response.status_code} from {url}")
            return response.text[:MAX_TEXT]
    except httpx.HTTPError as exc:
        raise RuntimeError(f"source unavailable: {type(exc).__name__}") from exc


def _cve_id(value: str) -> str:
    match = CVE_RE.search(value or "")
    if not match:
        raise ValueError("a CVE id is required, e.g. CVE-2025-12345")
    return match.group(0).upper()


def nvd_cve(cve_id: str, transport=None) -> dict:
    cve_id = _cve_id(cve_id)
    cached = _cache_get(f"nvd-{cve_id}")
    if cached:
        return cached
    data = _fetch_json(f"{NVD_API}?cveId={cve_id}", transport=transport)
    items = data.get("vulnerabilities") or []
    if not items:
        raise RuntimeError(f"NVD has no record for {cve_id}")
    cve = items[0].get("cve") or {}
    descriptions = [item.get("value", "") for item in cve.get("descriptions") or []
                    if item.get("lang") == "en"]
    metrics = cve.get("metrics") or {}
    scores = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key) or []:
            data_block = metric.get("cvssData") or {}
            scores.append({
                "version": key.replace("cvssMetricV", "").replace("V", "."),
                "score": data_block.get("baseScore"),
                "severity": data_block.get("baseSeverity") or metric.get("baseSeverity"),
                "vector": data_block.get("vectorString"),
                "source": metric.get("source"),
            })
    references = [{"url": item.get("url"), "tags": item.get("tags") or []}
                  for item in cve.get("references") or []]
    result = {
        "cve": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": descriptions[0] if descriptions else "",
        "scores": scores,
        "best_score": max((item for item in scores if item.get("score") is not None),
                          key=lambda item: float(item["score"]), default={}),
        "cwe": [desc.get("value") for weakness in cve.get("weaknesses") or []
                for desc in weakness.get("description") or []],
        "references": references,
        "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
    _cache_put(f"nvd-{cve_id}", result)
    return result


def kev_lookup(cve_id: str, transport=None, base=None) -> dict:
    cve_id = _cve_id(cve_id)
    cached = _cache_get("cisa-kev", base=base)
    if cached is None:
        data = _fetch_json(KEV_FEED, transport=transport)
        cached = {"catalogVersion": data.get("catalogVersion"),
                  "dateReleased": data.get("dateReleased"),
                  "vulnerabilities": [
                      {"cve": item.get("cveID"), "vendor": item.get("vendorProject"),
                       "product": item.get("product"),
                       "name": item.get("vulnerabilityName"),
                       "description": item.get("shortDescription"),
                       "action": item.get("requiredAction"),
                       "due": item.get("dueDate"),
                       "ransomware": item.get("knownRansomwareCampaignUse")}
                      for item in data.get("vulnerabilities") or []]}
        _cache_put("cisa-kev", cached, base=base)
    hit = next((item for item in cached.get("vulnerabilities", [])
                if item.get("cve") == cve_id), None)
    return {"cve": cve_id, "known_exploited": bool(hit), "entry": hit,
            "catalog": cached.get("catalogVersion"),
            "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}


def github_pocs(cve_id: str, transport=None, token: str = "", limit: int = 10) -> list[dict]:
    cve_id = _cve_id(cve_id)
    headers = {"accept": "application/vnd.github+json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    query = f"{cve_id} in:name,description,readme"
    data = _fetch_json(f"{GITHUB_API}/search/repositories?q={query}&sort=updated&per_page={limit}",
                       transport=transport, headers=headers)
    items = []
    for repo in data.get("items") or []:
        items.append({
            "repo": repo.get("full_name"),
            "url": repo.get("html_url"),
            "description": repo.get("description") or "",
            "stars": repo.get("stargazers_count"),
            "updated": repo.get("updated_at"),
            "topics": repo.get("topics") or [],
            "default_branch": repo.get("default_branch") or "HEAD",
        })
    return items


def github_advisories(cve_id: str, transport=None, token: str = "") -> list[dict]:
    cve_id = _cve_id(cve_id)
    headers = {"accept": "application/vnd.github+json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    data = _fetch_json(f"{GITHUB_API}/advisories?cve_id={cve_id}",
                       transport=transport, headers=headers)
    return [{"ghsa": item.get("ghsa_id"), "summary": item.get("summary"),
             "severity": item.get("severity"), "cvss": item.get("cvss"),
             "url": item.get("html_url"), "published": item.get("published_at")}
            for item in data or []]


def sploitus(cve_id: str, transport=None, limit: int = 10) -> list[dict]:
    """Best-effort Sploitus search. The site is HTML, so parse links and titles."""
    cve_id = _cve_id(cve_id)
    html = _fetch_text(f"{SPLOITUS}?query={cve_id}", transport=transport)
    results = []
    for match in re.finditer(
            r'<a[^>]+href="(/exploits/[^"]+)"[^>]*>(.*?)</a>', html, re.S | re.I):
        title = re.sub(r"<[^>]+>", " ", match.group(2))
        title = re.sub(r"\s+", " ", title).strip()
        if title:
            results.append({"title": title[:200],
                            "url": "https://sploitus.com" + match.group(1),
                            "source": "sploitus"})
        if len(results) >= limit:
            break
    return results


def search(query: str, transport=None, token: str = "", limit: int = 10) -> dict:
    query = (query or "").strip()
    if not query:
        raise ValueError("query is required")
    result = {"query": query, "cve": None, "nvd": None, "kev": None,
              "github": [], "advisories": [], "sploitus": [], "errors": []}
    match = CVE_RE.search(query)
    if match:
        cve_id = match.group(0).upper()
        result["cve"] = cve_id
        for name, function in (("nvd", lambda: nvd_cve(cve_id, transport=transport)),
                               ("kev", lambda: kev_lookup(cve_id, transport=transport)),
                               ("github", lambda: github_pocs(cve_id, transport=transport,
                                                              token=token, limit=limit)),
                               ("advisories", lambda: github_advisories(
                                   cve_id, transport=transport, token=token)),
                               ("sploitus", lambda: sploitus(cve_id, transport=transport,
                                                             limit=limit))):
            try:
                result[name] = function()
            except RuntimeError as exc:
                result["errors"].append(f"{name}: {exc}")
    else:
        headers = {"accept": "application/vnd.github+json"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        try:
            data = _fetch_json(f"{GITHUB_API}/search/repositories?q="
                               f"{urllib.parse.quote(query)}&per_page={limit}",
                               transport=transport, headers=headers)
            result["github"] = [{"repo": item.get("full_name"), "url": item.get("html_url"),
                                 "description": item.get("description") or "",
                                 "stars": item.get("stargazers_count")}
                                for item in data.get("items") or []]
        except RuntimeError as exc:
            result["errors"].append(f"github: {exc}")
    return result


def _code_blocks(text: str) -> list[str]:
    blocks = re.findall(r"```[a-zA-Z0-9_+-]*\n(.*?)```", text, re.S)
    return [block.strip()[:4000] for block in blocks if block.strip()]


def reproduction_plan(cve_id: str, target: str = "", transport=None,
                      token: str = "", base=None) -> dict:
    """Build a cited, non-executing reproduction plan from public sources."""
    cve_id = _cve_id(cve_id)
    report = search(cve_id, transport=transport, token=token)
    cve = report.get("nvd") or {}
    kev = report.get("kev") or {}
    repos = report.get("github") or []
    readme = ""
    readme_source = ""
    for repo in repos[:3]:
        raw = f"https://raw.githubusercontent.com/{repo['repo']}/{repo['default_branch']}/README.md"
        try:
            readme = _fetch_text(raw, transport=transport)
            readme_source = raw
            if readme:
                break
        except RuntimeError:
            continue
    blocks = _code_blocks(readme)
    combined = "\n".join(blocks)
    destructive = bool(DESTRUCTIVE.search(combined)) or bool(DESTRUCTIVE.search(readme))
    steps = [
        "Confirm the target runs the affected product and version; record the exact banner.",
        "Read the advisory and the PoC end to end; list the preconditions and the expected marker.",
        "Prepare a disposable account or test tenant and a reversible baseline.",
        "Send the minimal request from the PoC with a benign marker (a callback or a unique string).",
        "Stop at the first proof; do not pivot, dump data, or modify state beyond the marker.",
        "Capture the request/response, revert the test state, and record the finding with evidence.",
    ]
    if target:
        steps.insert(0, f"Check that {target} is in the program's scope and is the affected asset.")
    return {
        "cve": cve_id,
        "target": target,
        "description": cve.get("description", ""),
        "severity": (cve.get("best_score") or {}).get("severity", ""),
        "score": (cve.get("best_score") or {}).get("score"),
        "known_exploited": kev.get("known_exploited", False),
        "ransomware": (kev.get("entry") or {}).get("ransomware", "Unknown"),
        "references": cve.get("references", [])[:12],
        "pocs": repos,
        "readme_source": readme_source,
        "code_blocks": blocks[:6],
        "destructive_payload_detected": destructive,
        "steps": steps,
        "safety": ("Do not execute a block wholesale. The plan is a reading aid; run only the "
                   "minimal request you understand, against an authorized target, and stop at "
                   "the first benign proof."),
        "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
