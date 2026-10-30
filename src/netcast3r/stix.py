"""STIX 2.1 export and TAXII 2.1 client.

Findings are local records. A client SOC often wants them as STIX objects, and
threat-intel teams want a TAXII collection instead of a JSON file. This module
keeps the mapping small and honest: a finding becomes a vulnerability object and
a report; no indicator is invented from a scanner line.

Nothing here pushes to a remote TAXII server. Polling is read-only; pushing is a
separate, explicit action for a later release.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

import httpx

NAMESPACE = uuid.UUID("4f1c2f6e-6d1f-5f6a-9f4e-6e7c6a1b2c3d")
TAXII_ACCEPT = "application/taxii+json;version=2.1"


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, seed)}"


def _time(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if value.endswith("Z"):
        return value
    return value + "Z"


def _cve(text: str) -> str:
    import re
    match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", text or "", re.I)
    return match.group(0).upper() if match else ""


def finding_objects(finding: dict, identity_id: str) -> list[dict]:
    created = _time(finding.get("created_at", ""))
    description = str(finding.get("impact") or "").strip()
    evidence = str(finding.get("evidence") or "").strip()
    if evidence:
        description = (description + "\n\nEvidence: " + evidence).strip()
    vulnerability = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": _id("vulnerability", f"finding:{finding.get('id')}"),
        "created": created,
        "modified": created,
        "name": str(finding.get("title") or "Untitled finding")[:200],
        "description": description[:4000],
        "confidence": int(float(finding.get("confidence") or 0) * 100),
        "labels": [str(tag) for tag in (finding.get("tags") or [])][:20],
        "created_by_ref": identity_id,
        "x_netcast3r_finding_id": finding.get("id"),
        "x_netcast3r_severity": finding.get("severity"),
    }
    cve = _cve(" ".join(str(finding.get(key) or "") for key in
                        ("title", "impact", "evidence", "notes")))
    if cve:
        vulnerability["external_references"] = [{
            "source_name": "cve", "external_id": cve,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        }]
    return [vulnerability]


def export_bundle(index, mission_id: str = "", severity: str = "",
                  limit: int = 100) -> dict:
    findings, _ = index.list_findings(run_id="", severity=severity, limit=limit)
    if mission_id:
        mission = index.get_mission(mission_id)
        if not mission:
            raise ValueError("mission not found")
        linked = {run.get("id") for run in mission.get("runs") or []}
        findings = [item for item in findings if item.get("run_id") in linked]
    identity_id = _id("identity", "netcast3r")
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    identity = {
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": created, "modified": created, "name": "NetCast3r",
        "identity_class": "system",
        "description": "Authorized security testing workspace",
    }
    vulnerabilities: list[dict] = []
    for finding in findings:
        vulnerabilities.extend(finding_objects(finding, identity_id))
    report = {
        "type": "report", "spec_version": "2.1",
        "id": _id("report", f"export:{mission_id}:{severity}:{created}"),
        "created": created, "modified": created, "published": created,
        "name": "NetCast3r finding export",
        "description": (f"{len(findings)} finding(s)"
                        + (f" from mission {mission_id}" if mission_id else "")),
        "created_by_ref": identity_id,
        "object_refs": [item["id"] for item in vulnerabilities],
        "labels": ["netcast3r", "authorized-testing"],
    }
    return {
        "type": "bundle", "id": _id("bundle", f"export:{created}:{mission_id}"),
        "spec_version": "2.1",
        "objects": [identity, report, *vulnerabilities],
        "x_netcast3r_count": len(findings),
    }


def load_taxii_config(base: str | Path | None = None) -> dict:
    path = Path(base or Path.home() / ".netcast3r") / "integrations.json"
    try:
        config = json.loads(path.read_text() or "{}")
    except (OSError, ValueError):
        return {"configured": False, "url": "", "token": "", "user": "",
                "password": ""}
    taxii = config.get("taxii") if isinstance(config.get("taxii"), dict) else {}
    return {
        "configured": bool(str(taxii.get("url") or "").strip()),
        "url": str(taxii.get("url") or "").strip().rstrip("/"),
        "token": str(taxii.get("token") or ""),
        "user": str(taxii.get("user") or ""),
        "password": str(taxii.get("password") or ""),
    }


class TaxiiClient:
    def __init__(self, base_url: str, token: str = "", user: str = "",
                 password: str = "", transport=None, timeout: float = 20.0):
        if not base_url:
            raise ValueError("TAXII base URL is required")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.user = user
        self.password = password
        self.transport = transport
        self.timeout = timeout

    def _headers(self) -> dict:
        headers = {"accept": TAXII_ACCEPT, "user-agent": "NetCast3r-TAXII/0.1"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        return headers

    def _get(self, url: str, params: dict | None = None) -> dict:
        auth = (self.user, self.password) if self.user else None
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True,
                              trust_env=False, transport=self.transport,
                              auth=auth) as client:
                response = client.get(url, headers=self._headers(), params=params or {})
                if response.status_code >= 400:
                    raise RuntimeError(f"TAXII returned HTTP {response.status_code}")
                return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"TAXII source unavailable: {type(exc).__name__}") from exc

    def discovery(self) -> dict:
        data = self._get(self.base_url + "/")
        return {"title": data.get("title", ""), "description": data.get("description", ""),
                "api_roots": data.get("api_roots") or [],
                "default": data.get("default", "")}

    def collections(self, api_root: str) -> list[dict]:
        data = self._get(api_root.rstrip("/") + "/collections/")
        return [{"id": item.get("id"), "title": item.get("title", ""),
                 "description": item.get("description", ""),
                 "can_read": item.get("can_read"), "can_write": item.get("can_write")}
                for item in data.get("collections") or []]

    def objects(self, api_root: str, collection_id: str, added_after: str = "",
                limit: int = 100) -> dict:
        params = {"limit": max(1, min(int(limit), 1000))}
        if added_after:
            params["added_after"] = added_after
        return self._get(api_root.rstrip("/") + f"/collections/{collection_id}/objects/",
                         params=params)
