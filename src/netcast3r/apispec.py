"""API-spec ingestion.

Strix can test every endpoint declared by an OpenAPI/Swagger/Postman contract
instead of discovering them by crawling. This reads the same contracts and turns
them into graph endpoints and parameters, so a scoped API assessment starts from
the surface the client already published.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import kb
from .graph import host_of

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+")
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


class ApiSpecError(Exception):
    pass


def _load(path_or_text: str) -> dict:
    text = str(path_or_text or "").strip()
    if not text:
        raise ApiSpecError("no spec given")
    candidate = Path(text)
    raw = ""
    if candidate.is_file():
        raw = candidate.read_text("utf-8", "ignore")
    elif text.lstrip().startswith("{"):
        raw = text
    else:
        raise ApiSpecError("spec must be a local file or an inline JSON document")
    try:
        return json.loads(raw)
    except ValueError:
        try:
            import yaml  # type: ignore
            loaded = yaml.safe_load(raw)  # codeaudit: ignore py-yaml-unsafe -- SafeLoader, local file
        except Exception as exc:  # noqa: BLE001
            raise ApiSpecError(f"spec is not valid JSON or YAML: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ApiSpecError("spec is not an object")
        return loaded


def _openapi_endpoints(spec: dict) -> tuple[list[str], list[str], str]:
    servers = spec.get("servers") or []
    base = ""
    if servers and isinstance(servers[0], dict):
        base = str(servers[0].get("url") or "")
    paths = spec.get("paths") or {}
    endpoints: list[str] = []
    parameters: set[str] = set()
    for route, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, detail in methods.items():
            if method.lower() not in HTTP_METHODS:
                continue
            endpoints.append(f"{method.upper()} {base.rstrip('/')}{route}")
            for param in (detail.get("parameters") or []) if isinstance(detail, dict) else []:
                if isinstance(param, dict) and param.get("name"):
                    parameters.add(str(param["name"]))
            for match in re.findall(r"\{([^}]+)\}", str(route)):
                parameters.add(match)
    return endpoints, sorted(parameters), base


def _postman_endpoints(spec: dict) -> tuple[list[str], list[str], str]:
    endpoints: list[str] = []
    parameters: set[str] = set()

    def walk(items) -> None:
        for item in items or []:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("item"), list):
                walk(item["item"])
                continue
            request = item.get("request") or {}
            url = request.get("url")
            raw = url.get("raw") if isinstance(url, dict) else url
            if not raw:
                continue
            method = str(request.get("method") or "GET").upper()
            endpoints.append(f"{method} {raw}")
            if isinstance(url, dict):
                for entry in url.get("query") or []:
                    if isinstance(entry, dict) and entry.get("key"):
                        parameters.add(str(entry["key"]))

    walk(spec.get("item") or [])
    return endpoints, sorted(parameters), ""


def ingest(index, mission_id: str, spec_path_or_text: str, limit: int = 500) -> dict:
    """Read a contract and record its endpoints and parameters on the graph."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    spec = _load(spec_path_or_text)
    if "paths" in spec:
        endpoints, parameters, base = _openapi_endpoints(spec)
        kind = "openapi"
    elif "item" in spec and "info" in spec:
        endpoints, parameters, base = _postman_endpoints(spec)
        kind = "postman"
    else:
        raise ApiSpecError("unrecognised spec: not OpenAPI and not a Postman collection")

    mission_host = host_of(str(mission.get("target") or ""))
    host = host_of(base) or mission_host
    host_node = index.upsert_graph_node(mission_id, "host", host, label=host)
    written = {"endpoints": 0, "parameters": 0, "kind": kind}

    for label in endpoints[:max(1, int(limit or 500))]:
        node = index.upsert_graph_node(mission_id, "endpoint", label, label=label,
                                       confidence="observed",
                                       data={"spec": kind})
        index.upsert_graph_edge(mission_id, host_node["id"], node["id"], "exposes",
                                evidence={"spec": kind})
        written["endpoints"] += 1
    for name in parameters[:max(1, int(limit or 500))]:
        index.upsert_graph_node(mission_id, "parameter", name, label=name,
                                data={"spec": kind})
        kb.record(index, "global", "parameter", name, title=name,
                  body=f"Declared by an API contract on {host}",
                  source={"mission_id": mission_id, "spec": kind})
        written["parameters"] += 1
    return {"mission_id": mission_id, "host": host, **written,
            "note": ("The contract is the published surface; each endpoint is a "
                     "lead to test, not a finding.")}
