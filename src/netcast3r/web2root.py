"""Web2root: from one public seed to an evidence-backed attack surface.

Boot2root starts with a box. Web2root starts with a public-facing host or URL.
This module is the deterministic front half of that path:

1. resolve the apex and stay inside mission scope;
2. expand names via certificate transparency, passive DNS, and a bounded brute;
3. resolve and HTTP-probe the live surface;
4. fingerprint tech / WAF / TLS from real responses;
5. write hosts, IPs, and services into the evidence graph;
6. refresh the target profile and return a ranked next-action pack.

Nothing here invents an asset. Every host either resolved, answered HTTP, or
came from a public CT/OTX record that still sits in scope. Exploitation is
out of scope for this module - it maps, then hands off to the director.
"""

from __future__ import annotations

import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .config import load_config
from .http import Session
from .scope import ScopeManager
from .subdomains import SubdomainFinder
from . import target as target_module


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_of(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    try:
        return (urlsplit(text if "://" in text else f"https://{text}").hostname
                or "").lower().rstrip(".")
    except ValueError:
        return ""


def _apex(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    if not host:
        return host
    # Literal IPs are their own apex; never slice them into "0.1".
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if host.count(".") < 1:
        return host
    # Keep multi-part public suffixes naive: operator scope is the authority.
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _mission_scope(mission: dict) -> ScopeManager:
    entries = list(mission.get("scope") or [])
    target = str(mission.get("target") or "").strip()
    host = _host_of(target)
    if host and host not in entries and f"*.{host}" not in entries:
        entries.append(host)
        apex = _apex(host)
        if apex and apex != host:
            entries.append(apex)
            entries.append(f"*.{apex}")
    return ScopeManager(in_scope=entries)


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    ips: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip and ip not in ips:
            ips.append(ip)
    return ips


def _tls_summary(host: str, timeout: float = 6.0) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert() or {}
        sans = []
        for kind, value in cert.get("subjectAltName") or []:
            if kind == "DNS" and value:
                sans.append(str(value).lower())
        subject = {}
        for relative in cert.get("subject") or ():
            for key, value in relative:
                subject[str(key)] = str(value)
        issuer_bits = []
        for relative in cert.get("issuer") or ():
            for key, value in relative:
                issuer_bits.append(f"{key}={value}")
        return {
            "subject": subject.get("commonName") or "",
            "issuer": " / ".join(issuer_bits[:4]),
            "not_after": cert.get("notAfter") or "",
            "sans": sans[:40],
        }
    except Exception:  # noqa: BLE001 - TLS is enrichment
        return {}


def _http_probe(session: Session, host: str) -> dict | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        response = session.get(url)
        if response is None:
            continue
        headers = {str(k).lower(): str(v) for k, v in (response.headers or {}).items()}
        title = ""
        body = response.text or ""
        lower = body.lower()
        start = lower.find("<title")
        if start >= 0:
            start = lower.find(">", start)
            end = lower.find("</title>", start)
            if start >= 0 and end > start:
                title = body[start + 1:end].strip()[:160]
        return {
            "url": response.url or url,
            "status": response.status_code,
            "headers": headers,
            "title": title,
            "server": headers.get("server", ""),
            "powered_by": headers.get("x-powered-by", ""),
            "bytes": len(body),
        }
    return None


def _rank_hosts(hosts: list[str], apex: str) -> list[str]:
    priority = ("www", "api", "app", "admin", "portal", "auth", "sso", "login",
                "vpn", "dev", "staging", "stage", "cdn", "static", "docs")
    def score(host: str) -> tuple:
        label = host[:-len(apex) - 1] if host.endswith("." + apex) else host
        head = label.split(".")[0] if label else host
        try:
            prio = priority.index(head)
        except ValueError:
            prio = 50
        return (0 if host == apex or host == f"www.{apex}" else 1, prio, len(host), host)
    return sorted(set(hosts), key=score)


def map_surface(index, mission_id: str, *, config=None, depth: str = "standard",
                probe_limit: int = 40, session: Session | None = None) -> dict:
    """Map the authorised external attack surface for one mission."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    target = str(mission.get("target") or "").strip()
    host = _host_of(target)
    if not host:
        raise ValueError("mission has no usable target")
    apex = _apex(host)
    config = config or load_config()
    scope = _mission_scope(mission)
    depth = str(depth or "standard").lower()
    probe_limit = max(5, min(int(probe_limit or 40), 120))
    own_session = session is None
    if session is None:
        session = Session(config)
    started = _utc()
    errors: list[str] = []

    seeds = [host]
    if apex and apex != host and scope.is_in_scope("https://" + apex):
        seeds.append(apex)

    finder = SubdomainFinder(scope, config, session)
    discovered: list[str] = []
    try:
        discovered = finder.find(seeds)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"subdomains: {type(exc).__name__}: {exc}")

    hosts = _rank_hosts([*seeds, *discovered], apex)
    # Always keep the seed first even if ranking moved it.
    hosts = [host] + [h for h in hosts if h != host]

    live: list[dict] = []
    unresolved: list[str] = []
    tls_hits: list[dict] = []
    workers = 8 if depth != "deep" else 12
    to_probe = hosts[:probe_limit]

    def work(name: str) -> dict:
        ips = _resolve(name)
        row = {"host": name, "ips": ips, "http": None, "tls": {}}
        if not ips:
            return row
        if depth != "passive":
            row["http"] = _http_probe(session, name)
            if name.endswith(apex) or name == apex:
                row["tls"] = _tls_summary(name)
        return row

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(work, name): name for name in to_probe}
        for future in as_completed(futures):
            try:
                row = future.result()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"probe {futures[future]}: {type(exc).__name__}")
                continue
            if not row.get("ips"):
                unresolved.append(row["host"])
                continue
            live.append(row)
            if row.get("tls"):
                tls_hits.append({"host": row["host"], **row["tls"]})

    # Persist into the evidence graph. Edges use node ids, not labels.
    for row in live:
        name = row["host"]
        host_node = index.upsert_graph_node(
            mission_id, "host", name, label=name, confidence="observed",
            data={"ips": row.get("ips") or [], "source": "web2root"})
        for ip in row.get("ips") or []:
            ip_node = index.upsert_graph_node(
                mission_id, "ip", ip, label=ip, confidence="observed",
                data={"host": name, "source": "web2root"})
            try:
                index.upsert_graph_edge(
                    mission_id, host_node["id"], ip_node["id"], "resolves",
                    confidence="observed",
                    evidence={"source": "web2root"})
            except Exception:  # noqa: BLE001
                pass
        http = row.get("http") or {}
        if http:
            index.upsert_graph_node(
                mission_id, "endpoint", http.get("url") or f"https://{name}/",
                label=http.get("title") or name, confidence="observed",
                data={"status": http.get("status"), "server": http.get("server"),
                      "source": "web2root"})
            tech = http.get("powered_by") or http.get("server")
            if tech:
                tech_node = index.upsert_graph_node(
                    mission_id, "technology", str(tech).lower()[:80],
                    label=str(tech), confidence="observed",
                    data={"host": name, "source": "web2root"})
                try:
                    index.upsert_graph_edge(
                        mission_id, host_node["id"], tech_node["id"], "runs",
                        evidence={"source": "web2root"})
                except Exception:  # noqa: BLE001
                    pass

    # Feed the target profile from real probe observations (headers/TLS/DNS).
    for row in live:
        http = row.get("http")
        if not http:
            continue
        try:
            index.add_tool_call(
                tool="web2root_probe", risk="low", status="ok",
                actor="agent:web2root", mission_id=mission_id,
                args={"target": http.get("url"), "host": row["host"]},
                result={
                    "headers": http.get("headers") or {},
                    "status": http.get("status"),
                    "tls": row.get("tls") or {},
                    "dns": {"ips": row.get("ips") or []},
                    "title": http.get("title") or "",
                    "url": http.get("url") or "",
                })
        except Exception:  # noqa: BLE001
            pass

    profile = {}
    try:
        profile = target_module.build_profile(index, mission_id)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"profile: {type(exc).__name__}: {exc}")

    interesting = []
    for row in live:
        http = row.get("http") or {}
        label = row["host"]
        reasons = []
        head = label.split(".")[0]
        if head in {"admin", "portal", "vpn", "sso", "auth", "login", "jenkins",
                    "grafana", "kibana", "staging", "stage", "dev", "api"}:
            reasons.append(f"sensitive-name:{head}")
        if http.get("status") in {200, 301, 302, 401, 403}:
            reasons.append(f"http-{http.get('status')}")
        if http.get("title"):
            reasons.append("titled")
        if reasons:
            interesting.append({"host": label, "url": http.get("url"),
                                "status": http.get("status"),
                                "title": http.get("title"),
                                "reasons": reasons})

    next_actions = []
    if interesting:
        top = interesting[0]
        next_actions.append({
            "kind": "probe",
            "goal": (f"Authenticate and map the privileged surface on "
                     f"{top['host']} ({', '.join(top['reasons'][:3])})"),
            "host": top["host"],
        })
    if any((row.get("http") or {}).get("status") == 401 for row in live):
        next_actions.append({
            "kind": "auth",
            "goal": "Attach an auth profile and re-probe 401 surfaces",
        })
    next_actions.append({
        "kind": "coverage",
        "goal": "Walk the coverage checklist against the live host set",
    })
    next_actions.append({
        "kind": "hunt",
        "goal": "Run a deterministic hunt on the highest-value live host",
    })

    summary = {
        "mission_id": mission_id,
        "seed": target,
        "apex": apex,
        "depth": depth,
        "started_at": started,
        "finished_at": _utc(),
        "hosts_discovered": len(discovered),
        "hosts_considered": len(hosts),
        "hosts_probed": len(to_probe),
        "hosts_live": len(live),
        "hosts_unresolved": len(unresolved),
        "interesting": interesting[:20],
        "live": [{
            "host": row["host"],
            "ips": row.get("ips") or [],
            "status": (row.get("http") or {}).get("status"),
            "url": (row.get("http") or {}).get("url"),
            "title": (row.get("http") or {}).get("title"),
            "server": (row.get("http") or {}).get("server"),
        } for row in live[:80]],
        "tls": tls_hits[:20],
        "profile": {
            "tech": (profile or {}).get("tech") or (profile or {}).get("technologies"),
            "waf": (profile or {}).get("waf"),
            "network": (profile or {}).get("network"),
        },
        "next_actions": next_actions,
        "errors": errors[:12],
        "findings": 0,
        "note": ("Attack-surface map only. Hosts are leads, not findings. "
                 "Stay inside mission scope; expand scope explicitly."),
    }

    index.add_agent_note(
        mission_id, "web2root",
        f"Surface map: {summary['hosts_live']} live / {summary['hosts_discovered']} names",
        json.dumps({
            "apex": apex,
            "live": summary["hosts_live"],
            "discovered": summary["hosts_discovered"],
            "interesting": interesting[:8],
            "next_actions": next_actions,
            "live_hosts": summary["live"][:20],
        }, default=str)[:8000])
    if own_session:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
    return summary
