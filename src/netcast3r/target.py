"""The target profile.

Penligent shows a consolidated target overview: network, web, and TLS data.
This builds the same object from real evidence only. Everything here comes from
a stored tool result (an HTTP response, a host probe) or a graph node. If a
field was never observed, it stays empty; the profile never invents an ASN, a
cloud provider, or a certificate.
"""

from __future__ import annotations

from urllib.parse import urlsplit

# Header fingerprints. Each entry is a real, observed value, not a guess.
_WAF_HEADERS = {
    "cf-ray": "cloudflare",
    "cf-cache-status": "cloudflare",
    "x-sucuri-id": "sucuri",
    "x-akamai-transformed": "akamai",
    "akamai-grn": "akamai",
    "x-iinfo": "imperva",
    "x-cdn": "generic-cdn",
    "x-fastly-request-id": "fastly",
    "x-served-by": "fastly",
}
_WAF_COOKIES = {
    "incap_ses": "imperva",
    "visid_incap": "imperva",
    "ak_bmsc": "akamai",
    "__cfduid": "cloudflare",
    "cf_clearance": "cloudflare",
}
_SERVER_TECH = {
    "nginx": "nginx", "apache": "apache", "iis": "iis", "microsoft-iis": "iis",
    "cloudflare": "cloudflare", "gunicorn": "gunicorn", "uvicorn": "uvicorn",
    "express": "express", "envoy": "envoy", "caddy": "caddy",
    "openresty": "openresty", "lighttpd": "lighttpd", "tomcat": "tomcat",
    "jetty": "jetty", "kestrel": "aspnet",
}
_POWERED_TECH = {
    "express": "express", "php": "php", "asp.net": "aspnet",
    "django": "django", "next.js": "nextjs", "nuxt": "nuxt",
    "rails": "rails", "servlet": "java", "spring": "spring",
    "laravel": "laravel", "flask": "flask",
}


def _host_of(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    try:
        return (urlsplit(text if "://" in text else f"https://{text}").hostname
                or "").lower()
    except ValueError:
        return ""


def _looks_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _headers_of(result: dict) -> dict:
    if not isinstance(result, dict):
        return {}
    for key in ("headers", "response_headers", "response"):
        value = result.get(key)
        if isinstance(value, dict):
            return {str(k).lower(): str(v) for k, v in value.items()}
    return {}


def _tech_from_headers(headers: dict) -> list[str]:
    found: list[str] = []
    server = headers.get("server", "").lower()
    for token, name in _SERVER_TECH.items():
        if token in server and name not in found:
            found.append(name)
    powered = headers.get("x-powered-by", "").lower()
    for token, name in _POWERED_TECH.items():
        if token in powered and name not in found:
            found.append(name)
    generator = headers.get("x-generator", "").lower()
    for token, name in _POWERED_TECH.items():
        if token in generator and name not in found:
            found.append(name)
    return found


def _waf_from(headers: dict, cookies: list) -> dict:
    for header, vendor in _WAF_HEADERS.items():
        if header in headers:
            return {"vendor": vendor, "header": header}
    server = headers.get("server", "").lower()
    if server in {"cloudflare", "sucuri/cloudproxy", "akamaighost"}:
        return {"vendor": server, "header": "server"}
    joined = " ".join(str(c).lower() for c in (cookies or []))
    for cookie, vendor in _WAF_COOKIES.items():
        if cookie in joined:
            return {"vendor": vendor, "header": "set-cookie"}
    return {}


def build_profile(index, mission_id: str, registry=None) -> dict:
    """Derive the target profile from stored evidence, plus an optional probe."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ValueError("mission not found")
    target = str(mission.get("target") or "").strip()
    host = _host_of(target)
    if not host:
        raise ValueError("mission has no usable target")

    tech: list[str] = []
    dns: dict = {}
    tls: dict = {}
    network: dict = {}
    waf: dict = {}

    calls, _ = index.list_tool_calls(mission_id=mission_id, limit=500)
    for call in calls:
        result = call.get("result") if isinstance(call.get("result"), dict) else {}
        headers = _headers_of(result)
        for name in _tech_from_headers(headers):
            if name not in tech:
                tech.append(name)
        if not waf and headers:
            waf = _waf_from(headers, result.get("set_cookie"))
        if not tls and isinstance(result.get("tls"), dict):
            tls = result["tls"]
        if not dns and isinstance(result.get("dns"), dict):
            dns = result["dns"]
        if not network:
            for key in ("asn", "org", "cloud", "subnet", "region"):
                if result.get(key):
                    network[key] = result[key]

    # Technology and service nodes the graph already carries.
    for node in index.list_graph_nodes(mission_id):
        if node.get("kind") in {"technology", "service"}:
            label = str(node.get("label") or "").strip()
            if label and label not in tech:
                tech.append(label)

    ip = host if _looks_ip(host) else ""
    if not ip:
        for node in index.list_graph_nodes(mission_id, kind="ip"):
            ip = str(node.get("key") or "")
            break

    # Optional live enrichment when a registry is supplied (never required).
    if registry is not None:
        try:
            probe, is_error = registry.call("host_probe", {"target": target},
                                            actor="agent:profile")
            if not is_error and isinstance(probe, dict):
                headers = _headers_of(probe)
                for name in _tech_from_headers(headers):
                    if name not in tech:
                        tech.append(name)
                if not waf and headers:
                    waf = _waf_from(headers, probe.get("set_cookie"))
                for key in ("ip", "asn", "org", "cloud", "region", "subnet"):
                    if probe.get(key) and key not in network:
                        network[key] = probe[key]
                if isinstance(probe.get("tls"), dict) and not tls:
                    tls = probe["tls"]
        except Exception:  # noqa: BLE001 - enrichment is best effort
            pass

    summary_bits = [host]
    if ip and ip != host:
        summary_bits.append(ip)
    if tech:
        summary_bits.append("tech: " + ", ".join(tech[:6]))
    if waf.get("vendor"):
        summary_bits.append(f"waf/cdn: {waf['vendor']}")

    profile = index.upsert_target_profile(
        mission_id, target=target, host=host, ip=ip,
        summary=" | ".join(summary_bits), dns=dns, tls=tls, waf=waf,
        tech=tech, network=network)

    # Reflect technology onto the graph so the profile feeds chaining.
    host_kind = "ip" if _looks_ip(host) else "host"
    host_node = index.upsert_graph_node(mission_id, host_kind, host, label=host)
    for name in tech:
        node = index.upsert_graph_node(mission_id, "technology", name.lower(),
                                       label=name)
        index.upsert_graph_edge(mission_id, host_node["id"], node["id"], "runs",
                                evidence={"source": "target_profile"})
    return profile
