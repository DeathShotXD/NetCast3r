"""The toolbox: a tiered, scope-checked broker for external offensive tools.

HexStrike wraps 150+ tools behind an MCP server; Strix ships a full toolkit in a
sandbox. This is NetCast3r's version with one rule kept: an external tool is a
source of **leads, not findings**. Output is parsed into graph nodes, endpoints,
technologies, and candidates with raw evidence; a finding is still a human-gated
promotion.

Safety is not optional here:

- the target host must be in the caller-supplied allowed set (the mission scope
  plus its target), checked before the binary starts;
- cloud metadata and link-local addresses are refused absolutely;
- arguments are built only from an allowlisted flag set - no shell, ever;
- every run is recorded as a tool call, and output is capped.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import kb
from .graph import host_of

MAX_OUTPUT = 400_000
METADATA_HOSTS = {"metadata.google.internal", "metadata.goog"}
METADATA_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}
URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+")
WORDLIST = Path(__file__).with_name("data") / "paths.txt"


class ToolboxError(Exception):
    pass


def _wordlist() -> str:
    return str(WORDLIST)


# -- catalog ---------------------------------------------------------------
# Each builder is a pure function (target, options) -> argv list. Options are
# validated against an allowlist, so a caller can tune intensity but never
# inject a flag or a shell token.
def _flag(value: str | None, allowed: set[str], default: str = "") -> str:
    value = str(value or default).strip()
    if value and value not in allowed:
        raise ToolboxError(f"value not allowed: {value}")
    return value


def _nmap(target: str, options: dict) -> list[str]:
    ports = _flag(options.get("ports"), {"top100", "top1000", "top5000", "all"},
                  "top1000")
    argv = ["nmap", "-Pn", "-sT", "-sV", "-T4", "--version-light",
            "--host-timeout", "60s", "-oX", "-"]
    argv += {"top100": ["--top-ports", "100"],
             "top1000": ["--top-ports", "1000"],
             "top5000": ["--top-ports", "5000"],
             "all": ["-p-"]}[ports]
    return argv + [target]


def _httpx(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    return ["httpx", "-u", url, "-silent", "-json", "-status-code", "-title",
            "-tech-detect", "-timeout", "10"]


def _katana(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    return ["katana", "-u", url, "-silent", "-d", "2", "-jc", "-kf", "all",
            "-fs", "rdn", "-timeout", "10"]


def _subfinder(target: str, options: dict) -> list[str]:
    return ["subfinder", "-d", target, "-silent", "-timeout", "60"]


def _whatweb(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    return ["whatweb", "--color=never", "--follow-redirect=never", url]


def _ffuf(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    url = url.rstrip("/") + "/FUZZ"
    return ["ffuf", "-u", url, "-w", _wordlist(), "-mc", "all", "-s",
            "-t", "10", "-timeout", "10"]


def _gobuster(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    return ["gobuster", "dir", "-u", url, "-w", _wordlist(), "-q",
            "--no-error", "-t", "10", "--timeout", "10s"]


def _nuclei(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    severity = _flag(options.get("severity"),
                     {"critical", "high", "medium", "low", "info"},
                     "critical")
    if options.get("severity_high"):
        severity = "critical,high"
    return ["nuclei", "-u", url, "-jsonl", "-silent", "-no-interactsh",
            "-severity", severity, "-c", "10", "-rl", "20", "-timeout", "8"]


def _sqlmap(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    return ["sqlmap", "-u", url, "--batch", "--smart", "--level", "1",
            "--risk", "1", "--threads", "2", "--timeout", "10",
            "--answers", "redirect=N,keep-alive=N,merge=N"]


def _nikto(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    return ["nikto", "-h", url, "-nointeractive", "-maxtime", "120s"]


def _wpscan(target: str, options: dict) -> list[str]:
    url = target if "://" in target else "https://" + target
    return ["wpscan", "--url", url, "--no-banner", "--random-user-agent",
            "--format", "json"]


def _netexec(target: str, options: dict) -> list[str]:
    return ["netexec", "smb", target, "--shares"]


def _enum4linux(target: str, options: dict) -> list[str]:
    return ["enum4linux-ng", "-A", target]


TOOLS: dict[str, dict] = {
    "nmap": {"title": "Port and service scan", "category": "recon",
             "binary": "nmap", "risk": "medium", "stage": "active",
             "scope": "host", "parser": "nmap", "builder": _nmap,
             "options": ["ports"], "timeout": 300},
    "subfinder": {"title": "Passive subdomain enumeration", "category": "recon",
                  "binary": "subfinder", "risk": "low", "stage": "passive",
                  "scope": "host", "parser": "urls", "builder": _subfinder,
                  "options": [], "timeout": 120},
    "httpx": {"title": "HTTP probe with technology detection", "category": "recon",
              "binary": "httpx", "risk": "low", "stage": "passive",
              "scope": "url", "parser": "httpx", "builder": _httpx,
              "options": [], "timeout": 120},
    "katana": {"title": "Crawl and print endpoints", "category": "recon",
               "binary": "katana", "risk": "medium", "stage": "active",
               "scope": "url", "parser": "urls", "builder": _katana,
               "options": [], "timeout": 180},
    "whatweb": {"title": "Fingerprint the web stack", "category": "recon",
                "binary": "whatweb", "risk": "low", "stage": "passive",
                "scope": "url", "parser": "whatweb", "builder": _whatweb,
                "options": [], "timeout": 120},
    "ffuf": {"title": "Content discovery", "category": "web",
             "binary": "ffuf", "risk": "medium", "stage": "active",
             "scope": "url", "parser": "urls", "builder": _ffuf,
             "options": [], "timeout": 240},
    "gobuster": {"title": "Directory discovery", "category": "web",
                 "binary": "gobuster", "risk": "medium", "stage": "active",
                 "scope": "url", "parser": "urls", "builder": _gobuster,
                 "options": [], "timeout": 240},
    "nuclei": {"title": "Template-based vulnerability check", "category": "web",
               "binary": "nuclei", "risk": "high", "stage": "intrusive",
               "scope": "url", "parser": "nuclei", "builder": _nuclei,
               "options": ["severity", "severity_high"], "timeout": 360},
    "sqlmap": {"title": "SQL injection test", "category": "web",
               "binary": "sqlmap", "risk": "high", "stage": "intrusive",
               "scope": "url", "parser": "sqlmap", "builder": _sqlmap,
               "options": [], "timeout": 360},
    "nikto": {"title": "Web server check", "category": "web",
              "binary": "nikto", "risk": "medium", "stage": "active",
              "scope": "url", "parser": "urls", "builder": _nikto,
              "options": [], "timeout": 180},
    "wpscan": {"title": "WordPress check", "category": "web",
               "binary": "wpscan", "risk": "medium", "stage": "active",
               "scope": "url", "parser": "urls", "builder": _wpscan,
               "options": [], "timeout": 240},
    "netexec": {"title": "SMB enumeration", "category": "ad",
                "binary": "nxc", "risk": "medium", "stage": "active",
                "scope": "host", "parser": "urls", "builder": _netexec,
                "options": [], "timeout": 180},
    "enum4linux": {"title": "SMB and AD enumeration", "category": "ad",
                   "binary": "enum4linux-ng", "risk": "medium", "stage": "active",
                   "scope": "host", "parser": "urls", "builder": _enum4linux,
                   "options": [], "timeout": 300},
}


def catalog() -> list[dict]:
    return [{"id": tid, "title": spec["title"], "category": spec["category"],
             "binary": spec["binary"], "risk": spec["risk"], "stage": spec["stage"],
             "scope": spec["scope"], "options": spec["options"],
             "installed": shutil.which(spec["binary"]) is not None}
            for tid, spec in sorted(TOOLS.items())]


# -- process registry ------------------------------------------------------
_RUNS: dict[str, dict] = {}
_RUN_LOCK = threading.Lock()


def _host_allowed(host: str, allowed: set[str]) -> bool:
    host = (host or "").strip().strip("[]").rstrip(".").lower()
    if not host:
        return False
    if host in METADATA_HOSTS or host in METADATA_IPS:
        return False
    allowed_l = {str(item).strip().strip("[]").rstrip(".").lower()
                 for item in (allowed or set())}
    return host in allowed_l


def _target_host(spec: dict, target: str) -> str:
    text = str(target or "").strip()
    if spec["scope"] == "url":
        url = text if "://" in text else "https://" + text
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ToolboxError("target must be an http(s) URL")
        return parts.hostname.lower()
    if "://" in text:
        parts = urlsplit(text)
        if not parts.hostname:
            raise ToolboxError("target must be a host")
        return parts.hostname.lower()
    return text.lower()


def run(index, tool_id: str, target: str, allowed_hosts: set[str],
        options: dict | None = None, base: str | Path | None = None,
        mission_id: str = "", run_id: str = "", background: bool = False) -> dict:
    """Run one allowlisted tool after a scope check, and parse its output."""
    spec = TOOLS.get(str(tool_id or "").strip().lower())
    if not spec:
        raise ToolboxError(f"unknown tool: {tool_id}")
    options = dict(options or {})
    for key in options:
        if key not in spec["options"] and key not in {"async", "timeout"}:
            raise ToolboxError(f"option not allowed for {tool_id}: {key}")
    # Scope first: a target outside the mission is refused before we even look
    # for the binary, so authorization never depends on tool availability.
    host = _target_host(spec, target)
    if not _host_allowed(host, allowed_hosts):
        raise ToolboxError(
            f"host is not in the mission scope: {host[:120]}")
    if shutil.which(spec["binary"]) is None:
        raise ToolboxError(f"{spec['binary']} is not installed on this machine")

    argv = spec["builder"](target, options)
    timeout = max(10, min(int(options.get("timeout") or spec["timeout"]), 600))
    run_dir = Path(base or Path.home() / ".netcast3r") / "toolbox" / \
        f"{tool_id}-{int(time.time())}-{os.getpid()}"
    run_dir.mkdir(parents=True, exist_ok=True)
    out_path = run_dir / "stdout.txt"
    err_path = run_dir / "stderr.txt"
    entry_id = f"{tool_id}-{int(time.time() * 1000) % 100000}"
    started = time.monotonic()
    stdout_file = open(out_path, "wb")
    stderr_file = open(err_path, "wb")
    try:
        proc = subprocess.Popen(argv, stdout=stdout_file, stderr=stderr_file,
                                stdin=subprocess.DEVNULL, cwd=str(run_dir),
                                start_new_session=True)
    except OSError as exc:
        stdout_file.close()
        stderr_file.close()
        raise ToolboxError(f"could not start {spec['binary']}: {exc}") from exc

    entry = {"id": entry_id, "tool": tool_id, "target": target, "argv": argv,
             "pid": proc.pid, "proc": proc, "started": started, "status": "running",
             "run_dir": str(run_dir), "timeout": timeout, "mission_id": mission_id,
             "run_id": run_id, "out": str(out_path), "err": str(err_path)}
    with _RUN_LOCK:
        _RUNS[entry_id] = entry

    if background:
        def _reap() -> None:
            try:
                proc.wait()
            finally:
                _finish(entry, index)
        threading.Thread(target=_reap, daemon=True).start()
        return {"id": entry_id, "tool": tool_id, "pid": proc.pid,
                "status": "running", "run_dir": str(run_dir)}

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate(proc)
    result = _finish(entry, index)
    result["timed_out"] = timed_out
    return result


def _terminate(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _read(path: str) -> str:
    try:
        text = Path(path).read_text("utf-8", "ignore")
    except OSError:
        return ""
    return text[:MAX_OUTPUT]


def _finish(entry: dict, index) -> dict:
    proc = entry["proc"]
    code = proc.returncode
    with _RUN_LOCK:
        entry["status"] = "done" if code == 0 else f"exit {code}"
    elapsed = int((time.monotonic() - entry["started"]) * 1000)
    stdout = _read(entry["out"])
    parsed = parse(entry["tool"], stdout)
    persisted = _persist(index, entry, parsed)
    summary = {"id": entry["id"], "tool": entry["tool"], "target": entry["target"],
               "exit_code": code, "elapsed_ms": elapsed,
               "stdout": stdout[-20000:], "stderr": _read(entry["err"])[-4000:],
               "parsed": parsed, "persisted": persisted,
               "note": ("Tool output is a lead, not a finding. It is recorded as "
                        "graph nodes and candidates; promote a candidate yourself "
                        "after you reproduce it.")}
    try:
        index.add_tool_call(entry["tool"], risk=TOOLS[entry["tool"]]["risk"],
                            status="ok" if code == 0 else "error",
                            actor="agent:toolbox", mission_id=entry["mission_id"],
                            run_id=entry["run_id"], args={"target": entry["target"]},
                            result={"exit_code": code, "parsed": parsed},
                            duration_ms=elapsed)
    except Exception:  # noqa: BLE001 - the audit is best effort
        pass
    return summary


def processes() -> list[dict]:
    with _RUN_LOCK:
        entries = list(_RUNS.values())
    return [{"id": item["id"], "tool": item["tool"], "target": item["target"],
             "pid": item["pid"], "status": item["status"],
             "age": round(time.time() - item["started"], 1)} for item in entries]


def kill(entry_id: str) -> bool:
    with _RUN_LOCK:
        entry = _RUNS.get(entry_id)
    if not entry:
        return False
    _terminate(entry["proc"])
    with _RUN_LOCK:
        entry["status"] = "killed"
    return True


# -- parsers ---------------------------------------------------------------
def parse(tool_id: str, stdout: str) -> dict:
    spec = TOOLS.get(tool_id) or {}
    parser = spec.get("parser", "urls")
    if parser == "nmap":
        return _parse_nmap(stdout)
    if parser == "nuclei":
        return _parse_nuclei(stdout)
    if parser == "sqlmap":
        return _parse_sqlmap(stdout)
    if parser == "httpx":
        return _parse_httpx(stdout)
    if parser == "whatweb":
        return _parse_whatweb(stdout)
    return _parse_urls(stdout)


def _urls(text: str) -> list[str]:
    found = []
    for match in URL_RE.findall(text or ""):
        cleaned = match.rstrip(".,;:")
        if cleaned not in found:
            found.append(cleaned)
    return found[:500]


def _parse_urls(stdout: str) -> dict:
    urls = _urls(stdout)
    return {"endpoints": urls, "count": len(urls)}


def _parse_nmap(stdout: str) -> dict:
    services = []
    for match in re.finditer(
            r'<port protocol="(\w+)" portid="(\d+)">.*?'
            r'<state state="(\w+)".*?'
            r'(?:<service name="([^"]*)".*?(?:product="([^"]*)")?)?',
            stdout or "", re.DOTALL):
        protocol, port, state, name, product = match.groups()
        if state != "open":
            continue
        services.append({"port": int(port), "protocol": protocol,
                         "service": name or "", "product": product or ""})
    return {"services": services, "count": len(services)}


def _parse_nuclei(stdout: str) -> dict:
    findings = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get("info") or {}
        findings.append({
            "template": item.get("template-id") or item.get("templateID") or "",
            "name": info.get("name") or "",
            "severity": str(info.get("severity") or "info").lower(),
            "matched_at": item.get("matched-at") or item.get("host") or "",
            "type": item.get("type") or "",
        })
    return {"findings": findings, "count": len(findings)}


def _parse_sqlmap(stdout: str) -> dict:
    text = stdout or ""
    vulnerable = bool(re.search(r"is vulnerable|sqlmap identified the following",
                                text, re.IGNORECASE))
    params = re.findall(r"Parameter: ([^\s(]+)", text)
    return {"vulnerable": vulnerable, "parameters": sorted(set(params))[:50],
            "urls": _urls(text)[:50]}


def _parse_httpx(stdout: str) -> dict:
    rows = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        rows.append({"url": item.get("url") or item.get("input") or "",
                     "status": item.get("status_code") or item.get("status-code"),
                     "title": item.get("title") or "",
                     "tech": item.get("tech") or []})
    return {"endpoints": [row["url"] for row in rows if row["url"]],
            "hosts": rows, "count": len(rows)}


def _parse_whatweb(stdout: str) -> dict:
    tech = []
    blob = stdout or ""
    for match in re.findall(r"\[([A-Za-z0-9 .\-]{2,30})\]", blob):
        name = match.strip()
        if name and name not in tech:
            tech.append(name)
    return {"tech": tech[:60], "urls": _urls(blob)[:50], "count": len(tech)}


# -- persistence -----------------------------------------------------------
def _persist(index, entry: dict, parsed: dict) -> dict:
    mission_id = str(entry.get("mission_id") or "")
    host = host_of(entry["target"]) or _target_host(
        TOOLS.get(entry["tool"], {"scope": "url"}), entry["target"])
    written = {"nodes": 0, "edges": 0, "candidates": 0, "kb": 0}
    if not mission_id:
        return written

    host_node = None
    if host:
        host_node = index.upsert_graph_node(mission_id, "host", host, label=host)
        written["nodes"] += 1

    def endpoint(url: str) -> None:
        nonlocal host_node
        if not url:
            return
        url_host = host_of(url)
        if host and url_host and url_host != host:
            return  # only the mission host's own surface
        node = index.upsert_graph_node(mission_id, "endpoint", url, label=url)
        written["nodes"] += 1
        if host_node:
            index.upsert_graph_edge(mission_id, host_node["id"], node["id"],
                                    "exposes",
                                    evidence={"tool": entry["tool"]})
            written["edges"] += 1

    for url in (parsed.get("endpoints") or [])[:200]:
        endpoint(url)
    for row in (parsed.get("hosts") or [])[:100]:
        endpoint(str(row.get("url") or ""))
        for name in row.get("tech") or []:
            tech = index.upsert_graph_node(mission_id, "technology",
                                           str(name).lower(), label=str(name))
            written["nodes"] += 1
            kb.record(index, "global", "technology", str(name).lower(),
                      title=str(name), body=f"Observed on {host}",
                      source={"mission_id": mission_id, "tool": entry["tool"]})
            written["kb"] += 1
            if host_node:
                index.upsert_graph_edge(mission_id, host_node["id"], tech["id"],
                                        "runs", evidence={"tool": entry["tool"]})
                written["edges"] += 1
    for name in (parsed.get("tech") or [])[:60]:
        index.upsert_graph_node(mission_id, "technology", str(name).lower(),
                                label=str(name))
        written["nodes"] += 1
    for service in (parsed.get("services") or [])[:100]:
        key = f"{service.get('port')}/{service.get('protocol')}"
        node = index.upsert_graph_node(
            mission_id, "service", key,
            label=f"{key} {service.get('service') or ''}".strip(),
            data=service)
        written["nodes"] += 1
        if host_node:
            index.upsert_graph_edge(mission_id, host_node["id"], node["id"],
                                    "exposes", evidence={"tool": entry["tool"]})
            written["edges"] += 1

    for finding in (parsed.get("findings") or [])[:50]:
        try:
            index.create_candidate(
                mission_id, str(finding.get("name") or finding.get("template")),
                severity=str(finding.get("severity") or "medium"),
                module_id=str(finding.get("template") or ""),
                run_id=str(entry.get("run_id") or ""),
                evidence={"tool": entry["tool"], **finding})
            written["candidates"] += 1
        except ValueError:
            continue
    if parsed.get("vulnerable"):
        try:
            index.create_candidate(
                mission_id, f"SQL injection ({entry['tool']})",
                severity="high", module_id="web-sqli-error",
                run_id=str(entry.get("run_id") or ""),
                evidence={"tool": entry["tool"], **parsed})
            written["candidates"] += 1
        except ValueError:
            pass
    return written
