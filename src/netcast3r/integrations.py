"""Local recon tools and Burp MCP integration.

NetCast3r already owns scope, policy, audit, and evidence. This module lets an
agent use the tools that are actually installed on the machine without handing
it a shell:

* ``run_tool`` builds a fixed command for an allowlisted binary, never a shell
  string, and captures a bounded amount of output.
* ``BurpClient`` speaks the MCP streamable-HTTP transport to a Burp MCP server,
  so proxy history and Repeater-style requests can be driven from the same
  mission and audit trail.

Scope is enforced by the MCP handler before anything here is called. This
module only refuses targets that cannot be a normal public host and tools that
are not on the allowlist.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

MAX_OUTPUT = 200_000
DEFAULT_TIMEOUT = 180

# tool -> (mode, binary, risk, description)
TOOL_CATALOG: dict[str, tuple[str, str, str, str]] = {
    "subfinder": ("passive", "subfinder", "medium",
                  "Passive subdomain enumeration for one domain."),
    "httpx": ("passive", "httpx", "medium",
              "HTTP probe with status, title, and technology detection."),
    "katana": ("passive", "katana", "medium",
               "Crawl a scoped URL and print discovered endpoints."),
    "whatweb": ("passive", "whatweb", "medium",
                "Fingerprint the web stack of one URL."),
    "gau": ("passive", "gau", "medium",
            "Fetch known URLs for a domain from public archives."),
    "waybackurls": ("passive", "waybackurls", "medium",
                    "Fetch known URLs for a domain from the Wayback Machine."),
    "nuclei": ("active", "nuclei", "high",
               "Run critical/high nuclei templates against one URL."),
    "dalfox": ("active", "dalfox", "high",
               "XSS scan against one URL with a bounded payload set."),
    "nmap": ("active", "nmap", "high",
             "Service probe of the top 100 TCP ports on one host."),
}

METADATA_HOSTS = {"metadata.google.internal", "metadata.goog"}
METADATA_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}
HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


class ToolRunError(Exception):
    pass


def _public_host(host: str) -> str:
    host = (host or "").strip().strip("[]").rstrip(".").lower()
    if not host:
        raise ToolRunError("target host is empty")
    if host in METADATA_HOSTS or host in METADATA_IPS:
        raise ToolRunError("metadata and link-local hosts are refused")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.match(host):
            raise ToolRunError(f"not a valid hostname: {host[:80]}")
        return host
    if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
        raise ToolRunError("private, loopback, and link-local addresses are refused")
    return host


def target_host(target: str, domain_only: bool = False) -> str:
    """Return the host a tool should run against, refusing unsafe targets."""
    target = (target or "").strip()
    if "://" in target:
        parts = urlsplit(target)
        if parts.scheme not in {"http", "https"}:
            raise ToolRunError("only http(s) targets are accepted")
        if domain_only:
            raise ToolRunError("this tool takes a domain, not a URL")
        return _public_host(parts.hostname or "")
    if domain_only or "/" in target:
        return _public_host(target.split("/", 1)[0])
    return _public_host(target)


def _resolve_check(host: str) -> None:
    """Refuse a hostname that resolves only to private or link-local space."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return
    for info in infos:
        raw = info[4][0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            raise ToolRunError(f"{host} resolves to a private address ({raw}); refused")


def _command(tool: str, target: str, timeout: int) -> list[str]:
    host = target_host(target, domain_only=tool in {"subfinder", "gau", "waybackurls"})
    if tool in {"nuclei", "dalfox", "whatweb", "httpx", "katana"}:
        url = target if "://" in target else "https://" + target
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ToolRunError("target must be an http(s) URL")
        host = _public_host(parts.hostname)
    _resolve_check(host)

    if tool == "subfinder":
        return ["subfinder", "-d", host, "-silent", "-timeout", str(min(timeout, 120))]
    if tool == "httpx":
        return ["httpx", "-u", url, "-silent", "-status-code", "-title",
                "-tech-detect", "-follow-redirects", "-timeout", "10"]
    if tool == "katana":
        return ["katana", "-u", url, "-silent", "-d", "2", "-jc", "-kf", "all",
                "-timeout", "10"]
    if tool == "whatweb":
        return ["whatweb", "--no-color", "--quiet", url]
    if tool == "gau":
        return ["gau", "--subs", host]
    if tool == "waybackurls":
        return ["waybackurls", host]
    if tool == "nuclei":
        return ["nuclei", "-u", url, "-silent", "-severity", "critical,high",
                "-stats", "-timeout", "10", "-retries", "1", "-no-color"]
    if tool == "dalfox":
        return ["dalfox", "url", url, "--silence", "--no-color",
                "--timeout", "10"]
    if tool == "nmap":
        return ["nmap", "-sV", "-T3", "--top-ports", "100", "--open", host]
    raise ToolRunError(f"tool is not allowlisted: {tool}")


def run_tool(tool: str, target: str, timeout: int = DEFAULT_TIMEOUT,
             base: str | Path | None = None) -> dict:
    """Run one allowlisted tool and return bounded stdout/stderr."""
    tool = (tool or "").strip().lower()
    if tool not in TOOL_CATALOG:
        raise ToolRunError(f"unknown tool: {tool}")
    if shutil.which(tool) is None:
        raise ToolRunError(f"{tool} is not installed on this machine")
    timeout = max(10, min(int(timeout or DEFAULT_TIMEOUT), 600))
    command = _command(tool, target, timeout)
    run_dir = Path(base or Path.home() / ".netcast3r") / "tool-runs" / \
        f"{tool}-{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                              cwd=str(run_dir), check=False)
        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"").decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr or b"").decode("utf-8", "ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        code = 124
        timed_out = True
    elapsed = int((time.monotonic() - started) * 1000)
    output = (stdout or "").strip()
    truncated = len(output) > MAX_OUTPUT
    if truncated:
        output = output[:MAX_OUTPUT]
    return {
        "tool": tool,
        "mode": TOOL_CATALOG[tool][0],
        "target": target,
        "command": command[:-1] + [command[-1]] if len(" ".join(command)) < 400 else command[:8] + ["..."],
        "exit_code": code,
        "timed_out": timed_out,
        "elapsed_ms": elapsed,
        "stdout": output,
        "stderr": (stderr or "").strip()[:20_000],
        "truncated": truncated,
        "run_dir": str(run_dir),
        "note": ("Raw tool output. Treat every line as a lead and verify it against the "
                 "target; do not record a finding from scanner output alone."),
    }


# ---------------------------------------------------------------------------
# Burp MCP
# ---------------------------------------------------------------------------

class BurpError(Exception):
    pass


def load_burp_config(base: str | Path | None = None) -> dict:
    path = Path(base or Path.home() / ".netcast3r") / "integrations.json"
    config: dict = {}
    if path.is_file():
        try:
            config = json.loads(path.read_text() or "{}")
        except (OSError, ValueError):
            config = {}
    burp = config.get("burp") if isinstance(config.get("burp"), dict) else {}
    url = os.environ.get("NETCAST3R_BURP_URL") or str(burp.get("url") or "")
    token = os.environ.get("NETCAST3R_BURP_TOKEN") or str(burp.get("token") or "")
    return {"url": url.strip(), "token": token, "configured": bool(url.strip())}


def _parse_sse(text: str) -> list[dict]:
    messages: list[dict] = []
    for block in re.split(r"\r?\n\r?\n", text or ""):
        data = "\n".join(line[5:].strip() for line in block.splitlines()
                         if line.startswith("data:"))
        if not data:
            continue
        try:
            payload = json.loads(data)
        except ValueError:
            continue
        if isinstance(payload, dict):
            messages.append(payload)
        elif isinstance(payload, list):
            messages.extend(item for item in payload if isinstance(item, dict))
    return messages


class BurpClient:
    """Minimal MCP streamable-HTTP client for a Burp MCP server."""

    def __init__(self, url: str, token: str = "", timeout: float = 20.0,
                 transport=None):
        if not url:
            raise BurpError("Burp MCP URL is not configured; set NETCAST3R_BURP_URL "
                            "or ~/.netcast3r/integrations.json")
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.session_id = ""
        self._id = 0
        self._client = None
        if transport is not None:
            import httpx
            self._client = httpx.Client(transport=transport, timeout=timeout)

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def _post(self, payload: dict) -> dict:
        import httpx
        client = self._client or httpx.Client(timeout=self.timeout)
        close = self._client is None
        try:
            response = client.post(self.url, json=payload, headers=self._headers())
            session = response.headers.get("mcp-session-id")
            if session:
                self.session_id = session
            if response.status_code >= 400:
                raise BurpError(f"Burp MCP returned HTTP {response.status_code}: "
                                f"{response.text[:300]}")
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                messages = _parse_sse(response.text)
                for message in messages:
                    if message.get("id") == payload.get("id"):
                        return message
                if messages:
                    return messages[-1]
                raise BurpError("Burp MCP returned an empty event stream")
            try:
                return response.json()
            except ValueError as exc:
                raise BurpError("Burp MCP returned invalid JSON") from exc
        except httpx.HTTPError as exc:
            raise BurpError(f"Burp MCP unreachable: {type(exc).__name__}") from exc
        finally:
            if close:
                client.close()

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method,
                   "params": params or {}}
        message = self._post(payload)
        if "error" in message:
            error = message["error"] or {}
            raise BurpError(f"{error.get('code')}: {error.get('message')}")
        return message.get("result") or {}

    def initialize(self) -> dict:
        result = self.request("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "netcast3r", "version": "0.1.0"},
        })
        try:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized",
                        "params": {}})
        except BurpError:
            pass
        return result

    def list_tools(self) -> list[dict]:
        result = self.request("tools/list", {})
        return result.get("tools") or []

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        result = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        if result.get("isError"):
            raise BurpError("Burp tool returned an error")
        return result

    def status(self) -> dict:
        info = self.initialize()
        tools = self.list_tools()
        return {
            "ok": True,
            "url": self.url,
            "server": info.get("serverInfo") or {},
            "protocol": info.get("protocolVersion", ""),
            "tools": [{"name": item.get("name"), "description": item.get("description", "")[:200]}
                      for item in tools],
            "tool_count": len(tools),
        }
