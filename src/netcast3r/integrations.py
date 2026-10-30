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


# ---------------------------------------------------------------------------
# Scoped artifact download
# ---------------------------------------------------------------------------

MAX_DOWNLOAD = 20 * 1024 * 1024
SANDBOX_IMAGES = ("python:3.12-slim", "alpine:3.20", "debian:12-slim", "ubuntu:24.04")


def sandbox_run(image: str, command: list[str], stdin: str = "", timeout: int = 60,
                base: str | Path | None = None) -> dict:
    """Run one command in a locked-down Docker container.

    No network, read-only root, dropped capabilities, no new privileges, a
    non-root user, and a small tmpfs. The caller supplies a short command or a
    script on stdin; there is no host mount. This is for reading a PoC, not for
    reaching a target.
    """
    if image not in SANDBOX_IMAGES:
        raise ToolRunError(f"image is not allowlisted: {image}")
    if not isinstance(command, list) or not command:
        raise ToolRunError("command must be a non-empty list")
    if not all(isinstance(part, str) and part for part in command):
        raise ToolRunError("every command argument must be a non-empty string")
    if shutil.which("docker") is None:
        raise ToolRunError("docker is not installed")
    timeout = max(5, min(int(timeout or 60), 300))
    argv = [
        "docker", "run", "--rm", "-i", "--network", "none",
        "--memory", "256m", "--cpus", "1", "--pids-limit", "128",
        "--read-only", "--tmpfs", "/tmp:rw,size=64m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65534:65534", image, *command,
    ]
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              check=False, input=stdin or "")
        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"").decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr or b"").decode("utf-8", "ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        code = 124
        timed_out = True
    output = (stdout or "").strip()
    truncated = len(output) > MAX_OUTPUT
    return {
        "image": image,
        "command": command,
        "exit_code": code,
        "timed_out": timed_out,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "stdout": output[:MAX_OUTPUT],
        "stderr": (stderr or "").strip()[:20_000],
        "truncated": truncated,
        "sandbox": {"network": "none", "read_only": True, "cap_drop": "ALL",
                    "user": "65534:65534", "memory": "256m"},
        "note": ("Sandboxed local execution. The container has no network and no host "
                 "mount; read the output before trusting it."),
    }


def fetch_to_file(url: str, name: str, base: str | Path | None = None,
                  max_bytes: int = 10 * 1024 * 1024, verify_tls: bool = True,
                  timeout: float = 30.0, headers: dict | None = None) -> dict:
    """Download one scoped URL to the local artifact directory.

    The caller has already checked the URL against the mission scope. The file
    is never opened or executed; it exists so a reverse-engineering tool can
    read it after the response size cap of ``http_request``.
    """
    import hashlib
    import httpx

    if not url.startswith(("http://", "https://")):
        raise ToolRunError("download target must be an http(s) URL")
    max_bytes = max(1024, min(int(max_bytes or 10 * 1024 * 1024), MAX_DOWNLOAD))
    safe = "".join(char for char in Path(str(name or "artifact.bin")).name
                   if char.isalnum() or char in "._-")[:120] or "artifact.bin"
    directory = Path(base or Path.home() / ".netcast3r") / "downloads"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{int(time.time())}-{safe}"
    digest = hashlib.sha256()
    total = 0
    truncated = False
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False,
                          verify=verify_tls) as client:
            with client.stream("GET", url, headers=headers or {}) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location", "")
                    raise ToolRunError(f"download redirected to {location[:200]}; "
                                       "fetch the in-scope URL directly")
                if response.status_code >= 400:
                    raise ToolRunError(f"download returned HTTP {response.status_code}")
                content_type = response.headers.get("content-type", "")
                with open(target, "wb") as handle:
                    for chunk in response.iter_bytes():
                        if total + len(chunk) > max_bytes:
                            handle.write(chunk[: max_bytes - total])
                            digest.update(chunk[: max_bytes - total])
                            total = max_bytes
                            truncated = True
                            break
                        handle.write(chunk)
                        digest.update(chunk)
                        total += len(chunk)
    except httpx.HTTPError as exc:
        raise ToolRunError(f"download failed: {type(exc).__name__}") from exc
    os.chmod(target, 0o600)
    return {
        "path": str(target),
        "name": safe,
        "url": url,
        "bytes": total,
        "sha256": digest.hexdigest(),
        "content_type": content_type,
        "truncated": truncated,
        "note": "Local artifact. Analyze it with reveng_analyze; nothing was executed.",
    }


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
                              cwd=str(run_dir), check=False, stdin=subprocess.DEVNULL)
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


def load_mcp_servers(base: str | Path | None = None) -> dict[str, dict]:
    """Return the operator-configured outbound MCP servers, without secrets."""
    path = Path(base or Path.home() / ".netcast3r") / "integrations.json"
    try:
        config = json.loads(path.read_text() or "{}")
    except (OSError, ValueError):
        return {}
    servers = config.get("mcp_servers")
    if not isinstance(servers, dict):
        return {}
    result: dict[str, dict] = {}
    for name, raw in servers.items():
        if not isinstance(raw, dict):
            continue
        transport = str(raw.get("transport") or "http").lower()
        item = {"transport": transport}
        if transport == "stdio":
            command = raw.get("command")
            if isinstance(command, str):
                command = [command]
            if not isinstance(command, list) or not command:
                continue
            item["command"] = [str(part) for part in command]
            item["args"] = [str(part) for part in (raw.get("args") or [])]
            item["cwd"] = str(raw.get("cwd") or "")
            item["env"] = {str(k): str(v) for k, v in (raw.get("env") or {}).items()}
        else:
            item["url"] = str(raw.get("url") or "").strip()
            item["token"] = str(raw.get("token") or "")
            if not item["url"]:
                continue
        result[str(name)] = item
    return result


class StdioMCPClient:
    """Minimal MCP stdio client for a local command the operator configured."""

    def __init__(self, command: list[str], args: list[str] | None = None,
                 env: dict | None = None, cwd: str = "", timeout: float = 20.0):
        self.command = [*command, *(args or [])]
        if not self.command:
            raise BurpError("stdio MCP command is empty")
        import subprocess
        merged = os.environ.copy()
        merged.update(env or {})
        try:
            self.proc = subprocess.Popen(
                self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, cwd=cwd or None,
                env=merged)
        except OSError as exc:
            raise BurpError(f"could not start stdio MCP server: {exc.strerror or exc}") from exc
        self.timeout = timeout
        self._id = 0

    def _send(self, payload: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def _read(self, wanted: int) -> dict:
        import select
        assert self.proc.stdout is not None
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            ready, _, _ = select.select([self.proc.stdout], [], [], 0.5)
            if not ready:
                if self.proc.poll() is not None:
                    break
                continue
            line = self.proc.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("id") == wanted:
                return message
        raise BurpError("stdio MCP server did not answer; check its stderr")

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method,
                    "params": params or {}})
        message = self._read(self._id)
        if "error" in message:
            error = message["error"] or {}
            raise BurpError(f"{error.get('code')}: {error.get('message')}")
        return message.get("result") or {}

    def initialize(self) -> dict:
        result = self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "netcast3r", "version": "0.1.0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized",
                    "params": {}})
        return result

    def list_tools(self) -> list[dict]:
        return self.request("tools/list", {}).get("tools") or []

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        result = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        if result.get("isError"):
            raise BurpError("stdio MCP tool returned an error")
        return result

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def mcp_server_tools(config: dict) -> dict:
    """Start a configured outbound MCP server, list its tools, then stop it."""
    if config.get("transport") == "stdio":
        client = StdioMCPClient(config.get("command") or [], config.get("args") or [],
                                config.get("env") or {}, config.get("cwd") or "")
        try:
            info = client.initialize()
            tools = client.list_tools()
        finally:
            client.close()
    else:
        client = BurpClient(config.get("url", ""), config.get("token", ""))
        info = client.initialize()
        tools = client.list_tools()
    return {
        "ok": True,
        "transport": config.get("transport", "http"),
        "server": info.get("serverInfo") or {},
        "protocol": info.get("protocolVersion", ""),
        "tools": [{"name": item.get("name"), "description": (item.get("description") or "")[:240]}
                  for item in tools],
        "tool_count": len(tools),
    }


def mcp_server_call(config: dict, tool: str, arguments: dict) -> dict:
    if config.get("transport") == "stdio":
        client = StdioMCPClient(config.get("command") or [], config.get("args") or [],
                                config.get("env") or {}, config.get("cwd") or "")
        try:
            client.initialize()
            return client.call_tool(tool, arguments)
        finally:
            client.close()
    client = BurpClient(config.get("url", ""), config.get("token", ""))
    client.initialize()
    return client.call_tool(tool, arguments)


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
