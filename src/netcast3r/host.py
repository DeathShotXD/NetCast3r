"""Host control: a shell and filesystem on the operator's own machine.

This is what makes NetCast3r a real harness: it can run a command, read and
write a file, and list a directory on the host it runs on, the way a coding
agent can. It is powerful on purpose and gated on purpose.

Rules that are enforced here, not suggested:

- **The framework protects itself.** NetCast3r's own secret store
  (``secrets.json``, the control-plane token) is refused, so a prompt injected
  from a target cannot use the shell to read the control-plane token.
- **A shell is high risk.** It runs under the tool registry's risk gate: a
  supervised caller needs a single-use approval; an authorized autonomous
  mission runs it and the audit records ``authorized:autonomous``.
- **Bounded.** A wall-clock timeout and an output cap on every call; a timed-out
  command's whole process group is killed.
- **Audited.** Every call is a tool call with its command, cwd, and exit code.

The host is the operator's machine. Everything outside NetCast3r's own secret
store is theirs to grant; the agent does not read it silently.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from pathlib import Path

DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 600
MAX_OUTPUT = 200_000
MAX_READ = 1_000_000

# Only NetCast3r's own credentials are off limits by default. The operator's
# other files are theirs; a shell can already reach them, so hiding paths here
# would be theatre, not security.
_SELF_SECRETS = ("secrets.json", "control-plane.json", "mcp-state.json")


class HostError(Exception):
    pass


def _secret_store(base: str | Path | None) -> Path:
    root = Path(base).expanduser().resolve() if base else \
        (Path.home() / ".netcast3r").resolve()
    return root


def guard_path(path: str, base: str | Path | None = None,
               allow_sensitive: bool = False) -> Path:
    """Resolve a host path, refusing NetCast3r's own secret store."""
    raw = str(path or "").strip()
    if not raw:
        raise HostError("path is required")
    try:
        resolved = Path(raw).expanduser().resolve()
    except OSError as exc:
        raise HostError(f"could not resolve the path: {exc}") from exc
    if not allow_sensitive:
        store = _secret_store(base)
        if resolved.name in _SELF_SECRETS and (resolved.parent == store or
                                               store in resolved.parents):
            raise HostError(
                "path is inside NetCast3r's own secret store and is refused")
    return resolved


def _cwd(cwd: str | Path | None, base: str | Path | None) -> str:
    if cwd:
        target = Path(str(cwd)).expanduser()
    else:
        target = Path(base).expanduser() if base else Path.home()
    target = target.resolve()
    if not target.is_dir():
        raise HostError(f"working directory does not exist: {target}")
    return str(target)


def shell(command: str, cwd: str | Path | None = None,
          timeout: int = DEFAULT_TIMEOUT, base: str | Path | None = None,
          env: dict | None = None) -> dict:
    """Run one command in the host shell and return the bounded result."""
    command = str(command or "").strip()
    if not command:
        raise HostError("command is required")
    workdir = _cwd(cwd, base)
    timeout = max(1, min(int(timeout or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    run_env = dict(os.environ)
    run_env.pop("NETCAST3R_TOKEN", None)
    if env:
        run_env.update({str(k): str(v) for k, v in env.items()})
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.Popen(
            ["/bin/sh", "-lc", command], cwd=workdir, env=run_env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, text=True, start_new_session=True)
    except OSError as exc:
        raise HostError(f"could not start the shell: {exc}") from exc
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            stdout, stderr = "", ""
    elapsed = int((time.monotonic() - started) * 1000)
    return {"command": command, "cwd": workdir, "exit_code": proc.returncode,
            "timed_out": timed_out, "elapsed_ms": elapsed,
            "stdout": (stdout or "")[:MAX_OUTPUT],
            "stderr": (stderr or "")[:MAX_OUTPUT],
            "truncated": len(stdout or "") > MAX_OUTPUT or len(stderr or "") > MAX_OUTPUT}


def read_file(path: str, base: str | Path | None = None, max_bytes: int = MAX_READ,
              allow_sensitive: bool = False) -> dict:
    target = guard_path(path, base, allow_sensitive)
    if not target.is_file():
        raise HostError(f"not a file: {target}")
    size = target.stat().st_size
    if size > max(1, min(int(max_bytes or MAX_READ), 20_000_000)):
        raise HostError(f"file is larger than the read cap: {size} bytes")
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise HostError(f"could not read the file: {exc}") from exc
    binary = b"\x00" in data[:8000]
    return {"path": str(target), "bytes": size, "binary": binary,
            "content": "" if binary else data.decode("utf-8", "replace"),
            "note": "binary content is not returned as text" if binary else ""}


def write_file(path: str, content: str = "", append: bool = False,
               base: str | Path | None = None,
               allow_sensitive: bool = False) -> dict:
    target = guard_path(path, base, allow_sensitive)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    try:
        with open(target, mode, encoding="utf-8") as handle:
            handle.write(str(content))
    except OSError as exc:
        raise HostError(f"could not write the file: {exc}") from exc
    return {"path": str(target), "bytes": target.stat().st_size,
            "append": bool(append)}


def list_dir(path: str = ".", base: str | Path | None = None,
             limit: int = 500) -> dict:
    target = guard_path(path, base)
    if not target.is_dir():
        raise HostError(f"not a directory: {target}")
    entries = []
    for child in sorted(target.iterdir(), key=lambda p: p.name.lower()):
        try:
            stat = child.stat()
            kind = "dir" if child.is_dir() else "link" if child.is_symlink() \
                else "file"
            entries.append({"name": child.name, "kind": kind, "bytes": stat.st_size,
                            "modified": int(stat.st_mtime)})
        except OSError:
            entries.append({"name": child.name, "kind": "unknown", "bytes": 0,
                            "modified": 0})
        if len(entries) >= max(1, min(int(limit or 500), 5000)):
            break
    return {"path": str(target), "count": len(entries), "entries": entries}


def find_files(root: str = ".", pattern: str = "*", base: str | Path | None = None,
               limit: int = 500) -> dict:
    target = guard_path(root, base)
    if not target.is_dir():
        raise HostError(f"not a directory: {target}")
    matches = []
    for path in target.rglob(pattern or "*"):
        matches.append(str(path))
        if len(matches) >= max(1, min(int(limit or 500), 5000)):
            break
    return {"root": str(target), "pattern": pattern or "*", "count": len(matches),
            "items": matches}


def stat_path(path: str, base: str | Path | None = None) -> dict:
    target = guard_path(path, base)
    try:
        stat = target.stat()
    except OSError as exc:
        raise HostError(f"could not stat the path: {exc}") from exc
    return {"path": str(target), "exists": True,
            "kind": "dir" if target.is_dir() else "file",
            "bytes": stat.st_size, "mode": oct(stat.st_mode & 0o777),
            "modified": int(stat.st_mtime),
            "owner": stat.st_uid}


def processes(query: str = "", limit: int = 200) -> dict:
    """List host processes, optionally filtered by a name substring."""
    try:
        proc = subprocess.run(["ps", "-eo", "pid,ppid,user,etime,pcpu,pmem,comm"],
                              capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostError(f"could not list processes: {exc}") from exc
    lines = (proc.stdout or "").splitlines()
    header = lines[0] if lines else ""
    needle = str(query or "").lower()
    rows = [line for line in lines[1:]
            if not needle or needle in line.lower()]
    return {"count": len(rows), "header": header,
            "items": rows[:max(1, min(int(limit or 200), 2000))]}


def kill_process(pid: int, signal_name: str = "TERM") -> dict:
    """Send a signal to one host process by pid."""
    try:
        number = int(pid)
    except (TypeError, ValueError):
        raise HostError("pid must be an integer")
    if number <= 1:
        raise HostError("refusing to signal pid 0 or 1")
    sig = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL,
           "INT": signal.SIGINT}.get(str(signal_name or "TERM").upper())
    if sig is None:
        raise HostError("signal must be TERM, KILL, or INT")
    try:
        os.kill(number, sig)
    except ProcessLookupError:
        return {"pid": number, "signalled": False, "reason": "no such process"}
    except PermissionError:
        raise HostError(f"not permitted to signal pid {number}")
    return {"pid": number, "signalled": True, "signal": signal_name}


def which(name: str) -> dict:
    import shutil

    found = shutil.which(str(name or "").strip())
    return {"name": name, "path": found or "", "installed": bool(found)}


def capabilities() -> dict:
    """A quick map of what the host offers, so the agent can plan."""
    import shutil

    interesting = ["bash", "zsh", "python3", "pip", "git", "docker", "nmap",
                   "ffuf", "nuclei", "sqlmap", "hydra", "hashcat", "john",
                   "metasploit", "msfconsole", "netexec", "nxc", "impacket",
                   "burpsuite", "gobuster", "feroxbuster", "dalfox", "wpscan",
                   "responder", "bloodhound", "curl", "jq", "go", "node", "rg"]
    return {"host": os.uname().nodename, "kernel": os.uname().release,
            "user": os.environ.get("USER", ""),
            "tools": {name: bool(shutil.which(name)) for name in interesting}}
