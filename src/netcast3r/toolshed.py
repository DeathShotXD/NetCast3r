"""Helix's toolsmith: durable scripts, local execution, and tool study notes.

The brain can write a small automation when no installed tool fits, run it with
the mission context in the environment, and keep it in shared memory for later
turns. Scripts live under the state directory, run without a shell, are bounded
by a timeout, and every run is recorded.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
LANGUAGES = {"python": ".py", "bash": ".sh", "sh": ".sh"}
MAX_TIMEOUT = 300
MAX_OUTPUT = 40_000

TOOL_CATEGORIES = {
    "recon": ("curl", "wget", "dig", "nslookup", "whois", "nmap", "masscan",
              "subfinder", "amass", "httpx", "dnsx", "naabu"),
    "web": ("ffuf", "gobuster", "feroxbuster", "dirsearch", "nikto", "nuclei",
            "sqlmap", "dalfox", "wpscan", "whatweb", "wafw00f"),
    "auth": ("hydra", "john", "hashcat", "netexec", "nxc", "impacket-*"),
    "source": ("git", "git-dumper", "semgrep", "gitleaks", "trufflehog",
               "jadx", "apktool", "readelf", "objdump", "strings", "rg"),
    "runtime": ("python3", "node", "go", "jq", "curl", "docker", "pwsh"),
}


def toolshed_dir(base: str | Path | None) -> Path:
    root = Path(base or (Path.home() / ".netcast3r")) / "toolshed"
    root.mkdir(parents=True, exist_ok=True)
    return root


def validate_name(name: str) -> str:
    value = str(name or "").strip().lower().replace(" ", "-")
    if not NAME_RE.match(value):
        raise ValueError(
            "script name must be 3-64 lowercase letters, digits, '-' or '_' "
            "and start with a letter")
    return value


def write_script(index, base, name: str, content: str, purpose: str = "",
                 language: str = "python", tags: list | None = None,
                 mission_id: str = "", source: str = "helix") -> dict:
    name = validate_name(name)
    language = str(language or "python").lower()
    if language not in LANGUAGES:
        raise ValueError(f"unsupported language: {language}")
    root = toolshed_dir(base)
    target = root / f"{name}{LANGUAGES[language]}"
    target.write_text(str(content), encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    record = index.save_helix_script(
        name, purpose or f"Helix automation: {name}", str(content),
        language="bash" if language in {"bash", "sh"} else "python",
        path=str(target), tags=tags, mission_id=mission_id, source=source)
    return {**record, "path": str(target)}


def run_script(index, base, name_or_id: str, args: list | None = None,
               timeout: int = 60, mission_id: str = "") -> dict:
    script = index.get_helix_script(name_or_id)
    if not script:
        raise ValueError(f"unknown script: {name_or_id}")
    path = Path(str(script.get("path") or "")).expanduser()
    root = toolshed_dir(base).resolve()
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        raise ValueError("script path is outside the toolshed")
    if not path.is_file():
        raise ValueError(f"script file is missing: {path}")
    language = str(script.get("language") or "python")
    argv = [sys.executable, str(path)] if language == "python" else \
        ["/bin/sh", str(path)]
    argv.extend(str(item) for item in (args or []))
    env = dict(os.environ)
    env["NETCAST3R_BASE"] = str(Path(base or (Path.home() / ".netcast3r")))
    env["NETCAST3R_MISSION_ID"] = str(mission_id or "")
    if mission_id:
        mission = index.get_mission(mission_id) or {}
        env["NETCAST3R_SCOPE"] = json.dumps({
            "target": mission.get("target") or "",
            "scope": mission.get("scope") or [],
        }, default=str)
    timeout = max(1, min(int(timeout or 60), MAX_TIMEOUT))
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(argv, cwd=str(root), env=env,
                              capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
        code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        code = -1
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
    except OSError as exc:
        code, stdout, stderr = -1, "", f"{type(exc).__name__}: {exc}"
    elapsed = int((time.monotonic() - started) * 1000)
    success = code == 0 and not timed_out
    status = "ok" if success else ("timeout" if timed_out else "error")
    result = {
        "script": script.get("name"), "path": str(path),
        "exit_code": code, "timed_out": timed_out, "elapsed_ms": elapsed,
        "status": status,
        "stdout": (stdout or "")[:MAX_OUTPUT],
        "stderr": (stderr or "")[:MAX_OUTPUT],
    }
    index.record_helix_script_run(
        script["id"], success, status=status,
        output=result["stdout"], error=result["stderr"], duration_ms=elapsed)
    try:
        index.add_tool_call(
            "helix_script", risk="medium", status="ok" if success else "error",
            actor="agent:helix", mission_id=mission_id,
            args={"script": script.get("name"), "args": args or []},
            result={"exit_code": code, "timed_out": timed_out,
                    "elapsed_ms": elapsed},
            error=result["stderr"][:500] if not success else "",
            duration_ms=elapsed)
    except Exception:  # noqa: BLE001 - audit must not hide the run
        pass
    return result


def delete_script(index, base, name_or_id: str) -> bool:
    record = index.get_helix_script(name_or_id)
    if not record:
        return False
    path = Path(str(record.get("path") or "")).expanduser()
    root = toolshed_dir(base).resolve()
    try:
        resolved = path.resolve()
        resolved.relative_to(root)
        if resolved.is_file():
            resolved.unlink()
    except (OSError, ValueError):
        pass
    return index.delete_helix_script(record["id"])


def _first_lines(text: str, limit: int = 12) -> str:
    lines = [line.rstrip() for line in str(text or "").splitlines()
             if line.strip()]
    return "\n".join(lines[:limit])[:2000]


def _which_study(name: str) -> dict:
    path = shutil.which(name)
    version = ""
    help_text = ""
    if path:
        for flag in ("--version", "-V"):
            try:
                proc = subprocess.run([path, flag], capture_output=True,
                                      text=True, timeout=6,
                                      stdin=subprocess.DEVNULL)
                version = _first_lines(proc.stdout or proc.stderr, 4)
                if version:
                    break
            except (OSError, subprocess.SubprocessError):
                continue
        for flag in ("--help", "-h"):
            try:
                proc = subprocess.run([path, flag], capture_output=True,
                                      text=True, timeout=8,
                                      stdin=subprocess.DEVNULL)
                help_text = _first_lines(proc.stdout or proc.stderr, 24)
                if help_text:
                    break
            except (OSError, subprocess.SubprocessError):
                continue
    return {"tool": name, "path": path or "", "installed": bool(path),
            "version": version, "help": help_text}


def study_tool(index, name: str = "", query: str = "") -> dict:
    name = str(name or "").strip()
    query = str(query or "").strip().lower()
    if name:
        found = _which_study(name)
        if found["installed"]:
            summary = (f"{name} is installed at {found['path']}. "
                       f"Version: {found['version'] or 'unknown'}.")
            index.save_tool_note(
                name, path=found["path"], version=found["version"],
                summary=summary, help_text=found["help"], tags=["tool-study"])
            try:
                index.add_lesson(
                    f"Tool study: {name}", found["help"] or summary,
                    technique="tool-study", context=found["path"],
                    outcome="observation", tags=["tool", name],
                    source="agent:helix", confidence=0.9)
            except Exception:  # noqa: BLE001 - lesson memory is best effort
                pass
        return {**found, "summary": summary if found["installed"]
                else f"{name} is not installed on this host."}
    categories = {}
    for category, tools in TOOL_CATEGORIES.items():
        rows = []
        for tool in tools:
            if tool.endswith("*"):
                prefix = tool[:-1]
                matches = [item for item in
                           ("impacket-secretsdump", "impacket-psexec",
                            "impacket-smbexec") if shutil.which(item)]
                rows.extend({"tool": item, "path": shutil.which(item),
                             "installed": True} for item in matches
                            if not query or query in item.lower()
                            or query in category)
                continue
            if query and query not in tool.lower() and query not in category:
                continue
            path = shutil.which(tool)
            rows.append({"tool": tool, "path": path or "",
                         "installed": bool(path)})
        if rows:
            categories[category] = rows
    return {"query": query, "categories": categories,
            "installed": sum(1 for rows in categories.values()
                             for row in rows if row["installed"]),
            "note": "Use tool_study with a tool name to read its version and help."}


def tools_context(index, limit: int = 8) -> dict:
    scripts = index.list_helix_scripts(limit=limit)
    notes = index.list_tool_notes(limit=limit)
    return {
        "scripts": [
            {"name": row.get("name"), "purpose": row.get("purpose"),
             "language": row.get("language"), "runs": row.get("runs"),
             "successes": row.get("successes"),
             "failures": row.get("failures"),
             "last_status": row.get("last_status")}
            for row in scripts
        ],
        "tool_notes": [
            {"tool": row.get("tool"), "version": row.get("version"),
             "summary": str(row.get("summary") or "")[:300]}
            for row in notes
        ],
        "note": ("Write a reusable Python automation with script_write when a "
                 "task needs custom logic; test it with script_run and keep it. "
                 "Study installed tools with tool_study before reinventing one."),
    }
