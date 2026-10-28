"""Local control-plane discovery and state files.

NetCast3r runs as two cooperating processes: the Svelte UI server and any
number of MCP clients (OpenCode, Claude Code, a future agent runtime). The UI
publishes where it listens and which session token it minted; the MCP server
publishes its policy and heartbeat. Both files live under the same base
directory as the SQLite index, are written atomically, and are readable only
by the current user.

Nothing in this module invents data. A missing or stale file is reported as
missing or stale.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

DEFAULT_BASE = Path.home() / ".netcast3r"
CONTROL_PLANE_FILE = "control-plane.json"
MCP_STATE_FILE = "mcp-state.json"


def base_dir(base: str | Path | None = None) -> Path:
    raw = base or os.environ.get("NETCAST3R_BASE") or DEFAULT_BASE
    path = Path(raw).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def control_plane_path(base: str | Path | None = None) -> Path:
    return base_dir(base) / CONTROL_PLANE_FILE


def mcp_state_path(base: str | Path | None = None) -> Path:
    return base_dir(base) / MCP_STATE_FILE


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True, default=str)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        os.replace(temp, path)
    finally:
        try:
            if os.path.exists(temp):
                os.unlink(temp)
        except OSError:
            pass


def write_private_json(path: str | Path, payload: dict) -> Path:
    """Atomically write a 0600 JSON file for local credential material."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_json(target, payload)
    return target


def read_private_json(path: str | Path) -> dict | None:
    """Read a local JSON file, returning None when it is missing or corrupt."""
    try:
        data = json.loads(Path(path).expanduser().read_text("utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_control_plane(base: str | Path | None, payload: dict) -> Path:
    path = control_plane_path(base)
    _atomic_json(path, payload)
    return path


def read_control_plane(base: str | Path | None = None) -> dict | None:
    path = control_plane_path(base)
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    data["path"] = str(path)
    return data


def remove_control_plane(base: str | Path | None, pid: int | None = None) -> None:
    """Remove the file only when it still belongs to this process."""
    path = control_plane_path(base)
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return
    if pid is not None and int(data.get("pid") or 0) not in (0, int(pid)):
        return
    try:
        path.unlink()
    except OSError:
        pass


def write_mcp_state(base: str | Path | None, payload: dict) -> Path:
    path = mcp_state_path(base)
    _atomic_json(path, payload)
    return path


def remove_mcp_state(base: str | Path | None, pid: int | None = None) -> None:
    """Remove the heartbeat only when it still belongs to this process."""
    path = mcp_state_path(base)
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return
    if pid is not None and int(data.get("pid") or 0) not in (0, int(pid)):
        return
    try:
        path.unlink()
    except OSError:
        pass


def read_mcp_state(base: str | Path | None = None) -> dict | None:
    path = mcp_state_path(base)
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    data["path"] = str(path)
    return data


def pid_alive(pid: int | None) -> bool:
    if not pid or int(pid) <= 0:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def public_control_plane(base: str | Path | None = None) -> dict | None:
    """Control-plane details safe to show in the UI (no session token)."""
    data = read_control_plane(base)
    if not data:
        return None
    public = {key: value for key, value in data.items() if key != "token"}
    public["alive"] = pid_alive(int(data.get("pid") or 0))
    return public
