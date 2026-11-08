"""Dashboard login credentials.

NetCast3r binds to loopback, but the dashboard still needs a login so a stray
tab or another local process cannot drive the plane. The default is
deliberately simple (``admin`` / ``123``) and is meant to be changed from the
dashboard on first use. The password is never stored in plain text: it is kept
as a salted PBKDF2-HMAC-SHA256 hash in a 0600 file under the base directory.

The long session token minted at boot still exists and is what the dashboard
cookie, the MCP client, and automation use. A username and password is just a
friendlier way to obtain that session.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path

from .control import base_dir

CRED_FILE = "credentials.json"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "123"
ITERATIONS = 240_000


def credentials_path(base: str | Path | None = None) -> Path:
    return base_dir(base) / CRED_FILE


def _hash(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations
    ).hex()


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
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


def _record(username: str, password: str) -> dict:
    salt = secrets.token_hex(16)
    return {
        "version": 1,
        "username": username,
        "salt": salt,
        "hash": _hash(password, salt, ITERATIONS),
        "iterations": ITERATIONS,
    }


def ensure_credentials(base: str | Path | None = None) -> dict:
    """Return the stored record, creating the default one on first run."""
    path = credentials_path(base)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if isinstance(data, dict) and data.get("username") and data.get("hash") and data.get("salt"):
        return data
    data = _record(DEFAULT_USERNAME, DEFAULT_PASSWORD)
    _atomic_write(path, data)
    return data


def verify(base: str | Path | None, username: str, password: str) -> bool:
    """Constant-time check of a username and password pair."""
    data = ensure_credentials(base)
    if not hmac.compare_digest(str(username), str(data.get("username", ""))):
        return False
    salt = str(data.get("salt", ""))
    try:
        iterations = int(data.get("iterations") or ITERATIONS)
        expected = str(data.get("hash", ""))
        actual = _hash(str(password), salt, iterations)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def update_credentials(base: str | Path | None, username: str, password: str) -> dict:
    """Replace the login. Returns the public view of the new state."""
    name = (username or "").strip()
    secret = password or ""
    if not name or len(name) > 64:
        raise ValueError("username must be 1-64 characters")
    if not secret or len(secret) > 256:
        raise ValueError("password must be 1-256 characters")
    _atomic_write(credentials_path(base), _record(name, secret))
    return public(base)


def is_default(base: str | Path | None = None) -> bool:
    data = ensure_credentials(base)
    if str(data.get("username")) != DEFAULT_USERNAME:
        return False
    return verify(base, DEFAULT_USERNAME, DEFAULT_PASSWORD)


def public(base: str | Path | None = None) -> dict:
    data = ensure_credentials(base)
    return {
        "username": str(data.get("username", "")),
        "default": is_default(base),
        "source": str(credentials_path(base)),
    }
