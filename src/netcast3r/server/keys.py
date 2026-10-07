"""Local secret storage.

A pasted key never lands in the database and never lands in a log line. Values
go to the OS keyring when one is actually usable, otherwise to a 0600 file
under ~/.netcast3r. Reads always return a masked value plus where the key came
from. A keyring that is present but locked is treated as absent, so the tool
never hangs on a headless machine.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

try:  # optional, only used when a usable keyring backend exists
    import keyring  # type: ignore
except Exception:  # pragma: no cover - import guard
    keyring = None

SERVICE = "netcast3r"


def mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


class KeyStore:
    def __init__(self, base: Path | None = None):
        self.base = Path(base) if base else Path.home() / ".netcast3r"
        self.path = self.base / "secrets.json"
        self._use_keyring = self._keyring_ready()

    def _keyring_ready(self) -> bool:
        if keyring is None or os.environ.get("NETCAST3R_NO_KEYRING"):
            return False
        result = {"ok": False}

        def probe() -> None:
            try:
                keyring.get_password(SERVICE, "__probe__")  # type: ignore[union-attr]
                result["ok"] = True
            except Exception:
                result["ok"] = False

        # A locked or unreachable backend can block forever; never wait on it.
        thread = threading.Thread(target=probe, daemon=True)
        thread.start()
        thread.join(timeout=1.0)
        return result["ok"] and not thread.is_alive()

    # -- file ------------------------------------------------------------
    def _read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except (ValueError, OSError):
            return {}

    def _write(self, data: dict) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    # -- api -------------------------------------------------------------
    def set(self, name: str, value: str) -> None:
        stored = False
        if self._use_keyring:
            try:
                keyring.set_password(SERVICE, name, value)  # type: ignore[union-attr]
                stored = True
            except Exception:
                self._use_keyring = False
        data = self._read()
        entry = {"source": "keyring" if stored else "file", "updated_at": time.time()}
        if not stored:
            entry["value"] = value
        data.setdefault("keys", {})[name] = entry
        self._write(data)

    def get(self, name: str) -> str:
        if self._use_keyring:
            try:
                value = keyring.get_password(SERVICE, name)  # type: ignore[union-attr]
                if value:
                    return value
            except Exception:
                self._use_keyring = False
        entry = (self._read().get("keys") or {}).get(name)
        if entry and "value" in entry:
            return entry["value"]
        return ""

    def delete(self, name: str) -> bool:
        if self._use_keyring:
            try:
                keyring.delete_password(SERVICE, name)  # type: ignore[union-attr]
            except Exception:
                self._use_keyring = False
        data = self._read()
        removed = (data.get("keys") or {}).pop(name, None) is not None
        if removed:
            self._write(data)
        return removed

    def has(self, name: str) -> bool:
        return bool(self.get(name))

    def listing(self) -> list[dict]:
        data = self._read()
        rows = []
        for name in sorted(data.get("keys") or {}):
            rows.append({"name": name, "masked": mask(self.get(name)),
                         "source": (data["keys"][name] or {}).get("source", "file")})
        return rows

    def resolve(self, name: str, env_name: str = "") -> tuple[str, str]:
        """Return (value, source) using the highest priority source available."""
        value = self.get(name)
        if value:
            return value, "keyring" if self._use_keyring else "file"
        if env_name:
            env_value = os.environ.get(env_name, "")
            if env_value:
                return env_value, "env"
        return "", ""


def redact(text: str, extra: list[str] | None = None) -> str:
    """Scrub anything that looks like a known key shape before it is logged."""
    import re

    patterns = [
        r"sk-[A-Za-z0-9_\-]{16,}", r"sk_live_[A-Za-z0-9]{10,}", r"rk_live_[A-Za-z0-9]{10,}",
        r"AIza[0-9A-Za-z_\-]{20,}", r"xox[baprs]-[A-Za-z0-9\-]{10,}", r"gh[pousr]_[A-Za-z0-9]{20,}",
        r"github_pat_[A-Za-z0-9_]{20,}", r"glpat-[A-Za-z0-9_\-]{16,}", r"AKIA[0-9A-Z]{16}",
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}",
    ]
    for value in (extra or []):
        if value and len(value) >= 8:
            text = text.replace(value, mask(value))
    for pattern in patterns:
        text = re.sub(pattern, lambda m: mask(m.group(0)), text)
    return text
