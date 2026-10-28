"""Named session material for authenticated testing.

An auth profile is a label plus the headers and cookies of one logged-in
session. Every value is kept in a 0600 file under the NetCast3r base directory
and is never returned by a listing call; the HTTP tool reads it by name.

The profile is deliberately not a browser: it holds exactly what an operator
or an approved agent captured. It cannot mint credentials on its own.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .control import base_dir, read_private_json, write_private_json

STORE_NAME = "auth-profiles.json"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
MAX_VALUE = 8192


class AuthError(RuntimeError):
    """An auth profile was rejected or missing."""


@dataclass
class AuthProfile:
    name: str
    headers: dict = field(default_factory=dict, repr=False)
    cookies: dict = field(default_factory=dict, repr=False)
    note: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

    def public(self) -> dict:
        return {
            "name": self.name,
            "header_names": sorted(self.headers),
            "cookie_names": sorted(self.cookies),
            "note": self.note,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_dict(self) -> dict:
        return asdict(self)

    def request_headers(self) -> dict:
        headers = dict(self.headers)
        if self.cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in self.cookies.items())
        return headers

    @classmethod
    def from_dict(cls, raw: dict) -> "AuthProfile | None":
        try:
            return cls(
                name=str(raw["name"]),
                headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
                cookies={str(k): str(v) for k, v in (raw.get("cookies") or {}).items()},
                note=str(raw.get("note") or ""),
                created_at=float(raw.get("created_at") or 0),
                updated_at=float(raw.get("updated_at") or 0),
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None


def _store_path(base: str | Path | None = None) -> Path:
    return base_dir(base) / STORE_NAME


def _load(base: str | Path | None = None) -> list[AuthProfile]:
    data = read_private_json(_store_path(base)) or {}
    profiles = []
    for raw in data.get("profiles") or []:
        if isinstance(raw, dict):
            profile = AuthProfile.from_dict(raw)
            if profile:
                profiles.append(profile)
    return profiles


def _save(profiles: list[AuthProfile], base: str | Path | None = None) -> None:
    write_private_json(_store_path(base), {
        "version": 1,
        "profiles": [profile.to_dict() for profile in profiles],
    })


def list_profiles(base: str | Path | None = None) -> list[dict]:
    return [profile.public() for profile in _load(base)]


def get_profile(name: str, base: str | Path | None = None) -> AuthProfile | None:
    key = (name or "").strip()
    for profile in _load(base):
        if profile.name == key:
            return profile
    return None


def _clean_pairs(pairs, label: str, name_re: re.Pattern, forbid: str) -> dict:
    if pairs is None:
        return {}
    if not isinstance(pairs, dict):
        raise AuthError(f"{label} must be an object of name/value strings")
    clean: dict[str, str] = {}
    size = 0
    for raw_name, raw_value in pairs.items():
        name = str(raw_name).strip()
        value = str(raw_value)
        if not name or not name_re.match(name):
            raise AuthError(f"invalid {label} name: {name[:40]!r}")
        if "\r" in name or "\n" in name:
            raise AuthError(f"{label} name contains a newline")
        if any(char in value for char in forbid):
            raise AuthError(f"{label} value for {name} contains a forbidden character")
        size += len(name) + len(value)
        if size > MAX_VALUE:
            raise AuthError(f"{label} are too large")
        clean[name] = value
    return clean


def set_profile(name: str, headers: dict | None = None, cookies: dict | None = None,
                note: str = "", base: str | Path | None = None) -> dict:
    label = (name or "").strip()
    if not NAME_RE.match(label):
        raise AuthError("profile name must be 1-64 characters of letters, digits, "
                        "dot, dash, or underscore")
    clean_headers = _clean_pairs(headers, "headers", HEADER_NAME_RE, "\r\n")
    clean_cookies = _clean_pairs(cookies, "cookies", COOKIE_NAME_RE, ";\r\n")
    if not clean_headers and not clean_cookies:
        raise AuthError("a profile needs at least one header or cookie")
    now = time.time()
    existing = get_profile(label, base)
    profile = AuthProfile(
        name=label,
        headers=clean_headers,
        cookies=clean_cookies,
        note=(note or "").strip()[:500],
        created_at=existing.created_at if existing else now,
        updated_at=now,
    )
    profiles = [item for item in _load(base) if item.name != label]
    profiles.append(profile)
    _save(profiles, base)
    return profile.public()


def delete_profile(name: str, base: str | Path | None = None) -> bool:
    profiles = _load(base)
    kept = [item for item in profiles if item.name != name]
    if len(kept) == len(profiles):
        return False
    _save(kept, base)
    return True


def from_storage_state(path: str | Path, name: str,
                       domain: str = "", base: str | Path | None = None) -> dict:
    """Import cookies from a Playwright storage-state JSON file."""
    try:
        data = json.loads(Path(path).expanduser().read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise AuthError(f"could not read the storage state: {type(exc).__name__}") from exc
    cookies: dict[str, str] = {}
    suffix = (domain or "").strip().lower().lstrip(".")
    for row in data.get("cookies") or []:
        if not isinstance(row, dict) or not row.get("name"):
            continue
        cookie_domain = str(row.get("domain") or "").lower().lstrip(".")
        if suffix and not (cookie_domain == suffix or cookie_domain.endswith("." + suffix)):
            continue
        cookies[str(row["name"])] = str(row.get("value") or "")
    if not cookies:
        raise AuthError("the storage state held no matching cookies")
    return set_profile(name, cookies=cookies, base=base,
                       note=f"imported from {Path(path).name}")
