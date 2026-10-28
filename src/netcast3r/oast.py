"""Out-of-band callbacks for blind vulnerability testing.

A unique HTTPS URL is created on a callback service; the target is asked to
reach it (SSRF, blind XSS, OAST in an XML parser, a webhook field). The agent
then polls the service and reads what actually arrived: method, path, query,
headers, body, and source address.

webhook.site is the default because it needs no account and gives a unique
endpoint per token. ``NETCAST3R_OAST_BASE`` points the client at a self-hosted
webhook.site-compatible instance. Sessions are stored in a 0600 file.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .control import base_dir, read_private_json, write_private_json

DEFAULT_BASE_URL = "https://webhook.site"
STORE_NAME = "oast.json"
BODY_LIMIT = 8192


class OastError(RuntimeError):
    """A callback operation failed; the message is safe to show to an operator."""


@dataclass
class OastSession:
    id: str
    provider: str
    token: str = field(repr=False)
    url: str
    label: str = ""
    created_at: float = 0.0
    base_url: str = DEFAULT_BASE_URL

    def public(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider,
            "url": self.url,
            "label": self.label,
            "created_at": self.created_at,
        }

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "OastSession | None":
        try:
            return cls(
                id=str(raw["id"]),
                provider=str(raw.get("provider") or "webhook.site"),
                token=str(raw["token"]),
                url=str(raw["url"]),
                label=str(raw.get("label") or ""),
                created_at=float(raw.get("created_at") or 0),
                base_url=str(raw.get("base_url") or DEFAULT_BASE_URL),
            )
        except (KeyError, TypeError, ValueError):
            return None


def _store_path(base: str | Path | None = None) -> Path:
    return base_dir(base) / STORE_NAME


def _load(base: str | Path | None = None) -> list[OastSession]:
    data = read_private_json(_store_path(base)) or {}
    sessions = []
    for raw in data.get("sessions") or []:
        if isinstance(raw, dict):
            session = OastSession.from_dict(raw)
            if session:
                sessions.append(session)
    return sessions


def _save(sessions: list[OastSession], base: str | Path | None = None) -> None:
    write_private_json(_store_path(base), {
        "version": 1,
        "sessions": [session.to_dict() for session in sessions],
    })


def list_sessions(base: str | Path | None = None) -> list[dict]:
    return [session.public() for session in _load(base)]


def get_session(session_id: str, base: str | Path | None = None) -> OastSession | None:
    key = (session_id or "").strip()
    for session in _load(base):
        if session.id == key:
            return session
    return None


def delete_session(session_id: str, base: str | Path | None = None) -> bool:
    sessions = _load(base)
    kept = [item for item in sessions if item.id != session_id]
    if len(kept) == len(sessions):
        return False
    _save(kept, base)
    return True


def _error(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        for key in ("message", "error", "detail"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:300]
    return (response.text or "").strip()[:300] or f"HTTP {response.status_code}"


class OastClient:
    """webhook.site-compatible client with an injectable transport for tests."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 20.0,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport

    def _request(self, method: str, path: str,
                 json_body: dict | None = None) -> httpx.Response:
        try:
            with httpx.Client(base_url=self.base_url, timeout=self.timeout,
                              transport=self.transport, trust_env=False) as client:
                return client.request(method, path, json=json_body)
        except httpx.HTTPError as exc:
            raise OastError(f"callback service request failed: {type(exc).__name__}") from exc

    def create(self, base: str | Path | None = None, label: str = "") -> OastSession:
        response = self._request("POST", "/token", json_body={})
        if response.status_code not in (200, 201):
            raise OastError(f"could not create a callback endpoint: {_error(response)}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OastError("callback service returned an unreadable response") from exc
        token = str((payload or {}).get("uuid") or (payload or {}).get("token") or "")
        url = str((payload or {}).get("url") or "")
        if not token or not url:
            raise OastError("callback service did not return a token and url")
        session = OastSession(
            id=token,
            provider="webhook.site",
            token=token,
            url=url,
            label=(label or "").strip()[:120],
            created_at=time.time(),
            base_url=self.base_url,
        )
        sessions = [item for item in _load(base) if item.id != session.id]
        sessions.append(session)
        _save(sessions, base)
        return session

    def poll(self, session: OastSession, base: str | Path | None = None,
             since: float | None = None, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        response = self._request(
            "GET", f"/token/{session.token}/requests?sorting=newest&per_page={limit}")
        if response.status_code != 200:
            raise OastError(f"could not read callbacks: {_error(response)}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OastError("callback service returned an unreadable request list") from exc
        rows = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            rows = []
        items = [self._normalize(row) for row in rows if isinstance(row, dict)]
        if since:
            items = [item for item in items if (item.get("created_at") or 0) >= since]
        items.sort(key=lambda item: item.get("created_at") or 0, reverse=True)
        return items[:limit]

    @staticmethod
    def _normalize(raw: dict) -> dict:
        url = str(raw.get("url") or "")
        parts = urlsplit(url)
        headers = raw.get("headers") or {}
        if isinstance(headers, list):
            headers = {str(row.get("name") or ""): str(row.get("value") or "")
                       for row in headers if isinstance(row, dict)}
        content = raw.get("content")
        if isinstance(content, (dict, list)):
            content = json.dumps(content, ensure_ascii=False)
        body = str(content or "")
        created = _timestamp(raw.get("created_at") or raw.get("created") or 0)
        return {
            "id": str(raw.get("uuid") or raw.get("id") or ""),
            "method": str(raw.get("method") or "").upper(),
            "path": parts.path or "/",
            "query": raw.get("query") if isinstance(raw.get("query"), dict) else {},
            "headers": {str(key): str(value) for key, value in headers.items()},
            "body": body[:BODY_LIMIT],
            "ip": str(raw.get("ip") or ""),
            "user_agent": str(raw.get("user_agent") or ""),
            "created_at": created,
        }

    def delete(self, session: OastSession, base: str | Path | None = None) -> bool:
        response = self._request("DELETE", f"/token/{session.token}")
        if response.status_code not in (200, 204, 404):
            raise OastError(f"could not delete the callback endpoint: {_error(response)}")
        delete_session(session.id, base)
        return response.status_code in (200, 204)


def create_session(base: str | Path | None = None, label: str = "",
                   base_url: str = DEFAULT_BASE_URL, timeout: float = 20.0,
                   transport: httpx.BaseTransport | None = None) -> OastSession:
    return OastClient(base_url=base_url, timeout=timeout, transport=transport).create(
        base=base, label=label)


def _timestamp(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        return float(text)
    except ValueError:
        pass
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()
