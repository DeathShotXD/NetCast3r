"""Disposable inboxes for authorized account creation.

Bug bounty programs routinely require a confirmed account before an endpoint
can be tested. This module creates a mailbox through the mail.tm API, keeps the
credentials in a 0600 file under the NetCast3r base directory, and exposes
small primitives the agent runtime can call: list messages, read one, wait for
a verification mail, and pull the links out of it.

It is deliberately narrow. It does not send mail, does not touch a target, and
never returns the mailbox password or bearer token to an MCP client. Those
values stay in the local state file.
"""

from __future__ import annotations

import html as html_lib
import re
import secrets
import string
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import httpx

from .control import base_dir, read_private_json, write_private_json

DEFAULT_BASE_URL = "https://api.mail.tm"
GUERRILLA_URL = "https://api.guerrillamail.com/ajax.php"
PROVIDERS = ("mail.tm", "guerrillamail")
STORE_NAME = "mailboxes.json"
LOCAL_ALPHABET = string.ascii_lowercase + string.digits
LINK_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
TRAILING = ".,;:!?)]}>'\""


class MailError(RuntimeError):
    """A mailbox operation failed; the message is safe to show to an operator."""


@dataclass
class Mailbox:
    id: str
    address: str
    password: str = field(repr=False)
    token: str = field(repr=False)
    provider: str = "mail.tm"
    base_url: str = DEFAULT_BASE_URL
    label: str = ""
    created_at: float = 0.0

    def public(self) -> dict:
        return {
            "id": self.id,
            "address": self.address,
            "provider": self.provider,
            "label": self.label,
            "created_at": self.created_at,
        }

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "Mailbox | None":
        try:
            return cls(
                id=str(raw["id"]),
                address=str(raw["address"]),
                password=str(raw["password"]),
                token=str(raw.get("token") or ""),
                provider=str(raw.get("provider") or "mail.tm"),
                base_url=str(raw.get("base_url") or DEFAULT_BASE_URL),
                label=str(raw.get("label") or ""),
                created_at=float(raw.get("created_at") or 0),
            )
        except (KeyError, TypeError, ValueError):
            return None


def _store_path(base: str | Path | None = None) -> Path:
    return base_dir(base) / STORE_NAME


def _load(base: str | Path | None = None) -> list[Mailbox]:
    data = read_private_json(_store_path(base)) or {}
    boxes = []
    for raw in data.get("mailboxes") or []:
        if isinstance(raw, dict):
            box = Mailbox.from_dict(raw)
            if box:
                boxes.append(box)
    return boxes


def _save(boxes: list[Mailbox], base: str | Path | None = None) -> None:
    write_private_json(_store_path(base), {
        "version": 1,
        "mailboxes": [box.to_dict() for box in boxes],
    })


def list_mailboxes(base: str | Path | None = None) -> list[dict]:
    return [box.public() for box in _load(base)]


def get_mailbox(mailbox_id: str, base: str | Path | None = None) -> Mailbox | None:
    key = (mailbox_id or "").strip()
    for box in _load(base):
        if box.id == key or box.address == key:
            return box
    return None


def save_mailbox(box: Mailbox, base: str | Path | None = None) -> None:
    boxes = [item for item in _load(base) if item.id != box.id]
    boxes.append(box)
    _save(boxes, base)


def delete_mailbox(mailbox_id: str, base: str | Path | None = None) -> bool:
    boxes = _load(base)
    kept = [item for item in boxes if item.id != mailbox_id and item.address != mailbox_id]
    if len(kept) == len(boxes):
        return False
    _save(kept, base)
    return True


def _local_part(prefix: str) -> str:
    prefix = re.sub(r"[^a-z0-9]", "", (prefix or "nc3r").lower())[:8] or "nc3r"
    return prefix + "".join(secrets.choice(LOCAL_ALPHABET) for _ in range(10))


def _error(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        for key in ("message", "detail", "error"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:300]
        if isinstance(payload.get("hydra:description"), str):
            return payload["hydra:description"][:300]
    return (response.text or "").strip()[:300] or f"HTTP {response.status_code}"


class MailClient:
    """Thin mail.tm client with an injectable transport for tests."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 20.0,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport

    def _request(self, method: str, path: str, token: str = "",
                 json_body: dict | None = None) -> httpx.Response:
        headers = {"accept": "application/json"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        try:
            with httpx.Client(base_url=self.base_url, timeout=self.timeout,
                              transport=self.transport, trust_env=False) as client:
                return client.request(method, path, headers=headers, json=json_body)
        except httpx.HTTPError as exc:
            raise MailError(f"mail.tm request failed: {type(exc).__name__}") from exc

    def domains(self) -> list[str]:
        response = self._request("GET", "/domains")
        if response.status_code != 200:
            raise MailError(f"could not list mail domains: {_error(response)}")
        try:
            rows = response.json()
        except ValueError as exc:
            raise MailError("mail.tm returned an unreadable domain list") from exc
        if isinstance(rows, dict):
            rows = rows.get("hydra:member") or rows.get("domains") or []
        names = []
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("domain") and row.get("isActive", True):
                names.append(str(row["domain"]))
        if not names:
            raise MailError("mail.tm has no active domains right now")
        return names

    def create(self, base: str | Path | None = None, domain: str = "",
               prefix: str = "nc3r") -> Mailbox:
        domains = self.domains()
        chosen = (domain or "").strip().lower()
        if chosen and chosen not in domains:
            raise MailError(f"domain is not offered by mail.tm: {chosen}")
        chosen = chosen or domains[0]
        password = secrets.token_urlsafe(18)
        address = ""
        account_id = ""
        for _ in range(4):
            address = f"{_local_part(prefix)}@{chosen}"
            response = self._request(
                "POST", "/accounts",
                json_body={"address": address, "password": password})
            if response.status_code in (200, 201):
                try:
                    account_id = str(response.json().get("id") or "")
                except (ValueError, AttributeError):
                    account_id = ""
                break
            if response.status_code in (422, 400) and "exist" in _error(response).lower():
                continue
            raise MailError(f"could not create mailbox: {_error(response)}")
        if not account_id:
            raise MailError("mail.tm did not return an account id")
        token = self.token(address, password)
        box = Mailbox(id=account_id, address=address, password=password, token=token,
                      base_url=self.base_url, created_at=time.time())
        save_mailbox(box, base)
        return box

    def token(self, address: str, password: str) -> str:
        response = self._request(
            "POST", "/token", json_body={"address": address, "password": password})
        if response.status_code != 200:
            raise MailError(f"could not authenticate the mailbox: {_error(response)}")
        try:
            token = str(response.json().get("token") or "")
        except (ValueError, AttributeError):
            token = ""
        if not token:
            raise MailError("mail.tm did not return a mailbox token")
        return token

    def _refresh(self, box: Mailbox, base: str | Path | None) -> Mailbox:
        box.token = self.token(box.address, box.password)
        save_mailbox(box, base)
        return box

    def messages(self, box: Mailbox, base: str | Path | None = None,
                 page: int = 1) -> list[dict]:
        response = self._request("GET", f"/messages?page={max(1, int(page))}", token=box.token)
        if response.status_code == 401:
            self._refresh(box, base)
            response = self._request("GET", f"/messages?page={max(1, int(page))}",
                                     token=box.token)
        if response.status_code != 200:
            raise MailError(f"could not list the inbox: {_error(response)}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise MailError("mail.tm returned an unreadable inbox") from exc
        if isinstance(payload, dict):
            rows = payload.get("hydra:member") or payload.get("messages") or []
        else:
            rows = payload
        return [self._summary(row) for row in rows if isinstance(row, dict)]

    @staticmethod
    def _summary(raw: dict) -> dict:
        sender = raw.get("from") or {}
        if not isinstance(sender, dict):
            sender = {"address": str(sender)}
        return {
            "id": str(raw.get("id") or ""),
            "from": str(sender.get("address") or ""),
            "from_name": str(sender.get("name") or ""),
            "subject": str(raw.get("subject") or ""),
            "intro": str(raw.get("intro") or ""),
            "created_at": str(raw.get("createdAt") or ""),
            "seen": bool(raw.get("seen")),
        }

    def read(self, box: Mailbox, message_id: str, base: str | Path | None = None) -> dict:
        response = self._request("GET", f"/messages/{message_id}", token=box.token)
        if response.status_code == 401:
            self._refresh(box, base)
            response = self._request("GET", f"/messages/{message_id}", token=box.token)
        if response.status_code != 200:
            raise MailError(f"could not read the message: {_error(response)}")
        try:
            raw = response.json()
        except ValueError as exc:
            raise MailError("mail.tm returned an unreadable message") from exc
        if not isinstance(raw, dict):
            raise MailError("mail.tm returned an unexpected message shape")
        sender = raw.get("from") or {}
        if not isinstance(sender, dict):
            sender = {"address": str(sender)}
        body_html = raw.get("html")
        if isinstance(body_html, list):
            body_html = "\n".join(str(part) for part in body_html)
        text = str(raw.get("text") or "")
        html = str(body_html or "")
        message = {
            "id": str(raw.get("id") or message_id),
            "from": str(sender.get("address") or ""),
            "from_name": str(sender.get("name") or ""),
            "to": [str(item.get("address") if isinstance(item, dict) else item)
                   for item in (raw.get("to") or [])],
            "subject": str(raw.get("subject") or ""),
            "created_at": str(raw.get("createdAt") or ""),
            "text": text[:20000],
            "html": html[:20000],
            "attachments": [str(item.get("filename") if isinstance(item, dict) else item)
                            for item in (raw.get("attachments") or [])],
        }
        message["links"] = extract_links(message)
        return message

    def wait(self, box: Mailbox, base: str | Path | None = None, timeout: float = 180.0,
             interval: float = 4.0, match: str = "", since_id: str = "") -> dict | None:
        """Poll until a matching message arrives or the timeout expires.

        Only mail that arrives after the call starts is considered unless
        ``since_id`` is supplied; that keeps a wait from returning an old
        message the caller has already triaged.
        """
        timeout = max(5.0, min(float(timeout), 300.0))
        interval = max(2.0, min(float(interval), 30.0))
        needle = (match or "").strip().lower()
        seen: set[str] = set()
        deadline = time.monotonic() + timeout
        baseline: set[str] | None = None
        while time.monotonic() < deadline:
            rows = self.messages(box, base)
            if baseline is None:
                baseline = {row["id"] for row in rows}
            for row in rows:
                if row["id"] in seen:
                    continue
                seen.add(row["id"])
                if not since_id and baseline and row["id"] in baseline:
                    continue
                if needle:
                    haystack = " ".join(str(row.get(key) or "") for key in
                                        ("subject", "from", "intro")).lower()
                    if needle not in haystack:
                        continue
                message = self.read(box, row["id"], base)
                if needle and needle not in (message.get("text") or "").lower() \
                        and needle not in (message.get("subject") or "").lower():
                    continue
                return message
            time.sleep(interval)
        return None


class GuerrillaClient:
    """GuerrillaMail adapter with the same small surface as MailClient.

    GuerrillaMail has no password: the session id returned at creation is the
    credential. It is stored in the sealed mailbox record and never returned.
    """

    provider = "guerrillamail"

    def __init__(self, timeout: float = 20.0,
                 transport: httpx.BaseTransport | None = None):
        self.timeout = timeout
        self.transport = transport

    def _get(self, **params) -> dict:
        query = {"lang": "en", **params}
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport,
                              trust_env=False) as client:
                response = client.get(GUERRILLA_URL, params=query)
        except httpx.HTTPError as exc:
            raise MailError(f"guerrillamail request failed: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise MailError(f"guerrillamail returned HTTP {response.status_code}: "
                            f"{response.text[:200]}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise MailError("guerrillamail returned unreadable JSON") from exc
        if not isinstance(payload, dict):
            raise MailError("guerrillamail returned an unexpected shape")
        return payload

    def create(self, base: str | Path | None = None, domain: str = "",
               prefix: str = "nc3r") -> Mailbox:
        created = self._get(f="get_email_address")
        address = str(created.get("email_addr") or "")
        token = str(created.get("sid_token") or "")
        if not address or not token:
            raise MailError("guerrillamail did not return a mailbox")
        local = re.sub(r"[^a-z0-9]", "", (prefix or "nc3r").lower())[:10] or "nc3r"
        local += "".join(secrets.choice(LOCAL_ALPHABET) for _ in range(6))
        renamed = self._get(f="set_email_user", email_user=local, sid_token=token)
        address = str(renamed.get("email_addr") or address)
        box = Mailbox(id=address, address=address, password="", token=token,
                      provider=self.provider, base_url=GUERRILLA_URL,
                      created_at=time.time())
        save_mailbox(box, base)
        return box

    def messages(self, box: Mailbox, base: str | Path | None = None,
                 page: int = 1) -> list[dict]:
        payload = self._get(f="get_email_list", offset=max(0, (int(page) - 1) * 20),
                            sid_token=box.token)
        rows = payload.get("list") or []
        items = []
        for raw in rows if isinstance(rows, list) else []:
            if not isinstance(raw, dict):
                continue
            stamp = raw.get("mail_timestamp")
            try:
                created = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(float(stamp))) if stamp else ""
            except (TypeError, ValueError, OSError):
                created = ""
            items.append({
                "id": str(raw.get("mail_id") or ""),
                "from": str(raw.get("mail_from") or ""),
                "from_name": "",
                "subject": str(raw.get("mail_subject") or ""),
                "intro": str(raw.get("mail_excerpt") or ""),
                "created_at": created,
                "seen": str(raw.get("mail_read") or "0") != "0",
            })
        return items

    def read(self, box: Mailbox, message_id: str, base: str | Path | None = None) -> dict:
        raw = self._get(f="fetch_email", email_id=message_id, sid_token=box.token)
        body_html = str(raw.get("mail_body") or "")
        text = re.sub(r"<[^>]+>", " ", body_html)
        text = html_lib.unescape(re.sub(r"\s+", " ", text)).strip()
        try:
            created = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                    time.gmtime(float(raw.get("mail_timestamp"))))
        except (TypeError, ValueError, OSError):
            created = ""
        message = {
            "id": str(raw.get("mail_id") or message_id),
            "from": str(raw.get("mail_from") or ""),
            "from_name": "",
            "to": [box.address],
            "subject": str(raw.get("mail_subject") or ""),
            "created_at": created,
            "text": text[:20000],
            "html": body_html[:20000],
            "attachments": [],
        }
        message["links"] = extract_links(message)
        return message

    def wait(self, box: Mailbox, base: str | Path | None = None, timeout: float = 180.0,
             interval: float = 4.0, match: str = "", since_id: str = "") -> dict | None:
        timeout = max(5.0, min(float(timeout), 300.0))
        interval = max(2.0, min(float(interval), 30.0))
        needle = (match or "").strip().lower()
        deadline = time.monotonic() + timeout
        baseline = {row["id"] for row in self.messages(box, base)}
        seen: set[str] = set()
        while time.monotonic() < deadline:
            for row in self.messages(box, base):
                if row["id"] in seen:
                    continue
                seen.add(row["id"])
                if not since_id and row["id"] in baseline:
                    continue
                haystack = " ".join(str(row.get(key) or "")
                                    for key in ("subject", "from", "intro")).lower()
                if needle and needle not in haystack:
                    continue
                message = self.read(box, row["id"], base)
                if needle and needle not in (message.get("text") or "").lower() \
                        and needle not in (message.get("subject") or "").lower():
                    continue
                return message
            time.sleep(interval)
        return None


def client_for(box: Mailbox):
    if (box.provider or "").lower() == "guerrillamail":
        return GuerrillaClient()
    return MailClient(base_url=box.base_url)


def create_mailbox(base: str | Path | None = None, domain: str = "",
                   prefix: str = "nc3r", base_url: str = DEFAULT_BASE_URL,
                   timeout: float = 20.0,
                   transport: httpx.BaseTransport | None = None,
                   provider: str = "mail.tm") -> Mailbox:
    name = (provider or "mail.tm").strip().lower()
    if name == "guerrillamail":
        return GuerrillaClient(timeout=timeout, transport=transport).create(
            base=base, domain=domain, prefix=prefix)
    return MailClient(base_url=base_url, timeout=timeout, transport=transport).create(
        base=base, domain=domain, prefix=prefix)


def extract_links(message: dict) -> list[str]:
    """Pull http(s) links out of a message, in the order they appear."""
    chunks = [str(message.get("text") or ""), str(message.get("html") or "")]
    found: list[str] = []
    seen: set[str] = set()
    for chunk in chunks:
        text = html_lib.unescape(chunk)
        for match in LINK_RE.finditer(text):
            link = match.group(0).rstrip(TRAILING)
            if link and link not in seen:
                seen.add(link)
                found.append(link)
    return found
