"""Control-plane transports for the MCP server.

The MCP process does not own the workspace. It drives the same local HTTP API
the Svelte UI uses, so a scan started by an agent appears in the dashboard,
and a human decision in the dashboard is visible to the agent. When no UI is
running, an embedded control plane provides the identical surface in-process.

Auto mode is deliberately boring: discover the running UI, prove it is alive,
use it. Otherwise fall back to embedded and say so on stderr.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .. import control

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


class PlaneError(Exception):
    def __init__(self, message: str, status: int = 0, detail: str = ""):
        super().__init__(message)
        self.status = status
        self.detail = detail


def _note(message: str) -> None:
    print(f"netcast3r mcp: {message}", file=sys.stderr, flush=True)


def _allowed_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in {"http", "https"}:
        return False
    host = (parts.hostname or "").lower()
    if host in LOCAL_HOSTS:
        return True
    return os.environ.get("NETCAST3R_MCP_ALLOW_REMOTE") == "1"


def _query_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class ApiPlane:
    kind = "api"

    def __init__(self, url: str, token: str = "", timeout: float = 30.0,
                 base: Path | None = None):
        url = url.rstrip("/")
        if not _allowed_url(url):
            raise PlaneError(
                "refusing a non-local control plane",
                0,
                "set NETCAST3R_MCP_ALLOW_REMOTE=1 only for a host you control",
            )
        self.url = url
        self.token = token
        self.base = base
        self._client = httpx.Client(
            base_url=url, timeout=timeout, trust_env=False,
            headers={"x-netcast3r-token": token, "accept": "application/json"},
        )

    def _refresh_token(self) -> bool:
        """Pick up a new token after the UI restarts on the same URL."""
        state = control.read_control_plane(self.base)
        if not state or not state.get("token"):
            return False
        if str(state.get("url") or "").rstrip("/") != self.url:
            return False
        token = str(state["token"])
        if token == self.token:
            return False
        self.token = token
        self._client.headers["x-netcast3r-token"] = token
        return True

    def request(self, method: str, path: str, query: dict | None = None, body=None):
        params = {key: _query_value(value) for key, value in (query or {}).items()
                  if value is not None and value != ""}
        kwargs = {"params": params}
        if body is not None:
            kwargs["json"] = body
        try:
            response = self._client.request(method, path, **kwargs)
            if response.status_code == 401 and self._refresh_token():
                response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise PlaneError(f"control plane unreachable: {type(exc).__name__}", 0, str(exc))
        content_type = response.headers.get("content-type", "")
        if response.status_code >= 400:
            title, detail = f"HTTP {response.status_code}", ""
            try:
                problem = response.json()
                title = str(problem.get("title") or title)
                detail = str(problem.get("detail") or "")
            except ValueError:
                detail = response.text[:500]
            raise PlaneError(title, response.status_code, detail)
        if "json" in content_type:
            try:
                return response.json()
            except ValueError as exc:
                raise PlaneError("control plane returned invalid JSON", 502, str(exc))
        return {"text": response.text, "content_type": content_type}

    def close(self) -> None:
        self._client.close()


class EmbeddedPlane:
    kind = "embedded"

    def __init__(self, base: Path | None = None, results_dir: str = "results", runner=None):
        from ..server import build_server

        self.base = control.base_dir(base)
        self.server = build_server(results_dir=results_dir, base=self.base, runner=runner,
                                   recover=False)
        self.url = ""
        self._token = self.server.token

    def request(self, method: str, path: str, query: dict | None = None, body=None):
        raw = b""
        if body is not None:
            raw = json.dumps(body, default=str).encode("utf-8")
        headers = {"host": "127.0.0.1", "x-netcast3r-token": self._token}
        response = self.server.route(method, path, dict(query or {}), headers, raw)
        if hasattr(response, "frames"):
            raise PlaneError("streaming endpoints are not available through the embedded plane")
        if response.status >= 400:
            title, detail = f"HTTP {response.status}", ""
            try:
                problem = json.loads(response.body.decode("utf-8"))
                title = str(problem.get("title") or title)
                detail = str(problem.get("detail") or "")
            except (ValueError, UnicodeDecodeError):
                detail = response.body[:500].decode("utf-8", "replace")
            raise PlaneError(title, response.status, detail)
        text = response.body.decode("utf-8", "replace")
        if "json" in (response.content_type or ""):
            try:
                return json.loads(text)
            except ValueError as exc:
                raise PlaneError("embedded plane returned invalid JSON", 502, str(exc))
        return {"text": text, "content_type": response.content_type}

    def close(self) -> None:
        try:
            runtime = getattr(self.server, "agent_runtime", None)
            if runtime is not None:
                runtime.shutdown()
            labs = getattr(self.server, "lab_runner", None)
            if labs is not None:
                labs.shutdown(wait=False)
            self.server.jobs.shutdown(wait=False)
        finally:
            self.server.index.close()


def discover(base: Path | None, api_url: str = "", token: str = "") -> tuple[str, str] | None:
    """Resolve an API endpoint from explicit flags, environment, or state file."""
    url = (api_url or os.environ.get("NETCAST3R_API_URL") or "").strip()
    resolved_token = (token or os.environ.get("NETCAST3R_API_TOKEN") or "").strip()
    if url:
        return url, resolved_token
    state = control.read_control_plane(base)
    if state and state.get("url"):
        if state.get("token") and not resolved_token:
            resolved_token = str(state["token"])
        return str(state["url"]), resolved_token
    return None


def _probe(url: str, token: str) -> bool:
    try:
        client = httpx.Client(base_url=url.rstrip("/"), timeout=2.5, trust_env=False,
                              headers={"x-netcast3r-token": token})
        try:
            response = client.get("/api/v1/healthz")
            return response.status_code == 200
        finally:
            client.close()
    except httpx.HTTPError:
        return False


def build_plane(backend: str = "auto", base: Path | None = None,
                results_dir: str = "results", api_url: str = "", token: str = "",
                runner=None):
    backend = (backend or "auto").strip().lower()
    if backend not in {"auto", "api", "embedded"}:
        raise PlaneError(f"unknown backend: {backend}")
    if backend in {"auto", "api"}:
        found = discover(base, api_url, token)
        if found:
            url, resolved = found
            if _probe(url, resolved):
                return ApiPlane(url, resolved, base=base)
            if backend == "api":
                raise PlaneError(f"control plane did not answer at {url}")
            _note(f"no control plane at {url}; starting an embedded one")
        elif backend == "api":
            raise PlaneError("no control plane URL was supplied or discovered")
    return EmbeddedPlane(base=base, results_dir=results_dir, runner=runner)
