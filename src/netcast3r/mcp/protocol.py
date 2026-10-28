"""JSON-RPC 2.0 and MCP framing over stdio.

MCP's stdio transport is newline-delimited JSON-RPC. A few clients still use
the older ``Content-Length`` framing, so the reader accepts both; the writer
emits the newline form the current specification and OpenCode use.

The protocol layer knows nothing about NetCast3r. It validates envelopes,
dispatches methods, and turns exceptions into correct JSON-RPC errors.
"""

from __future__ import annotations

import json
from typing import BinaryIO, Callable

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
LATEST_PROTOCOL = PROTOCOL_VERSIONS[0]

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class RpcError(Exception):
    def __init__(self, code: int, message: str, data=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def as_dict(self, request_id=None) -> dict:
        error = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


class ParseError(Exception):
    pass


def _decode(raw) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def read_message(stream: BinaryIO) -> dict | None:
    """Read one JSON-RPC message.

    Returns ``None`` at clean EOF. Raises :class:`ParseError` for malformed
    input so the dispatcher can answer with ``-32700`` instead of dying.
    """
    while True:
        line = stream.readline()
        if not line:
            return None
        text = _decode(line).strip()
        if not text:
            continue
        if text.lower().startswith("content-length:"):
            try:
                length = int(text.split(":", 1)[1].strip())
            except ValueError as exc:
                raise ParseError("bad Content-Length") from exc
            while True:
                header = stream.readline()
                if not header:
                    raise ParseError("truncated headers")
                if _decode(header).strip() == "":
                    break
            body = stream.read(length)
            if len(body) != length:
                raise ParseError("truncated body")
            return _loads(_decode(body))
        return _loads(text)


def _loads(text: str) -> dict:
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise ParseError("invalid JSON") from exc
    if not isinstance(value, dict):
        raise ParseError("JSON-RPC message must be an object")
    return value


def write_message(stream: BinaryIO, message: dict) -> None:
    payload = json.dumps(message, separators=(",", ":"), default=str)
    stream.write((payload + "\n").encode("utf-8"))
    stream.flush()


def validate_envelope(message: dict) -> tuple[str, dict]:
    """Return ``(method, params)`` or raise an invalid-request error."""
    if message.get("jsonrpc") != "2.0":
        raise RpcError(INVALID_REQUEST, "jsonrpc must be '2.0'")
    method = message.get("method")
    if not isinstance(method, str) or not method:
        raise RpcError(INVALID_REQUEST, "method required")
    params = message.get("params") or {}
    if not isinstance(params, dict):
        raise RpcError(INVALID_PARAMS, "params must be an object")
    return method, params


def response(request_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id, error: RpcError) -> dict:
    return error.as_dict(request_id)


class Dispatcher:
    """A tiny method table with one guardrail: handlers never see bad params."""

    def __init__(self):
        self._methods: dict[str, Callable[[dict], dict]] = {}

    def method(self, name: str):
        def register(func):
            self._methods[name] = func
            return func
        return register

    def dispatch(self, message: dict) -> dict | None:
        request_id = message.get("id")
        is_notification = "id" not in message
        try:
            method, params = validate_envelope(message)
            handler = self._methods.get(method)
            if handler is None:
                raise RpcError(METHOD_NOT_FOUND, f"method not found: {method}")
            result = handler(params)
            if is_notification:
                return None
            return response(request_id, result if isinstance(result, dict) else {})
        except RpcError as exc:
            if is_notification:
                return None
            return error_response(request_id, exc)
        except Exception as exc:  # noqa: BLE001 - protocol boundary
            if is_notification:
                return None
            return error_response(request_id, RpcError(
                INTERNAL_ERROR, "internal error", f"{type(exc).__name__}: {exc}"))
