"""MCP server whose tools/call handler only forwards to the gateway.

Tool definitions are names. A callable, or a definition that carries a handler,
is rejected. An unlisted name is an error and is not executed locally.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from agentshield_sdk.errors import ApprovalRequired, Denied, ExecuteResult, GatewayError
from agentshield_sdk.jsonenc import encode_json

PROTOCOL_VERSION = "2024-11-05"
MAX_MESSAGE_BYTES = 1 << 20


class GatewayMCPServer:
    def __init__(self, client: Any, tools: list[str] | tuple[str, ...]) -> None:
        if not callable(getattr(client, "call_tool", None)):
            raise TypeError("client must send tool calls through the gateway")
        names: list[str] = []
        for tool in tools:
            if not isinstance(tool, str) or tool == "":
                raise TypeError("MCP tools must be names forwarded to the gateway")
            names.append(tool)
        self._client = client
        self._tools = tuple(names)

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return _failure(message.get("id"), -32600, "invalid request")
        method = message["method"]
        if "id" not in message:
            return None
        request_id = message.get("id")
        if method == "initialize":
            return _success(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "agentshield-gateway", "version": "0.1.0"},
                },
            )
        if method == "tools/list":
            return _success(request_id, {"tools": [_descriptor(name) for name in self._tools]})
        if method == "ping":
            return _success(request_id, {})
        if method == "tools/call":
            return self._call(request_id, message.get("params"))
        return _failure(request_id, -32601, "method not found")

    def _call(self, request_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict):
            return _failure(request_id, -32602, "invalid params")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or name not in self._tools:
            return _failure(request_id, -32602, "unknown tool")
        if not isinstance(arguments, dict):
            return _failure(request_id, -32602, "invalid params")
        payload = dict(arguments)
        resource = payload.pop("resource", None)
        if not isinstance(resource, str) or resource == "":
            return _failure(request_id, -32602, "resource is required")
        operation = payload.pop("operation", name)
        if not isinstance(operation, str) or operation == "":
            return _failure(request_id, -32602, "operation is empty")
        try:
            executed = self._client.call_tool(
                tool_name=name,
                operation=operation,
                resource=resource,
                arguments=payload,
            )
        except (Denied, ApprovalRequired, GatewayError) as exc:
            return _success(request_id, _tool_result(_error_text(exc), is_error=True))
        if not isinstance(executed, ExecuteResult):
            raise TypeError("gateway client returned an unexpected result")
        content = encode_json(executed.as_dict()).decode("ascii")
        return _success(request_id, _tool_result(content, is_error=False))


def read_message(stream: Any) -> dict[str, Any] | None:
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = stream.read(1)
        if chunk == b"":
            return None
        header += chunk
        if len(header) > 4096:
            raise ValueError("MCP header is too large")
    text, _, _rest = header.partition(b"\r\n\r\n")
    length = _content_length(text.decode("ascii"))
    body = stream.read(length)
    if len(body) != length:
        raise ValueError("MCP body was truncated")
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("MCP body was not an object")
    return parsed


def write_message(stream: Any, payload: Mapping[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        raise ValueError("MCP body is too large")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)


def _content_length(header: str) -> int:
    length: int | None = None
    for line in header.split("\r\n"):
        name, separator, value = line.partition(":")
        if separator != ":" or name.lower() != "content-length":
            continue
        length = int(value.strip())
    if length is None or length < 1 or length > MAX_MESSAGE_BYTES:
        raise ValueError("MCP content length is invalid")
    return length


def _descriptor(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": "Authorized only through the AgentShield gateway.",
        "inputSchema": {
            "type": "object",
            "properties": {"resource": {"type": "string"}},
            "required": ["resource"],
            "additionalProperties": True,
        },
    }


def _tool_result(text: str, *, is_error: bool) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _error_text(exc: Denied | ApprovalRequired | GatewayError) -> str:
    if isinstance(exc, Denied | ApprovalRequired):
        return encode_json(
            {
                "outcome": exc.decision.outcome,
                "decision_id": exc.decision.decision_id,
                "reason": exc.decision.explanation.get("reason", ""),
            }
        ).decode("ascii")
    return encode_json({"error": exc.code, "message": exc.message}).decode("ascii")


def _success(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _failure(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
