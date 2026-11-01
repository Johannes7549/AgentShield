"""LangGraph node that forwards tool calls to the gateway.

The node accepts no local callable. A tool runs only when the gateway has
already returned allow and its adapter executes the call.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentshield_sdk.errors import ApprovalRequired, Denied, ExecuteResult, GatewayError
from agentshield_sdk.jsonenc import encode_json


class GatewayToolNode:
    def __init__(self, client: Any) -> None:
        if not callable(getattr(client, "call_tool", None)):
            raise TypeError("client must send tool calls through the gateway")
        self._client = client

    def __call__(self, state: Mapping[str, Any]) -> dict[str, list[dict[str, str]]]:
        messages = state.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("state has no messages")
        calls = _tool_calls(messages[-1])
        if not calls:
            raise ValueError("the last message has no tool calls")
        outgoing: list[dict[str, str]] = []
        for call in calls:
            arguments = dict(call["args"])
            resource = arguments.pop("resource", None)
            if not isinstance(resource, str) or resource == "":
                raise ValueError("tool call arguments must include resource")
            operation = arguments.pop("operation", call["name"])
            if not isinstance(operation, str) or operation == "":
                raise ValueError("tool call operation is empty")
            try:
                executed = self._client.call_tool(
                    tool_name=call["name"],
                    operation=operation,
                    resource=resource,
                    arguments=arguments,
                )
            except (Denied, ApprovalRequired, GatewayError) as exc:
                outgoing.append(_message(call, "error", _error_content(exc)))
            else:
                if not isinstance(executed, ExecuteResult):
                    raise TypeError("gateway client returned an unexpected result")
                content = encode_json(executed.as_dict()).decode("ascii")
                outgoing.append(_message(call, "success", content))
        return {"messages": outgoing}


def _tool_calls(message: Any) -> list[dict[str, Any]]:
    if isinstance(message, Mapping):
        calls = message.get("tool_calls")
    else:
        calls = getattr(message, "tool_calls", None)
    if not calls:
        return []
    normalized: list[dict[str, Any]] = []
    for call in calls:
        if isinstance(call, Mapping):
            name = call.get("name")
            args = call.get("args", {})
            call_id = call.get("id", "")
        else:
            name = getattr(call, "name", None)
            args = getattr(call, "args", {})
            call_id = getattr(call, "id", "")
        if not isinstance(name, str) or name == "":
            raise ValueError("tool call name is required")
        if not isinstance(args, dict):
            raise ValueError("tool call args must be an object")
        normalized.append({"id": str(call_id), "name": name, "args": args})
    return normalized


def _message(call: Mapping[str, Any], status: str, content: str) -> dict[str, str]:
    return {
        "role": "tool",
        "tool_call_id": str(call["id"]),
        "name": str(call["name"]),
        "status": status,
        "content": content,
    }


def _error_content(exc: Denied | ApprovalRequired | GatewayError) -> str:
    if isinstance(exc, Denied | ApprovalRequired):
        reason = exc.decision.explanation.get("reason", "")
        body = {
            "outcome": exc.decision.outcome,
            "decision_id": exc.decision.decision_id,
            "reason": reason,
        }
        return encode_json(body).decode("ascii")
    return encode_json({"error": exc.code, "message": exc.message}).decode("ascii")
