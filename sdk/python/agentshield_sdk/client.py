"""Gateway client. Tool execution happens only after an allow decision."""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from agentshield_sdk.errors import ApprovalRequired, Decision, Denied, ExecuteResult, GatewayError
from agentshield_sdk.jsonenc import encode_json
from agentshield_sdk.signing import sign

Transport = Callable[[str, bytes, dict[str, str]], tuple[int, bytes]]


class Client:
    def __init__(
        self,
        *,
        gateway: str,
        agent_id: str,
        organization_id: str,
        seed: bytes,
        transport: Transport | None = None,
        clock: Callable[[], int] | None = None,
        nonce: Callable[[], str] | None = None,
        execution_id: Callable[[], str] | None = None,
        idempotency_key: Callable[[], str] | None = None,
    ) -> None:
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self.gateway = gateway.rstrip("/")
        self.agent_id = agent_id
        self.organization_id = organization_id
        self._seed = seed
        self._transport = transport or UrllibTransport()
        self._clock = clock or (lambda: int(time.time()))
        self._nonce = nonce or (lambda: secrets.token_urlsafe(16))
        self._execution_id = execution_id or (lambda: str(uuid.uuid4()))
        self._idempotency_key = idempotency_key or (lambda: "idem-" + secrets.token_hex(16))

    def __repr__(self) -> str:
        return f"Client(gateway={self.gateway!r}, agent_id={self.agent_id!r})"

    def authorize(
        self,
        *,
        tool_name: str,
        operation: str,
        resource: str,
        arguments: Mapping[str, Any],
        execution_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> Decision:
        key = idempotency_key or self._idempotency_key()
        timestamp = self._clock()
        body = encode_json(
            {
                "agent_id": self.agent_id,
                "organization_id": self.organization_id,
                "execution_id": execution_id or self._execution_id(),
                "tool_name": tool_name,
                "operation": operation,
                "resource": resource,
                "arguments": dict(arguments),
                "requested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
                "idempotency_key": key,
            }
        )
        payload = self._post("/api/v1/runtime/authorize", body, timestamp)
        return _decision(payload, key)

    def execute(self, decision_id: str, idempotency_key: str) -> ExecuteResult:
        body = encode_json({"decision_id": decision_id, "idempotency_key": idempotency_key})
        payload = self._post("/api/v1/runtime/execute", body, self._clock())
        if payload.get("outcome") != "allow" or "adapter" not in payload:
            raise _error(payload, 200)
        result = payload.get("result") or {}
        if not isinstance(result, dict):
            raise GatewayError(200, "invalid_response", "gateway response was not an object")
        return ExecuteResult(
            decision_id=str(payload["decision_id"]),
            outcome="allow",
            adapter=str(payload["adapter"]),
            result=result,
        )

    def call_tool(
        self,
        *,
        tool_name: str,
        operation: str,
        resource: str,
        arguments: Mapping[str, Any],
    ) -> ExecuteResult:
        decision = self.authorize(
            tool_name=tool_name,
            operation=operation,
            resource=resource,
            arguments=arguments,
        )
        if decision.outcome == "allow":
            return self.execute(decision.decision_id, decision.idempotency_key)
        if decision.outcome == "deny":
            raise Denied(decision)
        if decision.outcome == "require_approval":
            raise ApprovalRequired(decision)
        raise GatewayError(0, "invalid_decision", "gateway returned an unknown outcome")

    def _post(self, path: str, body: bytes, timestamp: int) -> dict[str, Any]:
        nonce = self._nonce()
        headers = {
            "Content-Type": "application/json",
            "X-AgentShield-Agent-Id": self.agent_id,
            "X-AgentShield-Timestamp": str(timestamp),
            "X-AgentShield-Nonce": nonce,
            "X-AgentShield-Signature": sign(self._seed, timestamp, nonce, body),
        }
        status, raw = self._transport(self.gateway + path, body, headers)
        return _read_response(status, raw)


class UrllibTransport:
    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_RefuseRedirect())

    def __call__(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise GatewayError(code, "redirect", "the gateway must not redirect a signed request")


def _read_response(status: int, raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayError(status, "invalid_response", "gateway response was not JSON") from exc
    if not isinstance(parsed, dict):
        raise GatewayError(status, "invalid_response", "gateway response was not an object")
    if "outcome" in parsed and "decision_id" in parsed:
        if status not in (200, 403):
            raise GatewayError(
                status,
                "invalid_response",
                "gateway decision used an unexpected status",
            )
        return parsed
    raise _error(parsed, status)


def _decision(payload: dict[str, Any], idempotency_key: str) -> Decision:
    explanation = payload.get("explanation") or {}
    if not isinstance(explanation, dict):
        raise GatewayError(200, "invalid_response", "gateway response was not an object")
    return Decision(
        decision_id=str(payload["decision_id"]),
        outcome=str(payload["outcome"]),
        explanation=explanation,
        idempotency_key=idempotency_key,
        approval_id=payload.get("approval_id"),
        approval_expires_at=payload.get("approval_expires_at"),
    )


def _error(payload: dict[str, Any], status: int) -> GatewayError:
    error = payload.get("error")
    if isinstance(error, dict):
        code = str(error.get("code", "error"))
        message = str(error.get("message", "gateway error"))
        return GatewayError(status, code, message)
    return GatewayError(status, "invalid_response", "gateway response was not a decision")
