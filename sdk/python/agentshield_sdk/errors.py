"""Failures returned to a caller. None of these is an allow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Decision:
    decision_id: str
    outcome: str
    explanation: dict[str, Any]
    idempotency_key: str
    approval_id: str | None = None
    approval_expires_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "decision_id": self.decision_id,
            "outcome": self.outcome,
            "explanation": self.explanation,
            "idempotency_key": self.idempotency_key,
        }
        if self.approval_id is not None:
            body["approval_id"] = self.approval_id
        if self.approval_expires_at is not None:
            body["approval_expires_at"] = self.approval_expires_at
        return body


@dataclass(frozen=True)
class ExecuteResult:
    decision_id: str
    outcome: str
    adapter: str
    result: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "outcome": self.outcome,
            "adapter": self.adapter,
            "result": self.result,
        }


class GatewayError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class Denied(Exception):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.explanation.get("reason", "denied"))
        self.decision = decision


class ApprovalRequired(Exception):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.explanation.get("reason", "approval required"))
        self.decision = decision
