import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))
sys.path.insert(0, str(ROOT / "integrations" / "langgraph"))

from agentshield_langgraph import GatewayToolNode  # noqa: E402
from agentshield_sdk.errors import ApprovalRequired, Decision, Denied, ExecuteResult, GatewayError  # noqa: E402


class Spy:
    def __init__(self, outcome: str) -> None:
        self.outcome = outcome
        self.remote = 0
        self.local = 0

    def run_local(self) -> None:
        self.local += 1

    def call_tool(self, **kwargs):
        self.remote += 1
        decision = Decision(
            decision_id="44444444-4444-4444-8444-444444444444",
            outcome=self.outcome,
            explanation={"reason": self.outcome},
            idempotency_key="idem-fixed-key-123",
        )
        if self.outcome == "allow":
            return ExecuteResult(
                decision_id=decision.decision_id,
                outcome="allow",
                adapter="sample.echo",
                result={"label": "sample adapter with no external side effect"},
            )
        if self.outcome == "deny":
            raise Denied(decision)
        if self.outcome == "require_approval":
            raise ApprovalRequired(decision)
        raise GatewayError(501, "not_implemented", "no adapter is registered for this tool")


def message(arguments):
    return {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [{"id": "call-1", "name": "sample.echo", "args": arguments}],
            }
        ]
    }


class LangGraphGatewayTests(unittest.TestCase):
    def test_rejects_local_tools(self) -> None:
        with self.assertRaises(TypeError):
            GatewayToolNode(Spy("allow"), tools=[lambda: None])  # type: ignore[call-arg]

    def test_missing_resource_does_not_call_the_gateway(self) -> None:
        spy = Spy("allow")
        with self.assertRaises(ValueError):
            GatewayToolNode(spy)(message({}))
        self.assertEqual(spy.remote, 0)
        self.assertEqual(spy.local, 0)

    def test_allow_uses_the_gateway_and_not_a_local_function(self) -> None:
        spy = Spy("allow")
        result = GatewayToolNode(spy)(message({"resource": "demo", "note": "hi"}))
        self.assertEqual(spy.remote, 1)
        self.assertEqual(spy.local, 0)
        self.assertEqual(result["messages"][0]["status"], "success")
        self.assertIn("sample.echo", result["messages"][0]["content"])

    def test_deny_and_approval_do_not_run_locally(self) -> None:
        for outcome in ("deny", "require_approval", "other"):
            spy = Spy(outcome)
            result = GatewayToolNode(spy)(message({"resource": "demo"}))
            self.assertEqual(spy.local, 0)
            self.assertEqual(spy.remote, 1)
            self.assertEqual(result["messages"][0]["status"], "error")
            self.assertNotIn("run_local", result["messages"][0]["content"])


if __name__ == "__main__":
    unittest.main()
