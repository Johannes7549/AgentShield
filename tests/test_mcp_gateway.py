import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))
sys.path.insert(0, str(ROOT / "integrations" / "mcp"))

from agentshield_mcp.server import GatewayMCPServer, read_message, write_message  # noqa: E402
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
        self.kwargs = kwargs
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


class MCPGatewayTests(unittest.TestCase):
    def test_rejects_local_handlers(self) -> None:
        with self.assertRaises(TypeError):
            GatewayMCPServer(Spy("allow"), tools=[lambda: None])  # type: ignore[list-item]

    def test_list_and_initialize_do_not_call_the_gateway(self) -> None:
        spy = Spy("allow")
        server = GatewayMCPServer(spy, ["sample.echo"])
        listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        server.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize"})
        self.assertEqual(spy.remote, 0)
        tool = listed["result"]["tools"][0]
        self.assertEqual(tool["name"], "sample.echo")
        self.assertNotIn("handler", tool)

    def test_unknown_tool_is_not_executed(self) -> None:
        spy = Spy("allow")
        server = GatewayMCPServer(spy, ["sample.echo"])
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "database.export", "arguments": {"resource": "customers"}},
            }
        )
        self.assertEqual(spy.remote, 0)
        self.assertEqual(spy.local, 0)
        self.assertEqual(response["error"]["message"], "unknown tool")

    def test_listed_tool_uses_the_gateway(self) -> None:
        for outcome, is_error in (("allow", False), ("deny", True), ("require_approval", True)):
            spy = Spy(outcome)
            server = GatewayMCPServer(spy, ["sample.echo"])
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "sample.echo",
                        "arguments": {"resource": "demo", "note": "hi"},
                    },
                }
            )
            self.assertEqual(spy.local, 0)
            self.assertEqual(spy.remote, 1)
            self.assertEqual(spy.kwargs["tool_name"], "sample.echo")
            self.assertEqual(spy.kwargs["resource"], "demo")
            self.assertEqual(response["result"]["isError"], is_error)

    def test_framing_round_trip(self) -> None:
        stream = io.BytesIO()
        write_message(stream, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        stream.seek(0)
        self.assertEqual(read_message(stream)["method"], "ping")


if __name__ == "__main__":
    unittest.main()
